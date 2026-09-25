import csv
import hashlib
import io
import sys
from types import SimpleNamespace

import numpy as np
import pytest
import pyzipper

from external_validation_runner import run_validation as validation
from external_validation_runner import run_validation_xai as xai
from external_validation_runner import calculate_metrics as metrics
from explainers.proximity import malware_proximity, calculate_group_impacts
from project_paths import configured_path, PROJECT_ROOT


def write_csv(path, rows):
    with path.open('w', encoding='utf-8-sig', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def manifest_row(name='sample.zip'):
    return dict(expected_class='malware', container_name=name, sample_name='sample.exe',
                sample_sha256='', sample_size='', sample_is_pe='True', excluded_reason='', error='')


def test_relative_setting_is_independent_of_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('TEST_XAI_PATH', 'somewhere/model.joblib')
    assert configured_path('TEST_XAI_PATH', '') == PROJECT_ROOT / 'somewhere/model.joblib'


def test_runtime_tampering_rejected(tmp_path, monkeypatch):
    file = tmp_path / 'triage.py'
    file.write_bytes(b'original')
    monkeypatch.setattr(validation, 'EXPECTED_RUNTIME_HASHES', {'triage.py': hashlib.sha256(b'original').hexdigest()})
    validation.verify_runtime(tmp_path)
    file.write_bytes(b'changed')
    with pytest.raises(SystemExit, match='triage.py'):
        validation.verify_runtime(tmp_path)


def test_manifest_accepts_small_set_and_rejects_duplicates(tmp_path):
    path = tmp_path / 'manifest.csv'
    row = manifest_row()
    write_csv(path, [row])
    assert len(validation.read_manifest(path)) == 1
    write_csv(path, [row, row])
    with pytest.raises(SystemExit, match='duplicate'):
        validation.read_manifest(path)


@pytest.mark.parametrize('name', ['../sample.zip', '..\\sample.zip', 'C:sample.zip'])
def test_manifest_rejects_path_escape(tmp_path, name):
    path = tmp_path / 'manifest.csv'
    write_csv(path, [manifest_row(name)])
    with pytest.raises(SystemExit, match='filename'):
        validation.read_manifest(path)


def test_encrypted_zip_is_read_without_extraction(tmp_path):
    (tmp_path / 'malware').mkdir()
    path = tmp_path / 'malware/sample.zip'
    raw = b'MZ synthetic inert bytes, not an executable'
    with pyzipper.AESZipFile(path, 'w', encryption=pyzipper.WZ_AES) as z:
        z.setpassword(b'infected')
        z.writestr('sample.exe', raw)
    row = manifest_row()
    row.update(sample_sha256=hashlib.sha256(raw).hexdigest(), sample_size=str(len(raw)))
    assert validation.load_sample(tmp_path, row) == raw
    assert list(tmp_path.rglob('*.exe')) == []
    row['sample_sha256'] = '0' * 64
    with pytest.raises(ValueError, match='SHA-256'):
        validation.load_sample(tmp_path, row)


def test_zip_multiple_members_rejected(tmp_path):
    path = tmp_path / 'multiple.zip'
    with pyzipper.AESZipFile(path, 'w') as z:
        z.writestr('a', b'MZ')
        z.writestr('b', b'MZ')
    with pytest.raises(ValueError):
        validation.read_single_member(path, 'a')


def test_excluded_sample_never_reaches_model(tmp_path):
    row = manifest_row()
    row['excluded_reason'] = 'ambiguous_nested_archive'
    assert validation.evaluate_row(tmp_path, row, None, None, None)['evaluation_status'] == 'excluded'


def test_xai_accepts_any_suspicious_count(tmp_path):
    p = tmp_path / 'results.csv'
    write_csv(p, [{'predicted_verdict': '통과'}, {'predicted_verdict': '의심'}])
    assert len(xai.read_validation_results(p)) == 1


def test_zero_distance_not_reported_as_high_risk():
    detector = SimpleNamespace(mal=0, ben_big=0, ben_pool=0, _kdist=lambda *args: 0.)
    assert np.isnan(malware_proximity(detector, np.zeros(295))['ratio'])


def test_group_impacts_use_normal_reference_without_mutating_input():
    vector = np.ones(295, dtype=np.float32)
    detector = SimpleNamespace(mal='mal', ben_big='big', ben_pool=(SimpleNamespace(mean_=np.zeros(295)),))
    detector._kdist = lambda group, v: 1. if group == 'mal' else 1. + float(v.sum())
    impacts = calculate_group_impacts(detector, vector)
    assert {i['id'] for i in impacts} == {'general', 'sections', 'datadirectories'}
    assert all(i['impact'] > 0 for i in impacts)
    np.testing.assert_array_equal(vector, np.ones(295))


@pytest.mark.parametrize('status,verdict', [('correct','통과'), ('excluded',''), ('error','')])
def test_metrics_handle_single_and_no_evaluated_rows(tmp_path, monkeypatch, status, verdict):
    p = tmp_path / 'results.csv'
    write_csv(p, [dict(expected_class='benign', predicted_verdict=verdict,
                       evaluation_status=status, correct_strict='True' if verdict else '', latency_ms='10')])
    monkeypatch.setattr(sys, 'argv', ['metrics', '--input', str(p)])
    assert metrics.main() == 0
    with (tmp_path / 'validation_metrics.csv').open(encoding='utf-8-sig') as f:
        result = {r['metric']: r for r in csv.DictReader(f)}
    assert result['malware_block_rate']['value'] == ''
    assert result['post_first_latency_mean']['value'] == ''
    assert result['evaluated_total']['value'] == ('1' if verdict else '0')


def test_percentile_and_zero_denominator():
    assert metrics.percentage(0, 0) == ''
    assert metrics.percentage(1, 4) == '25.00'
    assert metrics.percentile_linear([0, 100], .95) == 95


def test_xai_mismatched_score_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(xai, 'load_sample', lambda *args: b'MZ fake')
    manifest = manifest_row()
    row = dict(manifest, predicted_verdict='의심', ratio='0.2',
               sample_sha256=hashlib.sha256(b'MZ fake').hexdigest())
    explanation = {'model_result': {'verdict': 'suspicious', 'ratio': .3}}
    result = xai.analyze_one(tmp_path, row, manifest, None,
                             lambda *args: explanation, lambda *args: {})
    assert result['status'] == 'error'
    assert result['summary'] == ''


@pytest.mark.parametrize('verdict,expected_calls', [('safe', 0), ('blocked', 0), ('suspicious', 1)])
def test_local_api_explains_only_suspicious(monkeypatch, verdict, expected_calls):
    import importlib
    from adapters import knn295
    fake = SimpleNamespace(analyze=lambda raw: {'verdict': verdict})
    monkeypatch.setattr(knn295, 'Knn295Detector', lambda: fake)
    sys.modules.pop('app', None)
    app_module = importlib.import_module('app')
    calls = []
    monkeypatch.setattr(app_module, 'build_explanation', lambda *a: calls.append(a) or {})
    monkeypatch.setattr(app_module, 'render_explanation', lambda x: {'summary': 'test'})
    response = app_module.app.test_client().post('/v1/explanations',
        data={'file': (io.BytesIO(b'MZ fake'), 'fake.bin')}, headers={'Origin': 'https://untrusted.invalid'})
    assert response.status_code == 200
    assert len(calls) == expected_calls
    assert (response.json['explanation'] is not None) == bool(expected_calls)
    assert 'Access-Control-Allow-Origin' not in response.headers
    sys.modules.pop('app', None)
