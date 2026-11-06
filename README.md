# EmailGuard XAI

기존 EmailGuard의 295차원 PE 특징과 k-NN 거리 판정에 대한 설명을 생성한다.
이 저장소는 팀 백엔드 통합 전 검토용 모듈과 로컬 검증 도구다.
팀 통합 작업: https://github.com/JJeonJong/email_guard/issues/87

## 설치

저장소 루트에서 PowerShell로 실행한다. 이번 검증 환경은 Python 3.14이다.

```powershell
py -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
Copy-Item .env.example .env
notepad .env
```

`.env`의 모델·특징 추출기·데이터 경로를 자신의 위치로 설정한다. 상대경로는
현재 터미널 위치가 아니라 이 저장소 루트를 기준으로 해석한다. 이미 설정한 환경변수가
`.env`보다 우선한다. 설치 후 `python -m pip check`로 의존성을 확인한다.

| 설정 | 용도 |
| --- | --- |
| `EMAIL_GUARD_PE_FEATURES` | 기존 프로젝트의 `ml/pe_features.py` |
| `EMAIL_GUARD_INDEX` | 신뢰하는 기존 프로젝트의 `eg_index.joblib` |
| `EMAIL_GUARD_TRIAGE` | 기존 `ml/triage.py`; 기본값은 특징 추출기와 같은 폴더 |
| `EMAIL_GUARD_XAI_DATA_DIR` | 실험 manifest·결과 저장 폴더 |
| `EMAIL_GUARD_DATASET_DIR` | 기존 PE 실험 데이터 루트 |
| `EMAIL_GUARD_WINDOWS_DIR` | Windows 정상 대조군 수집 위치; 기본값은 `SystemRoot` |

신뢰하는 프로젝트가 생성한 joblib만 사용한다. 모델 파일과 실제 표본은 배포하지 않는다.
모델을 만든 scikit-learn 버전과 설치 버전을 일치시켜야 한다.

## 외부 검증

외부 데이터 루트는 명령마다 `--root`로 지정한다. 아래 `../email_guard_xai_data/new_validation`은
예시이며 자신의 경로로 변경한다. 데이터와 출력은 저장소 밖에서 보관한다.

```text
new_validation/
  manifest.csv
  benign/
  malware/              암호 ZIP, 비밀번호 infected
  frozen_runtime/
    pe_features.py
    triage.py
    eg_index.joblib
  results/
```

manifest 열:
`expected_class,container_name,sample_name,sample_sha256,sample_size,sample_is_pe,excluded_reason,error`.
추가 메타데이터 열은 허용한다. `expected_class`는 `benign` 또는 `malware`이며
`container_name`은 해당 클래스 폴더 안의 파일명이다. `sample_sha256`과 `sample_size`는
ZIP 자체가 아닌 내부 PE의 값이다. 제외 행에는 `excluded_reason`을 채운다.
빈칸인 출처·라벨 근거를 추측해서 채우지 않는다.

현재 실행기는 이전에 검증한 특정 런타임의 해시와 임계값을 고정한다.
다른 모델은 자동으로 허용하지 않는다. `run_validation.py`의 `EXPECTED_RUNTIME_HASHES`가
가리키는 신뢰된 파일을 담당자에게 받아 `frozen_runtime`에 둔다. 새 모델 평가 시에는
모델 변경을 별도 검토하고 해시·임계값 계약을 함께 변경해야 한다.

```powershell
& .\.venv\Scripts\python.exe -m external_validation_runner.run_validation --root ../email_guard_xai_data/new_validation
& .\.venv\Scripts\python.exe -m external_validation_runner.calculate_metrics --input ../email_guard_xai_data/new_validation/results/validation_results.csv
& .\.venv\Scripts\python.exe -m external_validation_runner.run_validation_xai --root ../email_guard_xai_data/new_validation
```

세 명령은 각각 `validation_results.csv`, `validation_metrics.csv`,
`suspicious_xai_results.csv`를 만든다. `--out`으로 출력 위치를 바꿀 수 있다.
기존 출력은 백업한다. 표본 수는 고정하지 않는다. 제외 파일도 판정 결과 CSV에 남긴다.
악성 ZIP은 단일 멤버만 메모리에서 읽고 실행하거나 디스크에 추출하지 않는다.
중첩·복수 멤버는 임의 선택하지 않고 제외 사유를 manifest에 기록한다.

## 결과 해석

`ratio = d_mal / (d_mal + d_ben)`이며 확률이 아니다.
작을수록 모델의 악성 거리 쪽에 상대적으로 가깝다. 판정은 색인의 임계값을 사용한다.
XAI는 일반 PE 정보·섹션 구조·데이터 디렉터리 그룹을 각각 정상 참조 평균으로 치환해
`1 - ratio`가 얼마나 변하는지 측정한다. 양의 영향도는 이 치환에서 악성 근접도가 감소했다는 뜻이다.
그룹 크기가 다르고 치환 벡터가 실제 실행 가능한 PE를 나타내지는 않으므로 인과·악성 확정 근거로 해석하지 않는다.

`fidelity_ok`는 의심 판정 재현과 ratio 오차 0.0001 이하를 확인한다.
이는 설명 품질 전체를 보증하지 않는다. 정적 관찰값과 모델 그룹 영향도는 별개다.
서명 관련 PE 필드 존재는 인증서 신뢰 검증이 아니며 높은 엔트로피도 악성 확정 근거가 아니다.
지표의 오류율은 읽기·해시·특징 추출·판정 오류를 합친 값이다.
지연시간에는 파일 읽기·ZIP 해제·해시·특징 추출·판정이 포함된다. 첫 파일을 제외한 평균은
참고값이며 별도의 반복 예열 성능 검증으로 간주하지 않는다.

## 테스트

```powershell
& .\.venv\Scripts\python.exe -m pytest -q
```

자동 테스트는 실제 악성 파일이나 모델 없이 실행한다. 기존 live API 테스트 4개는
기본적으로 건너뛴다. 신뢰하는 로컬 서버와 기존 결과 CSV의 원본 파일을 준비한 경우에만
`EMAIL_GUARD_RUN_LIVE_TESTS=1`을 설정해 선택적으로 실행한다.

```powershell
$env:EMAIL_GUARD_RUN_LIVE_TESTS = '1'
& .\.venv\Scripts\python.exe -m pytest tests/test_api_integration.py -q
Remove-Item Env:EMAIL_GUARD_RUN_LIVE_TESTS
```

## 로컬 API와 팀 통합

`python app.py`는 `127.0.0.1:5001`의 로컬 데모다. 디버그와 광범위 CORS는 꺼져 있다.
이 API에는 인증이 없으므로 외부 공개용으로 배포하지 않는다.
팀원은 `explainers/proximity.py`, `renderers/korean.py`와 detector 인터페이스를 검토해
기존 인증된 백엔드 안에 연결한다. `app.py`로 팀 백엔드를 덮어쓰지 않는다.

detector는 `extract(bytes)`, `score_vector(vector)`, `_kdist(group, vector)`와
`pf`, `mal`, `ben_big`, `ben_pool`을 제공한다. 기존 판정과 동일한 색인 스냅샷으로
의심 파일만 설명하고, 특징 추출은 재사용하며, 설명 실패가 원래 판정을 지우지 않도록 한다.
기존 인증·CORS·업로드 제한·모델 갱신 잠금은 팀 백엔드에서 유지한다.

과거 실험은 저장소 루트에서 `python -m experiments.run_fidelity --help`와 같이 실행한다.
모든 실험 기본 데이터 위치는 `project_paths.py`의 환경 설정을 사용한다.
Windows 대조군 수집은 Windows 전용이다. 원본 PE를 직접 읽는 과거 실험과 달리
이번 외부 검증 실행기는 암호 ZIP을 메모리에서 처리한다.

`.env`, 가상환경, 모델, 실제 표본, 결과 CSV는 Git에 추가하지 않는다.
공유 범위는 코드·설정 예시·사용법·테스트이며, 검증 집계는 PR에서 확인한다.
