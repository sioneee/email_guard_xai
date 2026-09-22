import importlib.util
import time

import joblib
import numpy as np

from config import INDEX_PATH, PE_FEATURES_PATH, check_backend_files


def load_pe_features_module():
    """기존 프로젝트의 pe_features.py를 읽기 전용으로 불러온다."""
    spec = importlib.util.spec_from_file_location(
        "original_pe_features",
        PE_FEATURES_PATH,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError("기존 pe_features.py를 불러올 수 없습니다.")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


class Knn295Detector:
    """기존 EmailGuard의 295차원 kNN 판정을 재현한다."""

    def __init__(self):
        check_backend_files()

        self.pf = load_pe_features_module()
        bundle = joblib.load(INDEX_PATH)

        self.t_low = bundle["t_low"]
        self.t_high = bundle["t_high"]
        self.mal = bundle["mal"]
        self.ben_big = bundle["ben_big"]
        self.ben_pool = bundle["ben_pool"]

        if self.pf.DIM != 295:
            raise RuntimeError(
                f"피처 차원이 예상과 다릅니다: {self.pf.DIM}"
            )

    def _kdist(self, index, vector):
        """한 군집과의 평균 최근접 거리."""
        scaler, pca, neighbors = index

        transformed = scaler.transform(vector.reshape(1, -1))

        if pca is not None:
            transformed = pca.transform(transformed)

        return float(neighbors.kneighbors(transformed)[0].mean())

    def score_vector(self, vector):
        """295차원 피처 벡터를 안전/의심/차단으로 분류."""
        d_mal = self._kdist(self.mal, vector)

        d_ben_big = self._kdist(self.ben_big, vector)
        d_ben_pool = self._kdist(self.ben_pool, vector)
        d_ben = (d_ben_big + d_ben_pool) / 2

        denominator = d_mal + d_ben

        if denominator <= 0:
            ratio = float("nan")
        else:
            ratio = d_mal / denominator

        if not np.isfinite(ratio):
            verdict = "suspicious"
        elif ratio <= self.t_low:
            verdict = "blocked"
        elif ratio >= self.t_high:
            verdict = "safe"
        else:
            verdict = "suspicious"

        return {
            "verdict": verdict,
            "ratio": round(ratio, 4),
            "malware_proximity": round(1 - ratio, 4),
            "d_mal": round(d_mal, 4),
            "d_ben": round(d_ben, 4),
        }

    def extract(self, file_bytes):
        """기존 피처 추출기로 파일을 295개 숫자로 변환."""
        raw_features = self.pf.raw_features(file_bytes)
        vector = self.pf.process(raw_features)

        if vector.shape[0] != 295:
            raise RuntimeError(
                f"추출된 피처 차원이 295가 아닙니다: {vector.shape[0]}"
            )

        return raw_features, vector

    def analyze(self, file_bytes):
        """파일을 받아 현재 탐지기와 동일한 판정 결과를 반환."""
        if len(file_bytes) < 2 or file_bytes[:2] != b"MZ":
            return {
                "verdict": "not_pe",
                "message": "PE 실행 파일이 아닙니다."
            }

        started = time.time()

        try:
            _, vector = self.extract(file_bytes)
            result = self.score_vector(vector)

            result["feature_dimension"] = 295
            result["analysis_ms"] = int(
                (time.time() - started) * 1000
            )

            return result

        except Exception as error:
            return {
                "verdict": "error",
                "message": f"{type(error).__name__}: {error}"
            }