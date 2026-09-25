#일반 PE 정보 피처를 정상 기준으로 바꿔 보기
#섹션·엔트로피 피처를 정상 기준으로 바꿔 보기
#데이터 디렉터리 피처를 정상 기준으로 바꿔 보기

#python app.py

import numpy as np


FEATURE_GROUPS = [
    {
        "id": "general",
        "name": "일반 PE 정보",
        "slice": slice(0, 10),
    },
    {
        "id": "sections",
        "name": "섹션 구조와 엔트로피",
        "slice": slice(10, 265),
    },
    {
        "id": "datadirectories",
        "name": "데이터 디렉터리 구조",
        "slice": slice(265, 295),
    },
]


def malware_proximity(detector, vector):
    """
    악성 군집 근접도 지표를 계산한다.
    값이 1에 가까울수록 악성 군집에 가깝다.
    확률이 아니라 거리 기반 지표다.
    """
    d_mal = detector._kdist(detector.mal, vector)

    d_ben_big = detector._kdist(detector.ben_big, vector)
    d_ben_pool = detector._kdist(detector.ben_pool, vector)
    d_ben = (d_ben_big + d_ben_pool) / 2

    denominator = d_mal + d_ben
    ratio = d_mal / denominator if denominator > 0 else float('nan')

    return {
        "ratio": float(ratio),
        "malware_proximity": float(1 - ratio),
        "d_mal": float(d_mal),
        "d_ben": float(d_ben),
    }


def impact_level(impact):
    """영향도 숫자를 화면용 수준으로 바꾼다."""
    if impact >= 0.15:
        return "high"

    if impact >= 0.05:
        return "medium"

    return "low"


def calculate_group_impacts(detector, vector):
    """
    각 피처 그룹을 정상 기준값으로 바꿔 본 뒤,
    악성 군집 근접도가 얼마나 낮아지는지 계산한다.
    """
    original = malware_proximity(detector, vector)
    original_risk = original["malware_proximity"]

    # 정상 참조 군집의 평균 295차원 피처
    normal_reference = np.asarray(
        detector.ben_pool[0].mean_,
        dtype=np.float32,
    )

    impacts = []

    for group in FEATURE_GROUPS:
        changed_vector = vector.copy()

        # 이 피처 묶음만 정상 파일 평균값처럼 바꾼다.
        changed_vector[group["slice"]] = normal_reference[group["slice"]]

        changed = malware_proximity(detector, changed_vector)
        changed_risk = changed["malware_proximity"]

        # 양수면: 원래 피처가 악성 군집에 가까워지게 했다는 뜻
        impact = original_risk - changed_risk

        impacts.append({
            "id": group["id"],
            "name": group["name"],
            "impact": round(float(impact), 4),
            "level": impact_level(impact),
        })

    return sorted(
        impacts,
        key=lambda item: item["impact"],
        reverse=True,
    )


def collect_static_observations(detector, file_bytes, raw_features):
    """
    모델 거리 계산과 별개로,
    원본 PE에서 사람이 이해할 수 있는 관찰값을 만든다.
    """
    general = raw_features["general"]
    sections = raw_features["sections"]

    rwx_sections = [
        section["name"]
        for section in sections
        if "MEM_EXECUTE" in section["props"]
        and "MEM_WRITE" in section["props"]
    ]

    high_entropy_sections = [
        {
            "name": section["name"],
            "entropy": round(float(section["entropy"]), 2),
        }
        for section in sections
        if section["entropy"] >= 7.0
    ]

    packing_fn = getattr(detector.pf, "packing_score", None)

    if callable(packing_fn):
        packing = packing_fn(
            file_bytes,
            raw_features,
        )
        packing_score = int(packing["score"])
        file_entropy = round(float(packing["file_entropy"]), 2)
        string_count = int(packing["n_strings"])
    else:
        # 기존 피처 추출기가 해당 정보를 제공하지 않는 경우:
        # 임의의 값으로 채우지 않고 '측정 불가'로 둔다.
        packing_score = None
        file_entropy = None
        string_count = None

    return {
        "has_signature": bool(general["has_signature"]),
        "import_count": int(general["imports"]),
        "section_count": len(sections),
        "rwx_sections": rwx_sections,
        "high_entropy_sections": high_entropy_sections,
        "packing_score": packing_score,
        "file_entropy": file_entropy,
        "string_count": string_count,
    }


def build_explanation(detector, file_bytes):
    """
    기술적인 XAI 결과를 만든다.
    아직 한국어 문장으로 바꾸지는 않는다.
    """
    raw_features, vector = detector.extract(file_bytes)
    model_result = detector.score_vector(vector)

    return {
        "method": "distance_based_local_explanation",
        "model_result": model_result,
        "distance_info": malware_proximity(detector, vector),
        "group_impacts": calculate_group_impacts(detector, vector),
        "observations": collect_static_observations(
            detector,
            file_bytes,
            raw_features,
        ),
    }
