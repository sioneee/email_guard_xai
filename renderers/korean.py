GROUP_DETAILS = {
    "general": (
        "파일 크기, 디지털 서명, import 수 등 "
        "기본 PE 정보가 악성 군집의 특성과 비교되었습니다."
    ),
    "sections": (
        "PE 섹션의 수, 이름, 크기, 엔트로피, "
        "실행·쓰기 권한 구조가 악성 군집과 비교되었습니다."
    ),
    "datadirectories": (
        "PE 내부 데이터 디렉터리의 구성과 위치가 "
        "정상 파일의 구조와 비교되었습니다."
    ),
}


def verdict_summary(verdict):
    if verdict == "suspicious":
        return (
            "이 파일은 정상 군집과 악성 군집의 경계에 있어 "
            "의심으로 분류되었습니다."
        )

    if verdict == "blocked":
        return (
            "이 파일은 정상 파일보다 알려진 악성 파일 군집에 "
            "훨씬 가깝게 분류되었습니다."
        )

    if verdict == "safe":
        return (
            "이 파일은 알려진 악성 파일 군집보다 정상 파일 군집에 "
            "더 가깝게 분류되었습니다."
        )

    return "파일 판정 결과를 설명할 수 없습니다."

def build_dynamic_summary(
    model_result,
    group_impacts,
    observations,
):
    verdict = model_result.get("verdict", "")
    ratio = model_result.get("ratio")

    top_group = next(
        (
            group
            for group in group_impacts
            if group["impact"] > 0
        ),
        None,
    )

    try:
        ratio = float(ratio)
    except (TypeError, ValueError):
        ratio = None

    if verdict == "suspicious":
        if ratio is None:
            summary = (
                "이 파일은 정상·악성 기준점 사이의 의심 구간에 "
                "분류되어 추가 확인이 필요합니다."
            )
        elif ratio < 0.5:
            summary = (
                f"거리 비율 {ratio:.4f}로, 의심 구간 중 "
                "악성 기준점에 상대적으로 더 가깝습니다."
            )
        else:
            summary = (
                f"거리 비율 {ratio:.4f}로, 의심 구간이지만 "
                "정상 기준점에 상대적으로 더 가깝습니다."
            )

    elif verdict == "blocked":
        summary = (
            "이 파일은 악성 기준점에 매우 가까워 "
            "차단으로 분류되었습니다."
        )

    elif verdict == "safe":
        summary = (
            "이 파일은 정상 기준점에 더 가까워 "
            "통과로 분류되었습니다."
        )

    else:
        summary = "판정 정보를 바탕으로 설명을 생성하지 못했습니다."

    if top_group:
        summary += (
            f" 가장 큰 영향은 "
            f"‘{top_group['name']}’ 피처 그룹에서 나타났습니다."
        )

    if observations["rwx_sections"]:
        summary += (
            " 실행과 쓰기가 동시에 가능한 섹션도 확인되어 "
            "추가 검토가 권장됩니다."
        )
    elif observations["high_entropy_sections"]:
        summary += (
            " 높은 엔트로피 섹션이 확인되어 "
            "압축·난독화 여부를 추가 확인할 수 있습니다."
        )

    return summary

def render_explanation(technical_result):
    model_result = technical_result["model_result"]
    observations = technical_result["observations"]

    factors = []

    for group in technical_result["group_impacts"][:3]:
        if group["impact"] <= 0:
            continue

        factors.append({
            "title": group["name"],
            "level": group["level"],
            "detail": GROUP_DETAILS[group["id"]],
        })

    static_signals = []

    if not observations["has_signature"]:
        static_signals.append(
            "PE 피처에서 서명 관련 정보가 확인되지 않았습니다."
        )

    if observations["rwx_sections"]:
        names = ", ".join(observations["rwx_sections"][:3])
        static_signals.append(
            f"실행과 쓰기가 동시에 가능한 섹션이 확인되었습니다: {names}"
        )

    if observations["high_entropy_sections"]:
        names = ", ".join(
            item["name"] or "이름 없음"
            for item in observations["high_entropy_sections"][:3]
        )
        static_signals.append(
            f"높은 엔트로피를 가진 섹션이 확인되었습니다: {names}"
        )

    if (
        observations.get("packing_score") is not None
        and observations["packing_score"] >= 2
    ):
        static_signals.append(
            "압축·암호화·난독화된 파일에서 나타날 수 있는 "
            "정적 신호가 여러 개 확인되었습니다."
        )

    if 0 < observations["import_count"] <= 20:
        static_signals.append(
            "일반 실행 파일보다 적은 수의 시스템 기능을 불러옵니다."
        )

    return {
        "method": "거리 기반 국소 설명",
        "summary": build_dynamic_summary(
            model_result,
            technical_result["group_impacts"],
            observations,
        ),
        "risk_factors": factors,
        "static_observations": static_signals,
        "disclaimer": (
            "이 설명은 탐지 모델의 거리 기반 판정 근거를 요약한 것이며, "
            "파일의 악성을 확정하는 결과는 아닙니다."
        ),
    }