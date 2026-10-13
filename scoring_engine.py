
import json

INPUT_FILE = "vulnerabilities.json"
OUTPUT_FILE = "prioritized_vulnerabilities.json"

ASSET_WEIGHTS = {
    "Critical": 0.5,
    "High": 0.3,
    "Medium": 0.1,
    "Low": 0.0
}


def calculate_risk(vuln):
    cvss = float(vuln["cvss_base"])

    if not 0 <= cvss <= 10:
        raise ValueError(
            f"{vuln['vuln_id']}: CVSS must be between 0 and 10"
        )

    # Score breakdown
    breakdown = {
        "cvss_component": round(cvss * 0.60, 2),
        "internet_exposure": 0.0,
        "active_exploit": 0.0,
        "asset_criticality": 0.0
    }

    score = breakdown["cvss_component"]
    reasons = []

    if vuln.get("internet_exposed") is True:
        breakdown["internet_exposure"] = 1.0
        score += 1.0
        reasons.append("Internet-facing asset")

    exploit = vuln.get("active_exploit_in_wild")

    if exploit is True:
        breakdown["active_exploit"] = 2.0
        score += 2.0
        reasons.append("Active exploit reported")
    elif exploit is None:
        breakdown["active_exploit"] = 0.3
        score += 0.3
        reasons.append("Exploit status unknown; verify")

    criticality = vuln.get("asset_criticality", "Low")
    asset_weight = ASSET_WEIGHTS.get(criticality, 0.0)

    breakdown["asset_criticality"] = asset_weight
    score += asset_weight

    if criticality in ("Critical", "High"):
        reasons.append(f"{criticality} criticality asset")

    score = round(min(score, 10.0), 1)

    return score, reasons, breakdown


def get_priority(score):
    if score >= 8:
        return "Critical"
    elif score >= 6:
        return "High"
    elif score >= 4:
        return "Medium"
    return "Low"


def get_action(priority):
    actions = {
        "Critical": "Investigate immediately; apply a verified fix or mitigation.",
        "High": "Schedule urgent remediation and verify the fix.",
        "Medium": "Plan remediation in the next maintenance cycle.",
        "Low": "Track and address through routine patching."
    }
    return actions[priority]


def main():
    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        vulnerabilities = json.load(file)

    for vuln in vulnerabilities:
        score, reasons, breakdown = calculate_risk(vuln)

        vuln["contextual_risk_score"] = score
        vuln["priority"] = get_priority(score)
        vuln["risk_reasons"] = reasons
        vuln["score_breakdown"] = breakdown
        vuln["recommended_action"] = get_action(vuln["priority"])

        if vuln.get("active_exploit_in_wild") is None:
            vuln["data_quality"] = "Review required: exploit status unknown"
        else:
            vuln["data_quality"] = "Exploit status provided"

    vulnerabilities.sort(
        key=lambda v: v["contextual_risk_score"],
        reverse=True
    )

    for rank, vuln in enumerate(vulnerabilities, start=1):
        vuln["priority_rank"] = rank

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(vulnerabilities, file, indent=2)

    print(f"Prioritized {len(vulnerabilities)} findings!")
    print("\nTOP 5 VULNERABILITIES")

    for vuln in vulnerabilities[:5]:
        print(
            f"#{vuln['priority_rank']} | {vuln['vuln_id']} | "
            f"Score: {vuln['contextual_risk_score']} | "
            f"Priority: {vuln['priority']}"
        )
        print(f"   Reasons: {', '.join(vuln['risk_reasons'])}")

    print(f"\nResults saved to {OUTPUT_FILE}")
    print("Note: This is a prototype scoring model, not official CVSS.")


if __name__ == "__main__":
    main()
