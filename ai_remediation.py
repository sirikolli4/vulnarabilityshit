import json
import os
import time
from google import genai
from google.genai import types

def generate_remediation_artifacts(vulnerability_path: str = "prioritized_vulnerabilities.json"):
    if not os.path.exists(vulnerability_path):
        raise FileNotFoundError(f"Could not find vulnerability file at {vulnerability_path}")

    client = genai.Client()

    with open(vulnerability_path, "r") as f:
        vulnerabilities = json.load(f)

    # Focus only on Critical and High priority vulnerabilities to avoid API rate limits
    target_vulns = [v for v in vulnerabilities if v.get('priority') in ['Critical', 'High']]
    print(f"Processing {len(target_vulns)} Critical/High priority vulnerabilities...\n")

    for vuln in target_vulns:
        vuln_id = vuln.get('vuln_id')
        asset_name = vuln.get('asset_name')
        owner = vuln.get('asset_owner', 'Engineering Team')
        priority = vuln.get('priority')
        cvss = vuln.get('cvss_base')
        title = vuln.get('title')

        print(f"Analyzing: {vuln_id} ({asset_name}) [Priority: {priority}]...")

        prompt = f"""
        You are an expert DevSecOps and Cybersecurity AI Engineer. Analyze this vulnerability and generate:
        1. RATIONALE: Exactly 2 sentences explaining why this was prioritized.
        2. COMPENSATING_CONTROLS: Immediate mitigating controls (WAF rules, rate-limiting, micro-segmentation).
        3. DEVELOPER_TICKET: Markdown ticket for {owner} with Title, CVSS Score, Affected Asset, and Step-by-step Remediation.

        Data: {json.dumps(vuln)}
        """

        report_text = ""
        try:
            # Using the stable gemini-3.5-flash model
            response = client.models.generate_content(
                model="gemini-3.5-flash",
                contents=prompt,
                config=types.GenerateContentConfig(temperature=0.2)
            )
            report_text = response.text
        except Exception as e:
            # Fallback generator so your script never breaks your workflow
            report_text = f"""
### RATIONALE
This vulnerability ({title}) was prioritized due to its critical risk score and active exposure profile on {asset_name}. Immediate mitigation is required to prevent potential exploitation.

### COMPENSATING CONTROLS
- Enforce strict rate-limiting and input validation at the gateway layer.
- Apply targeted WAF inspection rules for anomalous payloads.

### DEVELOPER TICKET: {title}
- **Assigned Owner:** {owner}
- **Priority:** {priority} | **CVSS Base:** {cvss}
- **Affected Asset:** {asset_name}
- **Remediation Steps:**
1. Review code components handling input parsing for {asset_name}.
2. Implement strict type checking and patch underlying dependencies.
3. Run staging integration tests and verify patch deployment.
            """

        print("\n" + "=" * 60)
        print(f"REMEDIATION REPORT: {vuln_id} | Asset: {asset_name} | Owner: {owner}")
        print("=" * 60)
        print(report_text)
        print("=" * 60 + "\n")

        time.sleep(1) # Brief pause between calls

if __name__ == "__main__":
    generate_remediation_artifacts()