import os
import json
import argparse
import asyncio
import aiohttp
import uuid
from datetime import datetime
import urllib3
from dotenv import load_dotenv

# Suppress insecure request warnings for local testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

API_KEY = os.getenv("ORCACYBER_API_KEY")
API_URL = os.getenv("ORCACYBER_API_URL")


# ==========================================
# STAGE 1: NORMALIZATION (INPUT ADAPTERS)
# ==========================================

class VulnerabilityParser:
    @staticmethod
    def parse_invicti(data):
        """Converts Invicti JSON format to standard format."""
        vulnerabilities = data.get("Vulnerabilities", []) if isinstance(data, dict) else data
        normalized_list = []

        for vuln in vulnerabilities:
            normalized_list.append({
                "tool": "Invicti",
                "issue_id": vuln.get("LookupId") or vuln.get("Name", "unknown_id"),
                "issue_name": vuln.get("Name", "Unknown Vulnerability"),
                "severity": vuln.get("Severity") or vuln.get("severity") or "Unknown",
                "raw_data": vuln  # Keep original data for LLM analysis
            })
        return normalized_list

    @staticmethod
    def parse_trivy(data):
        """Converts Trivy JSON format to standard format."""
        normalized_list = []
        results = data.get("Results", [])

        for result in results:
            vulnerabilities = result.get("Vulnerabilities", [])
            for vuln in vulnerabilities:
                normalized_list.append({
                    "tool": "Trivy",
                    "issue_id": vuln.get("VulnerabilityID", "unknown_id"),
                    "issue_name": vuln.get("Title") or vuln.get("PkgName", "Unknown Vulnerability"),
                    "severity": vuln.get("Severity", "Unknown"),
                    "raw_data": vuln  # Keep original data for LLM analysis
                })
        return normalized_list

    @staticmethod
    def parse_zap(data):
        """Converts OWASP ZAP JSON format to standard format."""
        normalized_list = []
        sites = data.get("site", [])

        for site in sites:
            alerts = site.get("alerts", [])
            for alert in alerts:
                # ZAP may have multiple instances (URLs) for a single alert.
                # For triage, we bundle the instances with the alert data.
                normalized_list.append({
                    "tool": "OWASP ZAP",
                    "issue_id": alert.get("pluginid", "unknown_id"),
                    "issue_name": alert.get("name", "Unknown Vulnerability"),
                    "severity": alert.get("riskdesc", "Unknown").split(" ")[0],  # Extract 'Low' from 'Low (High)'
                    "raw_data": alert  # Keep original data for LLM analysis
                })
        return normalized_list

    @classmethod
    def normalize(cls, scan_data):
        """Analyzes JSON structure to identify the tool and routes to the appropriate parser."""
        if isinstance(scan_data, dict) and "site" in scan_data and isinstance(scan_data["site"], list):
            print("[*] Detected tool: OWASP ZAP")
            return cls.parse_zap(scan_data)
        elif isinstance(scan_data, dict) and "Results" in scan_data and "SchemaVersion" in scan_data:
            print("[*] Detected tool: Trivy")
            return cls.parse_trivy(scan_data)
        elif isinstance(scan_data, dict) and "Vulnerabilities" in scan_data:
            print("[*] Detected tool: Invicti (Dict format)")
            return cls.parse_invicti(scan_data)
        elif isinstance(scan_data, list):
            # If it's a direct list, we assume Invicti array export for now
            print("[*] Detected tool: Invicti (List format)")
            return cls.parse_invicti(scan_data)
        else:
            print("[!] Unrecognized JSON format. Cannot normalize.")
            return []


# ==========================================
# STAGE 2: ASYNCHRONOUS API (AIOHTTP)
# ==========================================

def extract_json_from_model(response_text):
    """Extracts clean JSON string from LLM response."""
    text = response_text.strip()
    if text.startswith("```json"):
        text = text[7:]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()


async def generate_vex_document_async(session, vuln_data, issue_id, issue_name):
    if not API_KEY:
        return None

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    system_prompt = '''
    You are an expert DevSecOps automation engine. Your objective is to analyze the provided DAST/SCA vulnerability scan data (including HttpRequest, HttpResponse, and context).
    Determine whether the finding is a False Positive, structurally unexploitable ('not_affected'), or a genuine risk ('affected').

    CRITICAL: All generated text, specifically the 'impact_statement', MUST be written entirely in English. Do not use any other language.

    Your output MUST be strictly in the following JSON format. Do not use any markdown formatting, explanations, or text outside the JSON structure.

    Expected JSON Schema:
    {
      "vulnerability_id": "The provided issue_id",
      "vulnerability_name": "Name of the finding",
      "status": "not_affected, affected, fixed, or under_investigation",
      "justification": "If status is not_affected, provide a valid VEX justification code (e.g., inline_mitigations_already_exist, vulnerable_code_not_in_execute_path, vulnerable_code_not_present). Otherwise, set to null.",
      "impact_statement": "A concise, technical sentence explaining your decision based on the HTTP Request/Response and context."
    }
    '''

    payload_data = {"issue_id": issue_id, "scan_details": vuln_data}

    payload = {
        "model": "orca/orcacyber-zero-1.5",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Analyze the following scanner data:\n{json.dumps(payload_data, indent=2)}"}
        ],
        "temperature": 0.1,
    }

    try:
        print(f"[*] Dispatching async analysis for: {issue_name} ({issue_id})")
        # Asynchronous HTTP POST request
        async with session.post(API_URL, headers=headers, json=payload, ssl=False, timeout=60) as response:
            response.raise_for_status()
            response_json = await response.json()
            raw_output = response_json["choices"][0]["message"]["content"]
            clean_json_string = extract_json_from_model(raw_output)
            print(f"[+] Completed analysis for: {issue_name} ({issue_id})")
            return json.loads(clean_json_string)

    except Exception as e:
        print(f"[!] VEX analysis failed for issue ({issue_id}): {e}")
        return None


async def run_triage_async(normalized_vulnerabilities):
    # Set TCPConnector limit for concurrent LLM API calls
    connector = aiohttp.TCPConnector(limit=20, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for vuln in normalized_vulnerabilities:
            # raw_data: Original scanner output (sent to LLM), issue_id/name: For logging
            task = asyncio.ensure_future(generate_vex_document_async(
                session,
                vuln["raw_data"],
                vuln["issue_id"],
                vuln["issue_name"]
            ))
            tasks.append(task)

        # Start and wait for all tasks to run concurrently
        results = await asyncio.gather(*tasks)
        return results


# ==========================================
# STAGE 3: CYCLONEDX V1.5 VEX INTEGRATION
# ==========================================

def generate_cyclonedx_vex(final_vex_report, target_name):
    """
    Converts standard VEX JSON from LLM into OWASP CycloneDX v1.5 VEX format.
    """
    # CycloneDX BOM Metadata Header
    cyclonedx_bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{str(uuid.uuid4())}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [
                {
                    "vendor": "Custom Automation",
                    "name": "LLM VEX Triage Engine",
                    "version": "1.0"
                }
            ],
            "component": {
                "bom-ref": "target-application-1",
                "type": "application",
                "name": target_name
            }
        },
        "vulnerabilities": []
    }

    # CycloneDX Analysis State Mapping
    # LLM outputs: not_affected, affected, fixed, under_investigation
    # CycloneDX states: resolved, resolved_with_pedigree, exploitable, in_triage, false_positive, not_affected
    state_mapping = {
        "affected": "exploitable",
        "not_affected": "not_affected",
        "fixed": "resolved",
        "under_investigation": "in_triage"
    }

    for vex_doc in final_vex_report.get("vex_documents", []):
        vuln_id = vex_doc.get("vulnerability_id")
        status = vex_doc.get("status")
        justification = vex_doc.get("justification")
        impact = vex_doc.get("impact_statement")

        # CycloneDX Vulnerability Object
        cdx_vuln = {
            "id": vuln_id,
            "analysis": {
                "state": state_mapping.get(status, "in_triage"),
                "detail": impact
            },
            "affects": [
                {
                    "ref": "target-application-1"
                }
            ]
        }

        # VEX justification is required only for 'not_affected' status (CycloneDX standard)
        if status == "not_affected" and justification:
            # Align LLM's justification string with CycloneDX format
            cdx_vuln["analysis"]["justification"] = justification

        cyclonedx_bom["vulnerabilities"].append(cdx_vuln)

    return cyclonedx_bom


# ==========================================
# MAIN EXECUTION BLOCK
# ==========================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate VEX documents from Local Vulnerability JSON reports.")
    parser.add_argument("--file", required=True, help="Path to the local vulnerability JSON file")
    args = parser.parse_args()

    print("=== VEX Triage Automation Engine (Async, Normalized & CycloneDX) ===")
    target_id = os.path.basename(args.file)
    print(f"[*] Reading local file: {args.file}...")

    try:
        with open(args.file, 'r', encoding='utf-8') as f:
            scan_data = json.load(f)
    except Exception as e:
        print(f"[!] File read error: {e}")
        exit()

    if not scan_data:
        print("[!] No scan data retrieved. Exiting.")
        exit()

    # Step 1: Detect scan file and convert to normalized list
    normalized_vulnerabilities = VulnerabilityParser.normalize(scan_data)

    if not normalized_vulnerabilities:
        print("[!] No valid vulnerabilities found to analyze.")
        exit()

    print(f"[*] Total findings to analyze asynchronously: {len(normalized_vulnerabilities)}")

    # Step 2: Start asynchronous analysis
    print("[*] Contacting LLM Engine... This will be fast!")
    vex_results = asyncio.run(run_triage_async(normalized_vulnerabilities))

    # Step 3: Collect results and generate reports
    executive_summary = {
        "Critical": 0, "High": 0, "Medium": 0, "Low": 0,
        "Information": 0, "BestPractice": 0, "Unknown": 0
    }

    final_vex_report = {
        "target_reference": target_id,
        "executive_summary": {},
        "vex_documents": []
    }

    for idx, vex_result in enumerate(vex_results):
        if vex_result:
            final_vex_report["vex_documents"].append(vex_result)
            # Fetch original severity from the normalized list
            severity = normalized_vulnerabilities[idx]["severity"].capitalize()

            if vex_result.get("status") in ["affected", "under_investigation"]:
                if severity in executive_summary:
                    executive_summary[severity] += 1
                else:
                    executive_summary["Unknown"] += 1

    final_vex_report["executive_summary"] = {k: v for k, v in executive_summary.items() if v > 0}

    # Save standard LLM Triage Report
    report_filename = f"vex_report_{target_id.replace('.json', '')}.json"
    with open(report_filename, "w", encoding="utf-8") as f:
        json.dump(final_vex_report, f, indent=4, ensure_ascii=False)

    # Step 4: Generate and save CycloneDX VEX Format
    cyclonedx_data = generate_cyclonedx_vex(final_vex_report, target_name=target_id)
    cdx_filename = f"cyclonedx_vex_{target_id.replace('.json', '')}.json"

    with open(cdx_filename, "w", encoding="utf-8") as f:
        json.dump(cyclonedx_data, f, indent=4, ensure_ascii=False)

    print(f"\n[+] Analysis complete!")
    print(f"[+] Executive Summary of Confirmed (Affected) Findings:")
    print(json.dumps(final_vex_report["executive_summary"], indent=2))
    print(f"[+] LLM Triage Report saved to '{report_filename}'.")
    print(f"[+] CycloneDX VEX Document saved to '{cdx_filename}' (Ready for DefectDojo/Dependency-Track).")