# VEX Triage Automation Engine 🛡️⚡

An asynchronous DevSecOps engine designed to normalize vulnerability reports from disparate DAST/SCA scanners and leverage Large Language Models (LLMs) for automated false-positive triage. The engine standardizes outputs into the globally recognized **OWASP CycloneDX v1.5 VEX (Vulnerability Exploitability eXchange)** format, enabling seamless integration with enterprise vulnerability management platforms like DefectDojo and Dependency-Track.

## 🚀 Key Features

- **Multi-Scanner Normalization:** Automatically detects and standardizes proprietary JSON schemas from various security tools into a unified analysis pipeline.
- **Asynchronous LLM Triage:** Utilizes `aiohttp` for high-performance, concurrent API calls to drastically reduce triage time for reports with hundreds of findings.
- **CycloneDX v1.5 Integration:** Packages the final triage verdicts and justifications into industry-standard VEX documents.
- **Context-Aware Decisions:** Analyzes full HTTP Requests, Responses, and execution contexts to accurately classify vulnerabilities as `exploitable`, `not_affected`, `resolved`, or `in_triage`.

## 🛠️ Supported Scanners & Formats

The engine's modular `VulnerabilityParser` currently supports the following scanner exports:

| Scanner | Type | Required Export Format |
| :--- | :--- | :--- |
| **Trivy** | SCA / Container | `JSON` (`trivy repo --format json -o report.json`) |
| **OWASP ZAP** | DAST | `JSON` (Traditional JSON Report with Requests/Responses) |
| **Invicti** | DAST | `JSON` (Detailed Vulnerabilities Export) |

## 🧠 AI Model & Analysis

This engine is powered by the **OrcaCyber Zero 1.5** model (`orca/orcacyber-zero-1.5`). The model is specifically prompted to act as a DevSecOps automation engine, analyzing raw scanner artifacts to provide a structured JSON decision. 

For findings marked as false positives or structurally unexploitable (`not_affected`), the model provides a standard VEX justification (e.g., `vulnerable_code_not_in_execute_path`, `inline_mitigations_already_exist`).

## ⚙️ Setup & Configuration

### Prerequisites
- Python 3.7+
- Required packages: `aiohttp`, `python-dotenv`

```bash
pip install aiohttp python-dotenv
```

### Environment Variables
The engine requires an API key to communicate with the OrcaCyber LLM endpoint. Create a `.env` file in the root directory of the project and add your credentials:

```env
# .env file
ORCACYBER_API_KEY=your_api_key_here
ORCACYBER_API_URL=[https://api.orcacyber.com/v1/chat/completions](https://api.orcacyber.com/v1/chat/completions) # Update with actual endpoint
```

> **Note:** Ensure `.env` is added to your `.gitignore` to prevent leaking API keys.

## 💻 Usage

Run the engine by passing a local vulnerability JSON report using the `--file` argument. The tool will automatically detect the scanner type.

```bash
python main.py --file zap_report.json
```

### Outputs
Upon completion, the engine generates two files in the execution directory:

- `vex_report_<filename>.json`: The raw, human-readable triage report containing executive summaries and LLM decisions.
- `cyclonedx_vex_<filename>.json`: The standardized OWASP CycloneDX v1.5 document, ready to be ingested by automated CI/CD security pipelines.

---
*Developed as a modern DevSecOps initiative to bridge the gap between continuous security scanning and alert fatigue.*
