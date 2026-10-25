# VEX Triage Automation Engine 🛡️⚡

An asynchronous, model-agnostic DevSecOps engine designed to normalize vulnerability reports from disparate DAST/SCA scanners and leverage Large Language Models (LLMs) for automated false-positive triage. The engine standardizes outputs into the globally recognized **OWASP CycloneDX v1.5 VEX (Vulnerability Exploitability eXchange)** format, enabling seamless integration with enterprise vulnerability management platforms like DefectDojo and Dependency-Track.

## 🚀 Key Features

- **Multi-Scanner Normalization:** Automatically detects and standardizes proprietary JSON schemas from various security tools into a unified analysis pipeline.
- **Model-Agnostic LLM Architecture:** Built to work seamlessly with any major frontier LLM (Claude, Gemini, OpenAI, or local models) via standard API endpoints.
- **Asynchronous Triage Pipeline:** Utilizes `aiohttp` for high-performance, concurrent API calls to drastically reduce triage time for reports with hundreds of findings.
- **CycloneDX v1.5 Integration:** Packages the final triage verdicts and justifications into industry-standard VEX documents.
- **Context-Aware Decisions:** Analyzes full HTTP Requests, Responses, and execution contexts to accurately classify vulnerabilities as `exploitable`, `not_affected`, `resolved`, or `in_triage`.

## 🛠️ Supported Scanners & Formats

The engine's modular `VulnerabilityParser` currently supports the following scanner exports:

| Scanner | Type | Required Export Format |
| :--- | :--- | :--- |
| **Trivy** | SCA / Container | `JSON` (`trivy repo --format json -o report.json`) |
| **OWASP ZAP** | DAST | `JSON` (Traditional JSON Report with Requests/Responses) |
| **Invicti** | DAST | `JSON` (Detailed Vulnerabilities Export) |

## 🧠 AI Model & Benchmarking Insights

While the engine is **fully model-agnostic** and can be integrated with any advanced general-purpose LLM (such as **Anthropic Claude**, **Google Gemini**, or **OpenAI GPT** series), it is configured by default to use the **OrcaCyber Zero 1.5** model (`orca/orcacyber-zero-1.5`).

During development and benchmarking across various frontier models, **OrcaCyber Zero 1.5** delivered the most accurate and consistent triage results. Because it is purpose-built and domain-trained specifically for cybersecurity and vulnerability analysis, it excels at interpreting raw HTTP request/response artifacts, evaluating real-world exploitability paths, and reducing false-positive noise without hallucinating security context.

For findings marked as false positives or structurally unexploitable (`not_affected`), the model maps its reasoning directly to official VEX justifications (e.g., `vulnerable_code_not_in_execute_path`, `inline_mitigations_already_exist`).

## ⚙️ Setup & Configuration

### Prerequisites
- Python 3.7+
- Required packages: `aiohttp`, `python-dotenv`

```bash
pip install aiohttp python-dotenv
```

### Environment Variables & Customizing the LLM
The engine requires an API key and endpoint URL to communicate with your chosen LLM provider. Create a `.env` file in the root directory of the project:

```env
# .env file
ORCACYBER_API_KEY=your_api_key_here
ORCACYBER_API_URL=[https://api.orcacyber.com/v1/chat/completions](https://api.orcacyber.com/v1/chat/completions)
```

> **Using Another LLM (Claude, Gemini, OpenAI, etc.):**  
> If you do not have access to the OrcaCyber API, you can easily run this tool with any OpenAI-compatible chat completions endpoint:
> 1. Update `ORCACYBER_API_URL` and `ORCACYBER_API_KEY` in your `.env` file with your provider's endpoint and key.
> 2. Update the `"model"` parameter inside `main.py` to match your target model identifier (e.g., `claude-3-7-sonnet`, `gemini-2.5-pro`, or `gpt-4o`).

> **Note:** Ensure `.env` is added to your `.gitignore` to prevent leaking API keys.

## 💻 Usage

Run the engine by passing a local vulnerability JSON report using the `--file` argument. The tool will automatically detect the scanner type.

```bash
python main.py --file zap_report.json
```

### Outputs
Upon completion, the engine generates two files in the execution directory:

1. **`vex_report_<filename>.json`:** The raw, human-readable triage report containing executive summaries and LLM decisions.
2. **`cyclonedx_vex_<filename>.json`:** The standardized OWASP CycloneDX v1.5 document, ready to be ingested by automated CI/CD security pipelines.

---
*Developed as a modern DevSecOps initiative to bridge the gap between continuous security scanning and alert fatigue.*
