# PE Analyzer

<p align="center">
  <img alt="PE Analyzer" src="https://img.shields.io/badge/PE-Analyzer-1B1F23?style=for-the-badge&logo=python&logoColor=white" />
  <img alt="Python" src="https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img alt="Tests" src="https://img.shields.io/badge/Tests-PyTest-0A0A0A?style=for-the-badge&logo=pytest&logoColor=white" />
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
</p>

PE Analyzer is a static malware analysis and Portable Executable (PE) inspection toolkit built in Python. It helps security researchers and developers quickly assess suspicious binaries by extracting metadata, hashes, imported APIs, suspicious strings, and threat indicators from Windows executables.

## Features

### Core Functionality
- Parse and validate PE file headers and structure
- Inspect section metadata, entropy, and permission flags
- Extract/import API usage and compare against a blacklist of risk-prone Windows APIs
- Identify suspicious strings and network indicators such as URLs, domains, and IPv4 addresses
- Compute MD5 and SHA-256 hashes for triage and correlation
- Optional VirusTotal hash reputation lookup via API integration

### Security & Reliability
- Defensive validation of PE headers and malformed file input
- Structured reporting with risk scoring and operational warnings
- Clean CLI output and export to JSON or text reports
- Safe handling of malformed binaries and unsupported file types

### Performance
- Lightweight static analysis workflow
- Efficient PE parsing via pefile
- Optional fast-path parsing support for metadata-heavy inspection

## Tech Stack

| Category | Technology |
| --- | --- |
| Language | Python 3.11 |
| PE Parsing | pefile |
| Terminal UI | Rich |
| HTTP Client | requests |
| Testing | PyTest |
| Reporting | JSON / plain text exports |

## Getting Started

### Prerequisites

Make sure you have the following installed:

- Python 3.11+
- pip
- Git

### Installation

Clone the repository:

```bash
git clone https://github.com/your-username/PE-Analyzer.git
cd PE-Analyzer
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

Analyze a PE file and display the rich terminal report:

```bash
python src/main.py -f samples/helloWorld.exe
```

Analyze a file and export the report to JSON:

```bash
python src/main.py -f samples/helloWorld.exe -o output/report.json
```

Analyze a file and enable VirusTotal checking:

```bash
python src/main.py -f samples/helloWorld.exe --vt --api-key YOUR_VT_API_KEY
```

Display help:

```bash
python src/main.py --help
```

## Project Structure

```text
PE-Analyzer/
├── docs/                     # Project notes and analysis documentation
├── output/                   # Generated analysis reports
├── samples/                  # Sample PE binaries and demonstration files
├── src/                      # Application source code
│   ├── core/                 # PE parsing and hashing logic
│   ├── services/             # External services such as VT integration
│   ├── utils/                # Blacklist, display, and utility helpers
│   └── main.py               # CLI entry point
├── tests/                    # Automated tests
├── LICENSE                   # Project license
├── README.md                 # Project overview and usage
├── requirements.txt          # Python dependencies
└── .gitignore                # Git ignore rules
```

## Output

When you run the analyzer without a custom path, it creates a report in the repository output directory. For example:

```bash
python src/main.py -f samples/helloWorld.exe -o output/report.json
```

This writes a structured JSON result alongside the terminal analysis summary.

## Contributing

Contributions are welcome. To contribute:

1. Fork the repository.
2. Create a feature branch.
3. Commit your changes with a clear message.
4. Push the branch and open a pull request.

## License

This project is distributed under the MIT License. See [LICENSE](LICENSE) for more information.

---

Built for static malware triage, PE structure inspection, and fast IOC extraction.