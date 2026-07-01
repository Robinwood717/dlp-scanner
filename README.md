# DLP Scanner / Auditor

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Standard](https://img.shields.io/badge/Standard-ISO%2027001-blue)
![Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen)

A Python tool that **scans folders for exposed sensitive data** — credit card numbers, Greek tax IDs (AFM), and email addresses — and produces a clean audit report. Raw values are **never** written to the output; only masked versions appear (e.g. `****-****-****-1234`).

---

## What it does

You point it at a folder. It reads every `.txt` and `.csv` file inside (including subfolders), detects sensitive data, and writes a report — in JSON, CSV, or both.

```
Before scan:  customers.csv contains "4532015112830366"
After report: "masked_value": "****-****-****-0366"
```

---

## Get started in 3 steps

### Step 1 — Clone the project

```bash
git clone https://github.com/YOUR-GITHUB-USERNAME/dlp-scanner.git
cd dlp-scanner
```

> Replace `YOUR-GITHUB-USERNAME` with your actual GitHub username.

### Step 2 — (Recommended) Create a virtual environment

A virtual environment keeps this project isolated from the rest of your Python installation. This is best practice even though the tool has no external dependencies.

```bash
# Create it
python -m venv venv

# Activate it — Windows
venv\Scripts\activate

# Activate it — macOS / Linux
source venv/bin/activate
```

You will see `(venv)` appear at the start of your terminal prompt. That means it is active.

### Step 3 — Install and run

```bash
pip install -r requirements.txt
python main.py --target sample_data --format both --output my_first_report
```

That's it. You will see a summary printed in the terminal and two report files created: `my_first_report.json` and `my_first_report.csv`.

> **Windows note:** If `python` does not work, use `py` instead.

---

## Running a scan on your own data

Replace `sample_data` with the path to the folder you want to scan:

```bash
# Produce a JSON report
python main.py --target C:\path\to\your\folder

# Produce both JSON and CSV
python main.py --target C:\path\to\your\folder --format both --output audit_report

# See detailed scan progress
python main.py --target C:\path\to\your\folder --verbose
```

---

## All command-line options

| Option | What it does | Default |
|---|---|---|
| `--target` | Folder to scan | Current directory |
| `--format` | Output format: `json`, `csv`, or `both` | `json` |
| `--output` | Report filename (no extension needed) | `dlp_report` |
| `--verbose` | Show per-file debug details | Off |

---

## What gets detected

| Data type | Example (raw) | How it appears in the report |
|---|---|---|
| Credit card | `4532015112830366` | `****-****-****-0366` |
| Greek AFM | `123456787` | `XXXXXX787` |
| Email address | `alex@example.gr` | `****@example.gr` |

The tool does **not** just rely on pattern matching. It applies real validation algorithms to filter out false positives:

- **Credit cards** — validated with the Luhn algorithm (ISO/IEC 7812-1). A number that looks like a card but fails the checksum is ignored.
- **Greek AFM** — validated with the official GSIS check-digit formula. Random 9-digit numbers that happen to appear in a file are ignored.
- **Emails** — matched against a strict RFC 5322 pattern with word boundaries to avoid partial matches.

---

## What the report looks like

### Terminal summary

```
============================================================
  DLP SCAN SUMMARY
============================================================
  Files scanned : 3
  Files skipped : 0
  Total findings: 25

  Breakdown by data type:
    Credit Card          8
    Email                9
    Greek AFM            8
============================================================
```

### JSON report

```json
[
  {
    "timestamp": "2026-07-01T10:30:00Z",
    "file_path": "C:/data/customers.csv",
    "line_number": 2,
    "data_type": "Credit Card",
    "masked_value": "****-****-****-0366"
  },
  {
    "timestamp": "2026-07-01T10:30:00Z",
    "file_path": "C:/data/notes.txt",
    "line_number": 11,
    "data_type": "Greek AFM",
    "masked_value": "XXXXXX787"
  }
]
```

### CSV report

```
timestamp,file_path,line_number,data_type,masked_value
2026-07-01T10:30:00Z,C:/data/customers.csv,2,Credit Card,****-****-****-0366
2026-07-01T10:30:00Z,C:/data/notes.txt,11,Greek AFM,XXXXXX787
```

---

## Project structure

```
dlp-scanner/
│
├── dlp_scanner/
│   ├── models.py        # The structure of a single finding (dataclass)
│   ├── detectors.py     # Pattern matching + validation algorithms
│   ├── scanner.py       # Walks directories, reads files
│   └── reporter.py      # Writes JSON / CSV reports
│
├── sample_data/         # Synthetic test files — no real PII
│   ├── customers.csv
│   ├── notes.txt
│   └── latin1_notes.txt  # Tests encoding fallback (UTF-8 → Latin-1)
│
├── main.py              # Entry point — run this
├── requirements.txt     # No external packages needed
├── .gitignore
├── LICENSE
├── SECURITY.md          # Vulnerability reporting policy
├── README.md
└── README.html          # Visual documentation (open in browser)
```

---

## Adding a new detector

Open `dlp_scanner/detectors.py` and add a class at the bottom:

```python
class IBANDetector(BaseDetector):
    name = "IBAN"
    _PATTERN = re.compile(r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b')

    @staticmethod
    def _mask(value: str) -> str:
        return f"****{value[-4:]}"

    def find_all(self, line: str) -> List[Tuple[str, str]]:
        return [(m.group(), self._mask(m.group())) for m in self._PATTERN.finditer(line)]
```

Then register it in `DEFAULT_DETECTORS` (at the bottom of the same file):

```python
DEFAULT_DETECTORS = [
    CreditCardDetector(),
    GreekAFMDetector(),
    EmailDetector(),
    IBANDetector(),   # <-- add here
]
```

Nothing else needs to change.

---

## Important notes

- **Generated reports are excluded from git** (see `.gitignore`). Never commit a report file — even masked data should be treated as sensitive.
- **Only scan folders you are authorized to access.** This tool is for internal auditing. Unauthorized scanning may violate GDPR and Greek Law 4624/2019.
- Files that cannot be read (permission errors, unknown encoding) are **skipped and logged** — the scan continues.

---

## Requirements

- Python 3.9 or higher
- No external packages

---

## License

[MIT](LICENSE)
