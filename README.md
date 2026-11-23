# PhishTrace
### Phishing Email Investigation & Threat Intelligence Platform

PhishTrace is a Python-based security analysis tool designed to investigate phishing emails, extract indicators of compromise (IOCs), enrich findings with threat intelligence, and identify potential phishing campaigns through shared infrastructure and evidence.

## Key Features

- **Email Analysis:** Parse `.eml` files and extract email headers, authentication results, message bodies, hyperlinks, and attachment metadata.
- **IOC Extraction:** Identify email addresses, domains, IPv4 addresses, and URLs.
- **Attachment Fingerprinting:** Calculate SHA-256 hashes without executing attachments.
- **Threat Intelligence:** Enrich indicators using the VirusTotal API.
- **Campaign Correlation:** Identify relationships between emails using shared indicators and graph-based correlation.
- **Campaign Scoring:** Apply transparent, heuristic weights to shared evidence to prioritize investigations.
- **Report Generation:** Export investigation results as JSON and Markdown.
- **Batch Analysis:** Analyze multiple email files in one operation.

## Architecture

The project is organized into modular components:

| Module | Responsibility |
|---|---|
| `email_analysis/` | Email parsing and IOC extraction |
| `threat_intelligence/` | Threat intelligence providers and normalization |
| `campaign/` | Campaign correlation, scoring, and analysis |
| `reporting/` | JSON and Markdown report generation |
| `tests/` | Automated unit and integration tests |
| `main.py` | Command-line interface |

## Requirements

- Python 3.10 or later
- VirusTotal API key (optional, for threat intelligence enrichment)

The core analysis features use Python's standard library.

## Usage

### Investigate a single email

```bash
python main.py samples/phishing_sample.eml
```

### Enable VirusTotal enrichment

Set your API key as an environment variable.

PowerShell:

```powershell
$env:VIRUSTOTAL_API_KEY="YOUR_API_KEY"
```

Then run:

```bash
python main.py samples/phishing_sample.eml --enrich
```

### Analyze a directory of emails

```bash
python main.py --batch samples/
```

### Export reports

Markdown:

```bash
python main.py --batch samples/ --export markdown
```

JSON:

```bash
python main.py --batch samples/ --export json
```

Both formats:

```bash
python main.py --batch samples/ --export both
```

Specify a custom output directory:

```bash
python main.py --batch samples/ --export both --output reports
```

## Campaign Scoring

PhishTrace uses a heuristic scoring model to prioritize relationships between email investigations.

| Shared indicator | Weight |
|---|---:|
| Attachment SHA-256 | 5 |
| URL | 4 |
| Domain | 3 |
| IPv4 address | 2 |
| Email address | 1 |

The campaign score is based on the strongest direct relationship between two investigations.

**Important:** These scores are prioritization aids, not statistical probabilities or proof of malicious activity. Shared infrastructure can also occur in legitimate emails.

## Testing

Run the automated test suite:

```bash
python -m unittest discover -s tests -v
```

## Security Considerations

- Email content and headers are treated as untrusted input.
- Attachments are fingerprinted, not executed.
- URLs are extracted but not automatically visited.
- VirusTotal enrichment queries existing reports; attachments are not uploaded.
- Avoid submitting confidential indicators to external threat intelligence services without authorization.

## Project Scope

PhishTrace is an educational and portfolio project demonstrating email analysis, IOC extraction, threat intelligence integration, evidence-based correlation, and security reporting.