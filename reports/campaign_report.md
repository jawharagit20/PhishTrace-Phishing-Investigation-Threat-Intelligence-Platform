# PhishTrace - Campaign Investigation Report

## Investigation Summary

- Files discovered: 2
- Successful investigations: 2
- Failed files: 0
- Campaigns detected: 1

---

## Investigation Scope

- Emails analyzed: 2
- Analysis source: Locally provided email files
- Threat intelligence enrichment: Not recorded in the batch summary

## Campaign Findings

---

### CAMPAIGN-001

- Related emails: 2
- Heuristic correlation score: 10
- Priority level: HIGH

#### Related Emails

- phishing_sample.eml
- phishing_sample_2.eml

#### Shared Indicators

**Email Addresses**
- `security-alert@example.test`

**Domains**
- `example.test`
- `login-example.test`

**Ipv4 Addresses**
- `192.0.2.45`

**Urls**
- `https://example.test/verify`

#### Relationship Evidence

**phishing_sample.eml** → **phishing_sample_2.eml**

Heuristic correlation score: 10 (HIGH)

- Shared URL: +4 points (original: +4; not downweighted)
  - `https://example.test/verify` (seen in 2 investigations)
- Shared domain: +3 points (original: +3; not downweighted)
  - `example.test` (seen in 2 investigations)
  - `login-example.test` (seen in 2 investigations)
- Shared IP address: +2 points (original: +2; not downweighted)
  - `192.0.2.45` (seen in 2 investigations)
- Shared email address: +1 point (original: +1; not downweighted)
  - `security-alert@example.test` (seen in 2 investigations)

---

## Assessment and Limitations

Campaign relationships are identified through shared indicators between investigated emails. The scoring method is: frequency-aware heuristic weighted indicator matching.

Indicator frequency is calculated within the analyzed batch. Indicators appearing in at least three investigations and at least half of the batch are downweighted.

Evidence retains the original indicator weight, applied weight, matched values, and observed frequency to support transparent analysis.

Correlation scores are heuristic prioritization aids. They are not statistical probabilities, verified threat intelligence verdicts, or proof of malicious activity.

Shared infrastructure may be used by legitimate services. Findings should be reviewed alongside additional technical evidence before drawing conclusions.
