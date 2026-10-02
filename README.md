# iam-escalation-analyzer

Flag candidate IAM escalation permission combinations for manual review.

## Usage

Python 3.10+; Windows, Linux and macOS. No dependencies or cloud credentials.

```bash
python analyzer.py sample.json
python analyzer.py inventory.json --output report.json --fail-on-high
python -B -m unittest -v
```

Exit codes: 0 completed, 1 HIGH results when requested, 2 invalid input/I/O error.

## Input and interpretation

Use the supplied sample.json as the exact input schema. CloudTrail projects consume a Records array. Other projects consume normalized inventory or IAM statements; collection from cloud APIs is outside this version's scope. Required fields must follow the sample types. The IAM project expects Statement to be an array.

Results contain evidence, severity, explanation and remediation. UNKNOWN means missing information, INFO records an event or change, MEDIUM requests review and HIGH requests priority investigation. These are focused analyst utilities, not comprehensive posture assessments. Inspect the supported checks in analyzer.py; a clean report covers only those checks. Real inventory and reports may contain sensitive identifiers; keep them out of public repositories. No input is uploaded and no cloud resource is changed.

## Validation

Tests cover selected detection and false-positive cases. Sample data is fictional. Run tests before adopting or extending rules. Live provider behavior and effective access require separate validation.

