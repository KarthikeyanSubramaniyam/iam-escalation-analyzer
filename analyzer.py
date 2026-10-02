"""Flag candidate IAM escalation permission combinations for manual review."""

import fnmatch

def analyze(data):
    allow, deny = [], []
    for s in data.get("Statement", []):
        actions = s.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if s.get("Effect") == "Allow":
            allow.extend(actions)
        elif s.get("Effect") == "Deny":
            deny.extend(actions)
    def permitted(action):
        return any(fnmatch.fnmatchcase(action.lower(), p.lower()) for p in allow)
    combinations = [
        ("CREATE_POLICY_VERSION", ["iam:CreatePolicyVersion"], "A new policy version might become the default."),
        ("ATTACH_USER_POLICY", ["iam:AttachUserPolicy"], "Attaching a powerful policy might raise user privileges."),
        ("PASSROLE_LAMBDA", ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "A function might execute with a stronger role."),
        ("PASSROLE_EC2", ["iam:PassRole", "ec2:RunInstances"], "An instance might obtain a stronger role.")
    ]
    out = []
    for check, required, detail in combinations:
        if all(permitted(a) for a in required):
            out.append(finding("policy", "MEDIUM", check, detail + " Candidate only: resources, conditions, denies, boundaries and trust must be evaluated.", "Restrict privileged actions and passed roles; validate effective access.", {"required_actions": required, "deny_patterns": deny}))
    return out

import argparse
import json
import sys
from pathlib import Path

def finding(resource, severity, check, detail, remediation, evidence):
    return dict(resource=resource, severity=severity, check=check, detail=detail, remediation=remediation, evidence=evidence)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument("--fail-on-high", action="store_true")
    args = p.parse_args()
    try:
        data = json.loads(args.input.read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict):
            raise ValueError("Expected JSON object")
        results = analyze(data)
        text = json.dumps({"results": results, "count": len(results), "scope": __doc__}, indent=2)
        if args.output:
            args.output.write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
        return int(args.fail_on_high and any(r["severity"] == "HIGH" for r in results))
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as e:
        print(f"Input/report error: {e}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())

