# AWS IAM Privilege Escalation Path Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Security-Defensive_Auditor-blue?style=flat" alt="Type">
  <img src="https://img.shields.io/badge/Status-Architectural_Showcase-success?style=flat" alt="Status">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white" alt="Python">
</p>

> 🔒 **Technical Showcase & Architecture Specification**  
> *This repository provides public architectural documentation, system specifications, and implementation summaries. Full production source code, internal test suites, and proprietary algorithms are maintained in a secure private repository.*

---

## 📌 Executive Summary

**Category**: Identity & Access Management (IAM)  
**Tech Stack**: `Python 3.10+ · AWS IAM Policy Grammar · Graph Traversal · Security Analysis`  

Graph-based permission scanner identifying combinations of IAM permissions that allow non-admin users to elevate privileges to Administrator.

---

## 🎯 The Problem It Solves

AWS IAM permissions are deceptively complex. A user without `AdministratorAccess` may possess permissions like `iam:CreatePolicyVersion` or `iam:PassRole` + `lambda:CreateFunction` that can be leveraged to grant themselves full root permissions.

---

## ⚙️ How the Engine Works

1. **IAM Policy Deconstruction**: Parses identity-based policies, inline policies, and permission boundaries across IAM users, groups, and roles.
2. **Action Matrix Expansion**: Resolves wildcard actions (`iam:*`, `sts:*`) and action wildcards (`Put*`, `Attach*`) into concrete API capabilities.
3. **Escalation Vector Matching**: Evaluates permissions against 21 documented AWS privilege escalation techniques, including:
   - `iam:CreatePolicyVersion` (making oneself admin)
   - `iam:SetDefaultPolicyVersion` (reverting to prior admin policy)
   - `iam:AttachUserPolicy` / `iam:AttachRolePolicy`
   - `iam:PassRole` combined with EC2, Lambda, or CloudFormation creation
4. **Blast Radius Computation**: Determines the effective maximum permissions reachable from the current principal's state.
5. **Report Generation**: Outputs step-by-step escalation paths with explicit remediation policies.

---

## 🚀 Key Capabilities

- Detects 21+ known AWS IAM privilege escalation vectors
- Evaluates combined effective permissions across groups and attached policies
- Highlights stealthy escalation paths through resource creation and role passing
- Generates least-privilege replacement policies

---

## 🏗️ System Data Flow & Architecture

```
+-----------------------------------+
|  Target Input / Configuration    |
|  (JSON Snapshots / Policies)      |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  1. Schema Normalization Engine   |
|  Validates types & formats        |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  2. Core Analytical Pipeline      |
|  Heuristic rule evaluation,       |
|  invariant checks & drift diffs   |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  3. Risk Classification           |
|  Assigns severity: INFO / HIGH    |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  4. Structured Findings & Report  |
|  Root cause, evidence &           |
|  actionable remediation steps     |
+-----------------------------------+
```

---

## 📄 Findings Output Structure

The engine generates structured, machine-parsable JSON reports adhering to this standard audit schema:

```json
{
  "results": [
    {
      "resource": "resource-identifier",
      "severity": "HIGH",
      "check": "CHECK_IDENTIFIER",
      "detail": "Descriptive analysis of the identified security posture issue.",
      "remediation": "Actionable step-by-step guidance to restore compliant state.",
      "evidence": {
        "observed_field": "value",
        "required_policy": "enforced_policy"
      }
    }
  ],
  "count": 1,
  "scope": "Comprehensive defensive security audit"
}
```

---

## 🔒 Source Code & Enterprise Inquiries

To protect proprietary intellectual property and client operational security:
* **Public Repository**: Contains comprehensive architecture specifications, schemas, and design overviews.
* **Private Repository**: Contains the complete production implementation, continuous integration pipelines, and full regression test suites.

For architectural questions or enterprise inquiries, connect via [LinkedIn](https://www.linkedin.com/in/karthikeyansubramaniam04/) or visit the [Portfolio Site](https://karthikeyansubramaniyam.github.io).
