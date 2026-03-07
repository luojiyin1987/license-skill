---
name: oss-license-review
description: Analyze open-source license terms and compliance obligations for a repository. Use when asked to identify project licenses, explain what is required when reusing code, assess copyleft/commercial compatibility, or produce a practical risk checklist before shipping.
---

# OSS License Review

Perform a practical open-source license review from repository evidence and translate findings into deploy-time obligations.

## Workflow

1. Collect evidence first, then explain obligations.
2. Distinguish facts from inference:
   - Facts: detected files, SPDX identifiers, declared licenses.
   - Inference: likely obligations and compatibility risk.
3. Report uncertainty explicitly when license evidence is missing or contradictory.
4. State that this is compliance guidance, not legal advice.

## Step 1: Gather License Evidence

Run the inventory script on the target repo:

```bash
python3 scripts/license_inventory.py /path/to/repo --use-case saas --modified
```

If needed, output machine-readable JSON:

```bash
python3 scripts/license_inventory.py /path/to/repo --use-case binary --json
```

Usage scenario flags:
- `--use-case unknown|internal|saas|binary|source`
- `--modified` when you changed upstream code

Always inspect at least:
- Root `LICENSE*`, `COPYING*`, `NOTICE*`
- `package.json`, `pyproject.toml`, `Cargo.toml`, `pom.xml`, `composer.json` (if present)
- `package-lock.json` for dependency license hints (if present)
- `sbom.json`, `cyclonedx.json`, `spdx.json`, `*.spdx.json` (if present)

The script evaluates SPDX expressions (`AND` / `OR` / `WITH` / parentheses), models a broad SPDX exception map (40+ entries) in risk scoring, and performs exception/base-license compatibility checks.
It reports branch risk range (`min..max`) and warnings when exception compatibility is uncertain.
For very complex expressions, evaluation applies depth/branch limits and reports truncation warnings.
For large SBOM files, the parser uses streaming mode when optional `ijson` is available, and falls back to full JSON parsing on stream failure.

## Step 2: Classify License Type and Risk

Use `references/license-obligations.md` to map detected licenses to obligations.

Risk baseline:
- `low`: Permissive licenses (MIT/BSD/Apache-2.0) with clear attribution path.
- `medium`: Weak copyleft or file-level copyleft (MPL/LGPL) or unclear evidence.
- `high`: Strong/network copyleft (GPL/AGPL), license conflict, or missing license.

Compatibility checks to always perform:
- Planned usage mode: internal-only, SaaS, binary distribution, source redistribution.
- Whether code is modified and redistributed.
- Whether static/dynamic linking or derivative work risk exists.
- Patent and notice requirements (especially Apache-2.0 and NOTICE files).

## Step 3: Produce Actionable Output

Return results in this structure:

```text
License Findings
- Primary project license: <id or unknown>
- Additional detected licenses: <list>
- Evidence: <files and key declarations>

Usage Impact
- Your scenario: <internal / SaaS / distributed binary / source release>
- Required actions: <attribution, notice, source disclosure, license copy, changes disclosure>
- Restrictions and conflict notes: <if any>

Risk Assessment
- Level: <low/medium/high>
- Why: <short rationale>
- Unknowns: <missing files, ambiguous statements, dual-license uncertainty>

Respect and Give Back
- Suggested actions: <upstream fixes, docs contribution, clear changelog, sponsorship>

Recommended Next Actions
1. <action>
2. <action>
3. <action>
```

## Rules for Answers

- Prefer precise file references over generic claims.
- Do not claim full transitive dependency compliance unless fully verified.
- If data is incomplete, provide a conservative checklist and list missing evidence.
- Flag AGPL/GPL usage for distribution or hosted-service scenarios.
- Mention trademark and patent caveats when relevant.
- Include both mandatory compliance actions and optional give-back actions.
- For SPDX composite expressions (e.g., `MIT OR Apache-2.0`), state the branch-selection assumption explicitly.
- For CycloneDX 1.5+ SBOMs, inspect license fields from `metadata`, `components`, `services`, and `evidence`.
