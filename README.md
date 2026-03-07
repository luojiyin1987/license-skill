# License Skill Workspace

This repository contains an OSS license review skill focused on:

- License evidence discovery in source repositories
- SPDX expression evaluation (`AND` / `OR` / `WITH`, including risk range)
- CycloneDX/SPDX SBOM license extraction
- Practical compliance guidance, risk alerts, and open-source give-back suggestions

## Project Layout

- `oss-license-review/SKILL.md`: skill behavior and workflow
- `oss-license-review/scripts/license_inventory.py`: main analyzer CLI
- `oss-license-review/references/license-obligations.md`: obligation reference
- `oss-license-review/tests/`: unit and CLI integration tests

## Quick Start

Run analysis (human-readable output):

```bash
python3 oss-license-review/scripts/license_inventory.py /path/to/repo --use-case saas --modified
```

Run JSON output:

```bash
python3 oss-license-review/scripts/license_inventory.py /path/to/repo --use-case binary --json
```

## Test

Run test suite:

```bash
python3 -m unittest discover -s oss-license-review/tests -v
```

## Notes

- Output is technical compliance guidance, not legal advice.
- For large SBOM files, streaming mode may be used when optional `ijson` is available.
