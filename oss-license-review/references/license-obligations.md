# License Obligations Quick Reference

Use this reference to convert detected licenses into practical obligations.

## Permissive Licenses

### MIT / BSD-2 / BSD-3 / ISC
- Keep copyright and license text.
- Include attribution in redistributed source/binary packages.
- No source disclosure requirement.
- Typical risk: low.

### Apache-2.0
- Keep LICENSE and required NOTICE text (if NOTICE exists).
- Mark significant modifications in redistributed versions.
- Includes patent license terms and patent termination clauses.
- Typical risk: low to medium if NOTICE/patent handling is missing.

## Weak Copyleft

### MPL-2.0
- File-level copyleft: modified MPL files must remain under MPL when distributed.
- Keep license headers and notices.
- Other files can remain under other licenses.
- Typical risk: medium when modifications are redistributed.

### LGPL-2.1 / LGPL-3.0
- Library copyleft with linking conditions.
- If distributing binaries, provide path for relinking/replacement (details vary).
- Modifications to LGPL components usually require source disclosure.
- Typical risk: medium, higher for static linking.

## Strong Copyleft

### GPL-2.0 / GPL-3.0
- Derivative work distribution generally requires GPL-compatible licensing and source offer.
- Keep notices and license copy.
- Compatibility with proprietary distribution is often problematic.
- Typical risk: high for closed-source shipped products.

### AGPL-3.0
- GPL-like obligations plus network use trigger (SaaS/service access scenario).
- If users interact with modified AGPL software over a network, source obligations can apply.
- Typical risk: high for hosted services.

## Common Review Decisions

1. Clarify usage mode:
- Internal-only
- SaaS/hosted service
- Binary distribution
- Source distribution

2. Clarify modification and integration mode:
- Unmodified use vs modified fork
- Static vs dynamic linking (if applicable)
- Copying snippets vs using as separate component

3. Output required actions:
- Include license text and attribution
- Include NOTICE file content
- Publish source/modification patches if required
- Replace dependency if incompatible with target distribution model

## SPDX Composite Expressions

- For `OR` expressions, document which branch you selected and why.
- For `AND` expressions, assume obligations from all listed licenses apply together.
- For `WITH` exceptions, keep the exact exception text in compliance records.
- Known linking exceptions (e.g., `Classpath-exception-2.0`) may reduce GPL branch risk, but do not remove all obligations.
- Check that the exception is compatible with the GPL version in the same branch (e.g., some exceptions are GPL-2.0-only oriented).
- Use the built-in exception map as a first-pass check, but manually verify uncommon exceptions.
- If expression evaluation yields different risk branches, report both `minimum` and `maximum` risk until branch selection is fixed.
- If expression evaluation is truncated due to branch explosion, treat result as conservative and perform manual review.

## CycloneDX 1.5+ Notes

- Read license info from `metadata.component`, `components`, and `services`.
- Include `evidence.licenses` when present, not only top-level `licenses`.
- Keep `bomFormat` and `specVersion` in compliance artifacts for traceability.
- Prefer streaming parsing for very large SBOMs to reduce memory pressure.
- If streaming fails, fall back to full parsing and report parse mode for traceability.

## Respect and Give-Back Practices

- Preserve author attribution and license headers instead of stripping them.
- Contribute fixes upstream to reduce long-term private-fork compliance burden.
- Share non-sensitive bugfixes, test improvements, and docs updates when possible.
- Keep transparent changelogs for modified upstream components.
- Support key upstream maintainers via sponsorship, issue triage, or review help.

## Red Flags

- No license file and no clear declaration.
- Conflicting declarations across files (dual/multi-license ambiguity not resolved).
- Dependency lock shows GPL/AGPL in a proprietary distribution plan.
- Missing NOTICE handling for Apache-2.0 dependencies.
- "Custom license" text without clear grants.

## Disclaimer Template

Use this sentence in final output:

"This is a technical compliance assessment based on repository evidence, not legal advice."
