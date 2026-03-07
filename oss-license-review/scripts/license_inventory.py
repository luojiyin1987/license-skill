#!/usr/bin/env python3
"""Collect license evidence and generate compliance-oriented risk guidance."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None

try:
    import ijson
except ModuleNotFoundError:  # pragma: no cover
    ijson = None


SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    "target",
    ".next",
    ".nuxt",
}

LICENSE_FILE_RE = re.compile(r"^(license|copying|notice)(\..+)?$", re.IGNORECASE)
SPDX_RE = re.compile(r"SPDX-License-Identifier:\s*([^\r\n]+)")
SPDX_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9\.\-\+]*")
SPDX_EXPR_TOKEN_RE = re.compile(
    r"\(|\)|\bAND\b|\bOR\b|\bWITH\b|[A-Za-z0-9][A-Za-z0-9\.\-\+\:]*",
    re.IGNORECASE,
)
SPDX_OPERATOR_TOKENS = {"AND", "OR", "WITH"}
SBOM_FILE_NAMES = {"sbom.json", "bom.json", "cyclonedx.json", "spdx.json"}

LOW_RISK_LICENSES = {"MIT", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "ISC", "APACHE-2.0"}
MEDIUM_RISK_LICENSES = {"MPL-2.0", "LGPL", "LGPL-2.1", "LGPL-3.0", "EPL", "EPL-2.0"}
HIGH_COPYLEFT_LICENSES = {
    "GPL",
    "GPL-2.0",
    "GPL-3.0",
    "AGPL",
    "AGPL-3.0",
    "AGPL-3.0-ONLY",
    "AGPL-3.0-OR-LATER",
    "GPL-2.0-ONLY",
    "GPL-2.0-OR-LATER",
    "GPL-3.0-ONLY",
    "GPL-3.0-OR-LATER",
}

USE_CASES = ("unknown", "internal", "saas", "binary", "source")
RISK_LEVEL_SCORE = {"low": 1, "medium": 2, "high": 3}
MAX_SPDX_PARSE_DEPTH = 32
MAX_SPDX_BRANCHES = 128
SBOM_STREAMING_THRESHOLD_BYTES = 2 * 1024 * 1024
SPDX_ALIAS_MAP = {
    "GPL-2.0+": "GPL-2.0-OR-LATER",
    "GPL-3.0+": "GPL-3.0-OR-LATER",
    "AGPL-3.0+": "AGPL-3.0-OR-LATER",
    "LGPL-2.1+": "LGPL-2.1-OR-LATER",
    "LGPL-3.0+": "LGPL-3.0-OR-LATER",
}
COPYLEFT_EXCEPTIONS_REDUCE_RISK = {
    "CLASSPATH-EXCEPTION-2.0",
    "BOOTLOADER-EXCEPTION",
    "BISON-EXCEPTION-2.2",
    "ASTERISK-EXCEPTION",
    "AUTOCONF-EXCEPTION-2.0",
    "AUTOCONF-EXCEPTION-3.0",
    "AUTOCONF-EXCEPTION-GENERIC",
    "CLISP-EXCEPTION-2.0",
    "DIGIRULE-FOSS-EXCEPTION",
    "ECOS-EXCEPTION-2.0",
    "FAWKES-RUNTIME-EXCEPTION",
    "FLTK-EXCEPTION",
    "FREERTOS-EXCEPTION-2.0",
    "GCC-EXCEPTION-2.0",
    "GCC-EXCEPTION-3.1",
    "I2P-GPL-JAVA-EXCEPTION",
    "LIBTOOL-EXCEPTION",
    "LLVM-EXCEPTION",
    "OCAML-LGPL-LINKING-EXCEPTION",
    "OPENJDK-ASSEMBLY-EXCEPTION-1.0",
    "OPENVPN-OPENSSL-EXCEPTION",
    "QT-GPL-EXCEPTION-1.0",
    "QT-LGPL-EXCEPTION-1.1",
    "U-BOOT-EXCEPTION-2.0",
    "WXWINDOWS-EXCEPTION-3.1",
    "LLVM-EXCEPTION",
    "OPENSSL-EXCEPTION",
}
GPL2_FAMILY = {"GPL", "GPL-2.0", "GPL-2.0-ONLY", "GPL-2.0-OR-LATER"}
GPL3_FAMILY = {"GPL", "GPL-3.0", "GPL-3.0-ONLY", "GPL-3.0-OR-LATER"}
GPL_ANY_FAMILY = GPL2_FAMILY | GPL3_FAMILY
LGPL2_FAMILY = {"LGPL", "LGPL-2.1", "LGPL-2.1-OR-LATER"}
LGPL3_FAMILY = {"LGPL", "LGPL-3.0", "LGPL-3.0-OR-LATER"}
LGPL_ANY_FAMILY = LGPL2_FAMILY | LGPL3_FAMILY
COPYLEFT_ANY_FAMILY = GPL_ANY_FAMILY | LGPL_ANY_FAMILY
EXCEPTION_GPL_COMPATIBILITY = {
    "389-EXCEPTION": GPL_ANY_FAMILY,
    "ASTERISK-EXCEPTION": GPL2_FAMILY,
    "AUTOCONF-EXCEPTION-2.0": GPL2_FAMILY,
    "AUTOCONF-EXCEPTION-3.0": GPL3_FAMILY,
    "AUTOCONF-EXCEPTION-GENERIC": GPL_ANY_FAMILY,
    "BISON-EXCEPTION-2.2": GPL2_FAMILY,
    "BOOTLOADER-EXCEPTION": GPL2_FAMILY,
    "CLASSPATH-EXCEPTION-2.0": GPL2_FAMILY,
    "CLISP-EXCEPTION-2.0": GPL2_FAMILY,
    "DIGIRULE-FOSS-EXCEPTION": GPL_ANY_FAMILY,
    "ECOS-EXCEPTION-2.0": GPL_ANY_FAMILY,
    "FAWKES-RUNTIME-EXCEPTION": GPL_ANY_FAMILY,
    "FLTK-EXCEPTION": LGPL_ANY_FAMILY,
    "FONT-EXCEPTION-2.0": GPL_ANY_FAMILY,
    "FREERTOS-EXCEPTION-2.0": GPL_ANY_FAMILY,
    "GCC-EXCEPTION-2.0": GPL2_FAMILY,
    "GCC-EXCEPTION-3.1": GPL3_FAMILY,
    "GMSH-EXCEPTION": GPL_ANY_FAMILY,
    "GNAT-EXCEPTION": GPL_ANY_FAMILY,
    "GNUPLOT-EXCEPTION": GPL_ANY_FAMILY,
    "I2P-GPL-JAVA-EXCEPTION": GPL_ANY_FAMILY,
    "KIWI-EXCEPTION": GPL_ANY_FAMILY,
    "LIBTOOL-EXCEPTION": GPL_ANY_FAMILY,
    "LINUX-SYSCALL-NOTE": GPL_ANY_FAMILY,
    "LLVM-EXCEPTION": GPL_ANY_FAMILY,
    "LZMA-EXCEPTION": GPL_ANY_FAMILY,
    "MIF-EXCEPTION": GPL_ANY_FAMILY,
    "NOKIA-QT-EXCEPTION-1.1": LGPL_ANY_FAMILY,
    "OCAML-LGPL-LINKING-EXCEPTION": LGPL_ANY_FAMILY,
    "OCCT-EXCEPTION-1.0": LGPL_ANY_FAMILY,
    "OPENJDK-ASSEMBLY-EXCEPTION-1.0": GPL2_FAMILY,
    "OPENVPN-OPENSSL-EXCEPTION": GPL_ANY_FAMILY,
    "OPENSSL-EXCEPTION": GPL_ANY_FAMILY,
    "PS-OR-PDF-FONT-EXCEPTION-20170817": GPL_ANY_FAMILY,
    "QT-GPL-EXCEPTION-1.0": GPL_ANY_FAMILY,
    "QT-LGPL-EXCEPTION-1.1": LGPL_ANY_FAMILY,
    "QWT-EXCEPTION-1.0": LGPL_ANY_FAMILY,
    "SHL-2.0": COPYLEFT_ANY_FAMILY,
    "SHL-2.1": COPYLEFT_ANY_FAMILY,
    "SWIFT-EXCEPTION": GPL_ANY_FAMILY,
    "U-BOOT-EXCEPTION-2.0": GPL2_FAMILY,
    "UNIVERSAL-FOSS-EXCEPTION-1.0": GPL_ANY_FAMILY,
    "WXWINDOWS-EXCEPTION-3.1": GPL_ANY_FAMILY,
}

LICENSE_TEXT_PATTERNS = [
    ("AGPL", re.compile(r"gnu affero general public license", re.IGNORECASE)),
    (
        "LGPL",
        re.compile(
            r"gnu (lesser|library)\s+general public license", re.IGNORECASE
        ),
    ),
    ("GPL", re.compile(r"gnu general public license", re.IGNORECASE)),
    ("Apache-2.0", re.compile(r"apache license[, ]+version 2\.0", re.IGNORECASE)),
    (
        "MIT",
        re.compile(
            r"permission is hereby granted,\s+free of charge,\s+to any person obtaining a copy",
            re.IGNORECASE,
        ),
    ),
    (
        "BSD-3-Clause",
        re.compile(
            r"redistribution and use in source and binary forms.*neither the name of",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "BSD-2-Clause",
        re.compile(
            r"redistribution and use in source and binary forms.*are permitted provided that the following conditions are met",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    ("MPL-2.0", re.compile(r"mozilla public license.*2\.0", re.IGNORECASE | re.DOTALL)),
    ("EPL", re.compile(r"eclipse public license", re.IGNORECASE)),
]


def normalize_license_token(token: str) -> str:
    normalized = token.strip().upper()
    return SPDX_ALIAS_MAP.get(normalized, normalized)


def split_license_expression(value: str) -> list[str]:
    tokens = [normalize_license_token(t) for t in SPDX_TOKEN_RE.findall(value)]
    return [t for t in tokens if t not in SPDX_OPERATOR_TOKENS]


def extract_license_strings(obj: Any) -> list[str]:
    found: list[str] = []
    if isinstance(obj, str):
        found.append(obj)
    elif isinstance(obj, dict):
        for key, value in obj.items():
            if "license" in key.lower() or "licence" in key.lower():
                found.extend(extract_license_strings(value))
            elif isinstance(value, (dict, list)):
                found.extend(extract_license_strings(value))
    elif isinstance(obj, list):
        for value in obj:
            found.extend(extract_license_strings(value))
    return found


def iter_license_candidates(detected_ids: list[str], manifests: list[dict]) -> list[str]:
    candidates = list(detected_ids)
    for item in manifests:
        candidates.extend(extract_license_strings(item.get("declared", {})))
    return [x.strip() for x in candidates if isinstance(x, str) and x.strip()]


def is_spdx_expression(value: str) -> bool:
    upper = value.upper()
    return (
        " OR " in upper
        or " AND " in upper
        or " WITH " in upper
        or "(" in upper
        or ")" in upper
    )


class SPDXExpressionError(ValueError):
    pass


def tokenize_spdx_expression(value: str) -> list[str]:
    return [x for x in SPDX_EXPR_TOKEN_RE.findall(value) if x.strip()]


def parse_spdx_expression(value: str, max_depth: int = MAX_SPDX_PARSE_DEPTH):
    tokens = tokenize_spdx_expression(value)
    if not tokens:
        raise SPDXExpressionError("empty expression")
    index = 0

    def peek() -> str | None:
        return tokens[index] if index < len(tokens) else None

    def consume(expected: str | None = None) -> str:
        nonlocal index
        token = peek()
        if token is None:
            raise SPDXExpressionError("unexpected end of expression")
        if expected is not None and token.upper() != expected:
            raise SPDXExpressionError(f"expected {expected}, got {token}")
        index += 1
        return token

    def parse_primary(depth: int):
        if depth > max_depth:
            raise SPDXExpressionError(
                f"expression nesting too deep (>{max_depth})"
            )
        token = peek()
        if token is None:
            raise SPDXExpressionError("unexpected end of expression")
        if token == "(":
            consume("(")
            node = parse_or(depth + 1)
            if peek() != ")":
                raise SPDXExpressionError("missing closing parenthesis")
            consume(")")
            return node
        upper = token.upper()
        if upper in SPDX_OPERATOR_TOKENS or token == ")":
            raise SPDXExpressionError(f"unexpected token {token}")
        consume()
        return ("id", normalize_license_token(token))

    def parse_with(depth: int):
        node = parse_primary(depth)
        if (peek() or "").upper() == "WITH":
            consume("WITH")
            exc = consume()
            if exc.upper() in SPDX_OPERATOR_TOKENS or exc in {"(", ")"}:
                raise SPDXExpressionError("invalid exception token")
            node = ("with", node, normalize_license_token(exc))
        return node

    def parse_and(depth: int):
        node = parse_with(depth)
        while (peek() or "").upper() == "AND":
            consume("AND")
            node = ("and", node, parse_with(depth))
        return node

    def parse_or(depth: int):
        node = parse_and(depth)
        while (peek() or "").upper() == "OR":
            consume("OR")
            node = ("or", node, parse_and(depth))
        return node

    ast = parse_or(0)
    if index != len(tokens):
        raise SPDXExpressionError(f"unexpected trailing token: {tokens[index]}")
    return ast


def dedupe_branches(branches: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for branch in branches:
        key = (
            tuple(sorted(branch["licenses"])),
            tuple(sorted(branch["exceptions"])),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(branch)
    return result


def evaluate_spdx_ast(ast, max_branches: int = MAX_SPDX_BRANCHES) -> tuple[list[dict], bool]:
    node_type = ast[0]
    if node_type == "id":
        return [{"licenses": {ast[1]}, "exceptions": set()}], False
    if node_type == "with":
        branches, truncated = evaluate_spdx_ast(ast[1], max_branches=max_branches)
        updated = []
        for branch in branches:
            updated.append(
                {
                    "licenses": set(branch["licenses"]),
                    "exceptions": set(branch["exceptions"]) | {ast[2]},
                }
            )
        return dedupe_branches(updated), truncated
    if node_type == "and":
        left_branches, left_truncated = evaluate_spdx_ast(ast[1], max_branches=max_branches)
        right_branches, right_truncated = evaluate_spdx_ast(
            ast[2], max_branches=max_branches
        )
        merged = []
        truncated = left_truncated or right_truncated
        for left in left_branches:
            for right in right_branches:
                merged.append(
                    {
                        "licenses": set(left["licenses"]) | set(right["licenses"]),
                        "exceptions": set(left["exceptions"]) | set(right["exceptions"]),
                    }
                )
                if len(merged) >= max_branches:
                    truncated = True
                    break
            if len(merged) >= max_branches:
                break
        return dedupe_branches(merged[:max_branches]), truncated
    if node_type == "or":
        left_branches, left_truncated = evaluate_spdx_ast(ast[1], max_branches=max_branches)
        right_branches, right_truncated = evaluate_spdx_ast(
            ast[2], max_branches=max_branches
        )
        merged = dedupe_branches(left_branches + right_branches)
        truncated = left_truncated or right_truncated or len(merged) > max_branches
        return merged[:max_branches], truncated
    raise SPDXExpressionError(f"unknown ast node type: {node_type}")


def classify_tokens_risk(tokens: set[str]) -> str:
    if tokens & HIGH_COPYLEFT_LICENSES:
        return "high"
    if tokens & MEDIUM_RISK_LICENSES:
        return "medium"
    if tokens & LOW_RISK_LICENSES:
        return "low"
    if not tokens:
        return "high"
    return "medium"


def collect_copyleft_base_tokens(tokens: set[str]) -> set[str]:
    return {
        token
        for token in tokens
        if token == "GPL"
        or token.startswith("GPL-")
        or token == "LGPL"
        or token.startswith("LGPL-")
    }


def assess_exception_compatibility(
    licenses: set[str], exceptions: set[str]
) -> tuple[set[str], list[str]]:
    base_tokens = collect_copyleft_base_tokens(licenses)
    applicable = set()
    warnings = []
    for exception in exceptions:
        compat = EXCEPTION_GPL_COMPATIBILITY.get(exception)
        if compat is None:
            warnings.append(
                f"Exception '{exception}' is not in the built-in compatibility map; verify manually."
            )
            continue
        if not base_tokens:
            warnings.append(
                f"Exception '{exception}' appears without a GPL/LGPL base license in the same branch."
            )
            continue
        if base_tokens & compat:
            applicable.add(exception)
        else:
            warnings.append(
                f"Exception '{exception}' may be incompatible with base tokens: {', '.join(sorted(base_tokens))}."
            )
    return applicable, warnings


def apply_exception_risk_adjustment(
    base_risk: str, licenses: set[str], exceptions: set[str]
) -> tuple[str, str | None, list[str], set[str]]:
    applicable_exceptions, compatibility_warnings = assess_exception_compatibility(
        licenses, exceptions
    )
    if base_risk != "high":
        return base_risk, None, compatibility_warnings, applicable_exceptions
    if any(x.startswith("AGPL") or x == "AGPL" for x in licenses):
        return base_risk, None, compatibility_warnings, applicable_exceptions
    has_gpl = any(x.startswith("GPL") or x == "GPL" for x in licenses)
    if has_gpl and (applicable_exceptions & COPYLEFT_EXCEPTIONS_REDUCE_RISK):
        return (
            "medium",
            "Known GPL linking exception reduces copyleft risk for this branch.",
            compatibility_warnings,
            applicable_exceptions,
        )
    return base_risk, None, compatibility_warnings, applicable_exceptions


def evaluate_spdx_expression(value: str) -> dict:
    try:
        ast = parse_spdx_expression(value)
        branches, branches_truncated = evaluate_spdx_ast(ast)
    except SPDXExpressionError as err:
        return {
            "expression": value,
            "valid": False,
            "error": str(err),
        }

    branch_risks = []
    union_tokens = set()
    union_exceptions = set()
    high_risk_tokens = set()
    exception_impacts = []
    exception_compatibility_warnings = []
    applicable_exceptions = set()
    for branch in branches:
        licenses = set(branch["licenses"])
        exceptions = set(branch["exceptions"])
        union_tokens.update(licenses)
        union_exceptions.update(exceptions)
        base_risk = classify_tokens_risk(licenses)
        (
            effective_risk,
            impact,
            compatibility_warnings,
            branch_applicable_exceptions,
        ) = apply_exception_risk_adjustment(
            base_risk, licenses, exceptions
        )
        exception_compatibility_warnings.extend(compatibility_warnings)
        applicable_exceptions.update(branch_applicable_exceptions)
        branch_risks.append(effective_risk)
        if impact:
            exception_impacts.append(impact)
        if effective_risk == "high":
            high_risk_tokens.update(licenses & HIGH_COPYLEFT_LICENSES)

    min_risk = min(branch_risks, key=lambda x: RISK_LEVEL_SCORE[x]) if branch_risks else "high"
    max_risk = max(branch_risks, key=lambda x: RISK_LEVEL_SCORE[x]) if branch_risks else "high"
    return {
        "expression": value,
        "valid": True,
        "branch_count": len(branches),
        "branches_truncated": branches_truncated,
        "min_risk": min_risk,
        "max_risk": max_risk,
        "tokens": sorted(union_tokens),
        "branch_risks": unique_keep_order(branch_risks),
        "exceptions": sorted(union_exceptions),
        "applicable_exceptions": sorted(applicable_exceptions),
        "high_risk_tokens": sorted(high_risk_tokens),
        "exception_impacts": unique_keep_order(exception_impacts),
        "exception_compatibility_warnings": unique_keep_order(
            exception_compatibility_warnings
        ),
    }


def collect_spdx_expressions(detected_ids: list[str], manifests: list[dict]) -> list[str]:
    return unique_keep_order(
        [value for value in iter_license_candidates(detected_ids, manifests) if is_spdx_expression(value)]
    )


def collect_spdx_evaluations(detected_ids: list[str], manifests: list[dict]) -> list[dict]:
    return [evaluate_spdx_expression(x) for x in collect_spdx_expressions(detected_ids, manifests)]


def collect_non_expression_tokens(detected_ids: list[str], manifests: list[dict]) -> set[str]:
    tokens = set()
    for raw in iter_license_candidates(detected_ids, manifests):
        if is_spdx_expression(raw):
            continue
        tokens.update(split_license_expression(raw))
    return {t for t in tokens if len(t) > 1}


def collect_all_license_tokens(
    detected_ids: list[str], manifests: list[dict], spdx_evaluations: list[dict] | None = None
) -> set[str]:
    tokens = set(collect_non_expression_tokens(detected_ids, manifests))
    if spdx_evaluations:
        for item in spdx_evaluations:
            if not item.get("valid"):
                tokens.update(split_license_expression(item["expression"]))
                continue
            for token in item.get("tokens", []):
                tokens.add(normalize_license_token(token))
    return {t for t in tokens if len(t) > 1}


def unique_keep_order(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def has_any_token(tokens: set[str], candidates: set[str]) -> bool:
    return bool(tokens & candidates)


def assess_risk(
    detected_ids: list[str],
    manifests: list[dict],
    use_case: str,
    expressions: list[str],
    spdx_evaluations: list[dict],
) -> tuple[str, list[str], list[str], set[str]]:
    tokens = collect_all_license_tokens(detected_ids, manifests, spdx_evaluations)
    non_expression_tokens = collect_non_expression_tokens(detected_ids, manifests)
    expression_high_tokens = set()
    expr_range_notes = []
    expr_eval_notes = []
    valid_evals = [x for x in spdx_evaluations if x.get("valid")]
    invalid_evals = [x for x in spdx_evaluations if not x.get("valid")]
    risk_candidates = []
    if non_expression_tokens:
        risk_candidates.append(classify_tokens_risk(non_expression_tokens))
    for item in valid_evals:
        risk_candidates.append(item["max_risk"])
        expression_high_tokens.update(item.get("high_risk_tokens", []))
        min_risk = item["min_risk"]
        max_risk = item["max_risk"]
        if min_risk != max_risk:
            expr_range_notes.append(
                f"SPDX expression '{item['expression']}' risk range is {min_risk}..{max_risk} depending on chosen branch."
            )
        if item.get("exceptions"):
            expr_range_notes.append(
                f"SPDX expression '{item['expression']}' includes WITH exceptions: {', '.join(item['exceptions'])}."
            )
        for warning in item.get("exception_compatibility_warnings", []):
            expr_eval_notes.append(
                f"SPDX expression '{item['expression']}': {warning}"
            )
        if item.get("branches_truncated"):
            expr_eval_notes.append(
                f"SPDX expression '{item['expression']}' exceeded {MAX_SPDX_BRANCHES} branches; evaluation was truncated."
            )
        for impact in item.get("exception_impacts", []):
            expr_eval_notes.append(
                f"SPDX expression '{item['expression']}': {impact}"
            )
    for item in invalid_evals:
        risk_candidates.append("high")
        expr_eval_notes.append(
            f"SPDX expression '{item['expression']}' parse failed: {item.get('error', 'unknown error')}."
        )

    alerts = sorted((non_expression_tokens & HIGH_COPYLEFT_LICENSES) | expression_high_tokens)

    if not risk_candidates and not tokens:
        return (
            "high",
            [
                "No clear license signal detected.",
                "Using code without a clear license grant can create legal/compliance risk.",
            ],
            [],
            tokens,
        )

    overall_risk = max(risk_candidates, key=lambda x: RISK_LEVEL_SCORE[x]) if risk_candidates else classify_tokens_risk(tokens)
    if overall_risk == "high":
        reasons = [
            "Detected high-risk license obligations or unresolved expression uncertainty.",
            "Check distribution and SaaS scenarios before reusing or shipping code.",
        ]
    elif overall_risk == "medium":
        reasons = [
            "Detected moderate copyleft/notice obligations or mixed SPDX branch outcomes.",
            "Review linking, modification, and redistribution obligations carefully.",
        ]
    else:
        reasons = [
            "Detected mostly permissive license branches.",
            "Keep attribution, license text, and NOTICE requirements where applicable.",
        ]

    if use_case == "saas" and has_any_token(
        tokens, {"AGPL", "AGPL-3.0", "AGPL-3.0-ONLY", "AGPL-3.0-OR-LATER"}
    ):
        reasons.append(
            "AGPL in SaaS mode can require offering corresponding source to network users."
        )
    if expressions:
        reasons.append(
            "Composite SPDX expressions detected; verify and document the selected branch."
        )
    reasons.extend(expr_range_notes)
    reasons.extend(expr_eval_notes)
    return (
        overall_risk,
        unique_keep_order(reasons),
        alerts,
        tokens,
    )


def build_required_actions(tokens: set[str], use_case: str, modified: bool) -> list[str]:
    if not tokens:
        return [
            "Do not reuse code until a valid license grant is confirmed.",
            "Ask maintainers for explicit license terms or written permission.",
        ]

    actions = [
        "Keep a copy of each applicable license text in your repository/release package.",
        "Maintain an attribution record for reused components (name, version, source URL, license).",
    ]
    if use_case in {"binary", "source"}:
        actions.append(
            "Include attribution and license notices in distributed artifacts and documentation."
        )
    if "APACHE-2.0" in tokens:
        actions.append(
            "If Apache-2.0 code is used, preserve NOTICE content and mark significant modifications."
        )
    if tokens & {"MIT", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "ISC"}:
        actions.append(
            "For permissive components, keep copyright and permission notices."
        )
    if tokens & {"MPL-2.0", "LGPL", "LGPL-2.1", "LGPL-3.0", "EPL", "EPL-2.0"}:
        actions.append(
            "For weak-copyleft components, review linking/file-scope obligations before distribution."
        )
    if tokens & HIGH_COPYLEFT_LICENSES:
        actions.append(
            "For GPL/AGPL components, validate whether your distribution model is license-compatible."
        )
        if use_case in {"binary", "source"}:
            actions.append(
                "If distributing a derivative work, prepare source-code offer and reciprocal license compliance."
            )
        if use_case == "saas" and has_any_token(
            tokens, {"AGPL", "AGPL-3.0", "AGPL-3.0-ONLY", "AGPL-3.0-OR-LATER"}
        ):
            actions.append(
                "For AGPL in SaaS mode, prepare a user-facing path to access corresponding source."
            )
    if modified:
        actions.append(
            "Record your modifications and keep a change log for downstream compliance evidence."
        )
    return unique_keep_order(actions)


def build_restrictions(
    tokens: set[str],
    use_case: str,
    expressions: list[str],
    high_copyleft_alerts: list[str],
    spdx_evaluations: list[dict],
) -> list[str]:
    notes = []
    if not tokens:
        notes.append("No clear license grant detected; usage rights are uncertain.")
    if high_copyleft_alerts:
        notes.append(
            "Strong copyleft may conflict with closed-source distribution plans."
        )
    else:
        if any(item.get("exception_impacts") for item in spdx_evaluations if item.get("valid")):
            notes.append(
                "Copyleft obligations may be narrowed by SPDX exceptions, but verify exact exception scope."
            )
    if use_case == "saas" and has_any_token(
        tokens, {"AGPL", "AGPL-3.0", "AGPL-3.0-ONLY", "AGPL-3.0-OR-LATER"}
    ):
        notes.append(
            "AGPL can trigger obligations when users access modified software over a network."
        )
    if "APACHE-2.0" in tokens:
        notes.append("Apache-2.0 requires NOTICE handling and has patent-termination clauses.")
    if expressions:
        notes.append(
            "Composite SPDX expressions require selecting and documenting the applied license branch."
        )
    if any(item.get("branches_truncated") for item in spdx_evaluations if item.get("valid")):
        notes.append(
            f"Some SPDX expression evaluations were truncated at {MAX_SPDX_BRANCHES} branches."
        )
    if any(
        item.get("exception_compatibility_warnings")
        for item in spdx_evaluations
        if item.get("valid")
    ):
        notes.append(
            "Some SPDX WITH exceptions need manual compatibility review against specific GPL versions."
        )
    return unique_keep_order(notes)


def build_respect_and_giveback_actions(modified: bool) -> list[str]:
    actions = [
        "Keep original copyright and attribution visible where required.",
        "Contribute bug fixes or documentation improvements upstream when feasible.",
        "Open issues or PRs instead of carrying long-lived private patches when possible.",
        "Respect maintainer governance, contribution guidelines, and code of conduct.",
    ]
    if modified:
        actions.append(
            "Publish a clear changelog of your modifications when policy allows, to help downstream users."
        )
    actions.append(
        "Consider sponsoring or supporting key dependencies your product relies on."
    )
    return unique_keep_order(actions)


def read_text(path: Path, limit: int = 200_000) -> str:
    try:
        data = path.read_bytes()[:limit]
    except Exception:
        return ""
    return data.decode("utf-8", errors="replace")


def guess_license_from_text(text: str) -> str | None:
    for license_id, pattern in LICENSE_TEXT_PATTERNS:
        if pattern.search(text):
            return license_id
    return None


def scan_license_files(repo: Path) -> tuple[list[dict], list[str]]:
    findings: list[dict] = []
    detected = Counter()
    for path in repo.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(repo)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if not LICENSE_FILE_RE.match(path.name):
            continue
        text = read_text(path)
        spdx = SPDX_RE.search(text)
        license_id = spdx.group(1).strip() if spdx else guess_license_from_text(text)
        if license_id:
            detected[license_id] += 1
        findings.append(
            {
                "path": str(rel),
                "detected_license": license_id,
            }
        )
    return findings, [k for k, _ in detected.most_common()]


def parse_package_json(path: Path) -> dict:
    data = {}
    try:
        data = json.loads(read_text(path))
    except Exception:
        return {}
    result = {}
    if isinstance(data.get("license"), str):
        result["license"] = data["license"]
    elif isinstance(data.get("license"), dict):
        lic_type = data["license"].get("type")
        if isinstance(lic_type, str):
            result["license"] = lic_type
    if isinstance(data.get("licenses"), list):
        vals = []
        for item in data["licenses"]:
            if isinstance(item, str):
                vals.append(item)
            elif isinstance(item, dict) and isinstance(item.get("type"), str):
                vals.append(item["type"])
        if vals:
            result["licenses"] = vals
    return result


def parse_pyproject_toml(path: Path) -> dict:
    if tomllib is None:
        return {}
    try:
        data = tomllib.loads(read_text(path))
    except Exception:
        return {}
    project = data.get("project", {})
    license_value = project.get("license")
    if isinstance(license_value, str):
        return {"license": license_value}
    if isinstance(license_value, dict):
        if isinstance(license_value.get("text"), str):
            return {"license_text": license_value["text"]}
        if isinstance(license_value.get("file"), str):
            return {"license_file": license_value["file"]}
    return {}


def parse_cargo_toml(path: Path) -> dict:
    if tomllib is None:
        return {}
    try:
        data = tomllib.loads(read_text(path))
    except Exception:
        return {}
    package = data.get("package", {})
    out = {}
    if isinstance(package.get("license"), str):
        out["license"] = package["license"]
    if isinstance(package.get("license-file"), str):
        out["license_file"] = package["license-file"]
    return out


def parse_composer_json(path: Path) -> dict:
    try:
        data = json.loads(read_text(path))
    except Exception:
        return {}
    lic = data.get("license")
    if isinstance(lic, str):
        return {"license": lic}
    if isinstance(lic, list):
        vals = [x for x in lic if isinstance(x, str)]
        if vals:
            return {"licenses": vals}
    return {}


def parse_pom_xml(path: Path) -> dict:
    text = read_text(path)
    names = re.findall(r"<license>\s*<name>([^<]+)</name>", text, flags=re.IGNORECASE)
    urls = re.findall(r"<license>\s*<url>([^<]+)</url>", text, flags=re.IGNORECASE)
    out = {}
    if names:
        out["license_names"] = names
    if urls:
        out["license_urls"] = urls
    return out


def parse_package_lock(path: Path) -> dict:
    """Extract dependency license hints from package-lock.json."""
    try:
        data = json.loads(read_text(path))
    except Exception:
        return {}
    counter = Counter()
    packages = data.get("packages")
    if isinstance(packages, dict):
        for meta in packages.values():
            if not isinstance(meta, dict):
                continue
            lic = meta.get("license")
            if isinstance(lic, str) and lic.strip():
                counter[lic.strip()] += 1
    if not counter:
        deps = data.get("dependencies", {})
        if isinstance(deps, dict):
            for meta in deps.values():
                if not isinstance(meta, dict):
                    continue
                lic = meta.get("license")
                if isinstance(lic, str) and lic.strip():
                    counter[lic.strip()] += 1
    if not counter:
        return {}
    return {
        "dependency_license_counts": dict(counter.most_common(20)),
        "unique_dependency_licenses": len(counter),
    }


def extract_license_values_from_sbom_obj(
    obj: Any, in_license_context: bool = False
) -> list[str]:
    values: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            lower = key.lower()
            if lower in {"licensedeclared", "licenseconcluded", "licenseexpression"}:
                if isinstance(value, str) and value.strip():
                    values.append(value.strip())
                continue
            if lower in {"id", "name", "expression"} and in_license_context:
                if isinstance(value, str) and value.strip():
                    values.append(value.strip())
                elif isinstance(value, (dict, list)):
                    values.extend(
                        extract_license_values_from_sbom_obj(value, in_license_context)
                    )
                continue
            if lower == "license":
                if isinstance(value, str) and value.strip():
                    values.append(value.strip())
                elif isinstance(value, (dict, list)):
                    values.extend(extract_license_values_from_sbom_obj(value, True))
                continue
            if lower == "licenses":
                values.extend(extract_license_values_from_sbom_obj(value, True))
                continue
            if isinstance(value, (dict, list)):
                next_ctx = in_license_context or ("license" in lower)
                values.extend(extract_license_values_from_sbom_obj(value, next_ctx))
    elif isinstance(obj, list):
        for item in obj:
            values.extend(extract_license_values_from_sbom_obj(item, in_license_context))
    return values


def build_sbom_declared_result(
    values: list[str], bom_format: str | None, spec_version: str | None, parse_mode: str
) -> dict:
    result = {
        "license_values": values[:100],
        "unique_license_values": len(values),
        "parse_mode": parse_mode,
    }
    if isinstance(bom_format, str):
        result["bom_format"] = bom_format
    if isinstance(spec_version, str):
        result["spec_version"] = spec_version
    return result


def should_collect_streaming_string(prefix: str) -> bool:
    parts = [part.lower() for part in prefix.split(".") if part]
    if not parts:
        return False
    last = parts[-1]
    if last in {"licensedeclared", "licenseconcluded", "licenseexpression"}:
        return True
    has_license_context = any(
        part in {"license", "licenses", "licence", "licences"} for part in parts
    )
    if has_license_context and last in {"expression", "id", "name", "license", "value"}:
        return True
    if "licenseinfoinfiles" in parts and last in {"licenseid", "licenseinfoinfile"}:
        return True
    return False


def parse_sbom_json_streaming(path: Path) -> dict:
    if ijson is None:
        return {}
    values: list[str] = []
    bom_format = None
    spec_version = None
    try:
        with path.open("rb") as handle:
            for prefix, event, value in ijson.parse(handle):
                if event != "string":
                    continue
                if prefix == "bomFormat":
                    bom_format = value
                    continue
                if prefix == "specVersion":
                    spec_version = value
                    continue
                if should_collect_streaming_string(prefix):
                    if value.strip():
                        values.append(value.strip())
    except Exception:
        return {}
    values = unique_keep_order(values)
    if not values and not (isinstance(bom_format, str) and isinstance(spec_version, str)):
        return {}
    return build_sbom_declared_result(
        values,
        bom_format if isinstance(bom_format, str) else None,
        spec_version if isinstance(spec_version, str) else None,
        parse_mode="stream",
    )


def parse_sbom_json(path: Path) -> dict:
    """Parse SPDX/CycloneDX JSON structures for license values."""
    try:
        file_size = path.stat().st_size
    except OSError:
        file_size = 0

    if ijson is not None and file_size >= SBOM_STREAMING_THRESHOLD_BYTES:
        streamed = parse_sbom_json_streaming(path)
        if streamed:
            return streamed

    try:
        with path.open("rb") as handle:
            data = json.load(handle)
    except Exception:
        return {}

    values = unique_keep_order(extract_license_values_from_sbom_obj(data))
    bom_format = data.get("bomFormat")
    spec_version = data.get("specVersion")

    if not values and not (
        isinstance(bom_format, str) and isinstance(spec_version, str)
    ):
        return {}
    return build_sbom_declared_result(
        values,
        bom_format if isinstance(bom_format, str) else None,
        spec_version if isinstance(spec_version, str) else None,
        parse_mode="full",
    )


def collect_manifests(repo: Path) -> list[dict]:
    parsers = {
        "package.json": parse_package_json,
        "pyproject.toml": parse_pyproject_toml,
        "Cargo.toml": parse_cargo_toml,
        "composer.json": parse_composer_json,
        "pom.xml": parse_pom_xml,
        "package-lock.json": parse_package_lock,
    }
    findings = []
    for name, parser in parsers.items():
        for path in repo.rglob(name):
            if any(part in SKIP_DIRS for part in path.relative_to(repo).parts):
                continue
            parsed = parser(path)
            if parsed:
                findings.append(
                    {
                        "path": str(path.relative_to(repo)),
                        "type": name,
                        "declared": parsed,
                    }
                )

    for path in repo.rglob("*.json"):
        rel = path.relative_to(repo)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        name = path.name.lower()
        if (
            name not in SBOM_FILE_NAMES
            and not name.endswith(".spdx.json")
            and not name.endswith(".cdx.json")
            and "cyclonedx" not in name
        ):
            continue
        parsed = parse_sbom_json(path)
        if parsed:
            findings.append(
                {
                    "path": str(rel),
                    "type": "sbom.json",
                    "declared": parsed,
                }
            )
    return findings


def build_report(repo: Path, use_case: str, modified: bool) -> dict:
    license_files, detected_ids = scan_license_files(repo)
    manifests = collect_manifests(repo)
    spdx_expressions = collect_spdx_expressions(detected_ids, manifests)
    spdx_evaluations = collect_spdx_evaluations(detected_ids, manifests)
    primary = detected_ids[0] if detected_ids else None
    risk_level, risk_reasons, high_copyleft_alerts, tokens = assess_risk(
        detected_ids, manifests, use_case, spdx_expressions, spdx_evaluations
    )
    required_actions = build_required_actions(tokens, use_case, modified)
    restrictions = build_restrictions(
        tokens,
        use_case,
        spdx_expressions,
        high_copyleft_alerts,
        spdx_evaluations,
    )
    giveback_actions = build_respect_and_giveback_actions(modified)
    return {
        "repository": str(repo.resolve()),
        "use_case": use_case,
        "modified": modified,
        "primary_license_guess": primary,
        "detected_license_ids": detected_ids,
        "spdx_expressions": spdx_expressions,
        "spdx_expression_evaluations": spdx_evaluations,
        "license_files": license_files,
        "manifest_declarations": manifests,
        "risk_level": risk_level,
        "risk_reasons": risk_reasons,
        "high_copyleft_alerts": high_copyleft_alerts,
        "required_actions": required_actions,
        "restrictions_and_conflicts": restrictions,
        "respect_and_giveback_actions": giveback_actions,
        "limitations": [
            "Heuristic detection only; verify with actual legal text.",
            "Supports SPDX expression evaluation and CycloneDX 1.5+ JSON license fields; large SBOM streaming requires optional ijson.",
            "Dependency license data may be incomplete without full SBOM/SCA tooling.",
            "This output is technical compliance guidance, not legal advice.",
        ],
    }


def print_human(report: dict) -> None:
    print(f"Repository: {report['repository']}")
    print(f"Use case: {report['use_case']}")
    print(f"Code modified: {'yes' if report['modified'] else 'no'}")
    print(f"Primary license guess: {report['primary_license_guess'] or 'unknown'}")
    print(f"Risk level: {report['risk_level']}")

    ids = report["detected_license_ids"]
    print("Detected license IDs: " + (", ".join(ids) if ids else "none"))
    if report["spdx_expressions"]:
        print("SPDX expressions: " + ", ".join(report["spdx_expressions"]))
        print("SPDX expression evaluations:")
        for item in report["spdx_expression_evaluations"]:
            if not item.get("valid"):
                print(f"- {item['expression']}: parse error ({item.get('error', 'unknown')})")
                continue
            extras = []
            if item.get("exceptions"):
                extras.append(f"WITH exceptions: {', '.join(item['exceptions'])}")
            if item.get("applicable_exceptions"):
                extras.append(
                    f"applicable exceptions: {', '.join(item['applicable_exceptions'])}"
                )
            if item.get("branches_truncated"):
                extras.append(f"branches truncated at {MAX_SPDX_BRANCHES}")
            if item.get("exception_impacts"):
                extras.append("; ".join(item["exception_impacts"]))
            if item.get("exception_compatibility_warnings"):
                extras.append("; ".join(item["exception_compatibility_warnings"]))
            extra_text = ""
            if extras:
                extra_text = "; " + "; ".join(extras)
            print(
                "- "
                f"{item['expression']}: branches={item['branch_count']}, "
                f"risk={item['min_risk']}..{item['max_risk']}{extra_text}"
            )

    print("\nLicense files:")
    if report["license_files"]:
        for item in report["license_files"]:
            lic = item["detected_license"] or "unknown"
            print(f"- {item['path']} ({lic})")
    else:
        print("- none found")

    print("\nManifest declarations:")
    if report["manifest_declarations"]:
        for item in report["manifest_declarations"]:
            details = json.dumps(item["declared"], ensure_ascii=False, sort_keys=True)
            print(f"- {item['path']} [{item['type']}]: {details}")
    else:
        print("- none found")

    print("\nRisk reasons:")
    for line in report["risk_reasons"]:
        print(f"- {line}")

    print("\nHigh-copyleft alerts:")
    if report["high_copyleft_alerts"]:
        for item in report["high_copyleft_alerts"]:
            print(f"- {item}")
    else:
        print("- none")

    print("\nRequired actions before using code:")
    for item in report["required_actions"]:
        print(f"- {item}")

    print("\nRestrictions and conflict notes:")
    if report["restrictions_and_conflicts"]:
        for item in report["restrictions_and_conflicts"]:
            print(f"- {item}")
    else:
        print("- none")

    print("\nRespect and give-back suggestions:")
    for item in report["respect_and_giveback_actions"]:
        print(f"- {item}")

    print("\nLimitations:")
    for line in report["limitations"]:
        print(f"- {line}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan repository files and manifests for license evidence."
    )
    parser.add_argument("repo", help="Path to repository root")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument(
        "--use-case",
        choices=USE_CASES,
        default="unknown",
        help="Planned usage mode: unknown/internal/saas/binary/source",
    )
    parser.add_argument(
        "--modified",
        action="store_true",
        help="Indicate you modified upstream code and need change-tracking obligations.",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    repo = Path(args.repo).expanduser().resolve()
    if not repo.exists() or not repo.is_dir():
        print(f"error: invalid repository path: {repo}", file=sys.stderr)
        return 2
    report = build_report(repo, use_case=args.use_case, modified=args.modified)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
