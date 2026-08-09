#!/usr/bin/env python3
"""Redact addresses and common credential-shaped values from stdin."""

import re
import sys


# PATTERNS covers the identity and credential shapes emitted by Pi discovery.
# Replacements stay descriptive so a reviewer knows what kind of evidence was
# removed without learning the value itself.
PATTERNS = [
    (re.compile(r"(?i)\b(?:machine|boot)[ -]?id\s*[:=]\s*[0-9a-f]{16,}\b"), "[REDACTED_MACHINE_ID]"),
    (re.compile(r"(?i)\b(?:PARTUUID|UUID)=?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b"), "[REDACTED_UUID]"),
    (re.compile(r"(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b"), "[REDACTED_UUID]"),
    (re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?"), "[REDACTED_IPv4]"),
    (re.compile(r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:/\d{1,3})?"), "[REDACTED_IPv6]"),
    (re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])"), "[REDACTED_MAC]"),
    (re.compile(r"AGE-SECRET-KEY-1[A-Z0-9]+"), "[REDACTED_AGE_IDENTITY]"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{12,})\b"), "[REDACTED_TOKEN]"),
    (re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s]+"), r"\1[REDACTED]"),
]


# Stream line by line so even a large ruleset is never retained as a second
# unredacted in-memory report by this helper.
for line in sys.stdin:
    for pattern, replacement in PATTERNS:
        line = pattern.sub(replacement, line)
    sys.stdout.write(line)
