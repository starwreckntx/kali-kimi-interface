#!/usr/bin/env python3
"""
Positive (allowlist) input validation for the KKI governance layer.

The base adapter (`kali_tools.KaliToolAdapter`) uses a *blacklist* of dangerous
characters. This module adds the stronger, governance-grade *allowlist* gate that the
IRP hardening spec (Task 3.2 / 3.4) requires: a value is rejected unless it positively
matches an approved shape. The blacklist remains in place underneath as defense in depth.

Usage:
    from governance.validation import validate_target, validate_flags, PolicyViolation

    validate_target("192.168.1.0/24")        # -> "192.168.1.0/24"
    validate_target("8.8.8.8; rm -rf /")     # -> raises PolicyViolation
    validate_flags("nmap", "-sS -p 1-100")   # -> ["-sS", "-p", "1-100"]
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import List, Optional


class PolicyViolation(Exception):
    """Raised when an input fails positive (allowlist) validation."""


# RFC 1123 hostname / FQDN: labels of [A-Za-z0-9-], not starting/ending with '-',
# total length <= 253. ASCII-only by construction, which is itself a homoglyph defense:
# any non-ASCII confusable simply fails this pattern.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

# Value tokens that may follow a flag (e.g. the "1-100" after "-p"). Deliberately narrow.
_VALUE_TOKEN_RE = re.compile(r"^[A-Za-z0-9._,:/=+-]{1,256}$")

# Per-tool allowlist of bare flag tokens. Only the wrapped/known tools are listed; any
# tool not present here rejects *all* free-text flags (fail closed). Extend deliberately.
SAFE_FLAGS = {
    "nmap": frozenset({
        "-sS", "-sT", "-sU", "-sV", "-sC", "-O", "-A", "-Pn", "-n", "-F",
        "-p", "--top-ports", "--osscan-limit", "-T0", "-T1", "-T2", "-T3", "-T4",
        "--open", "-v", "-vv", "--script", "vuln",
    }),
    "masscan": frozenset({"-p", "--rate", "--ports", "--top-ports"}),
    "gobuster": frozenset({"dir", "dns", "fuzz", "-w", "-t", "-x", "-u", "-q", "-k"}),
    "dirb": frozenset({"-r", "-S", "-w", "-z"}),
    "nikto": frozenset({"-h", "-p", "-ssl", "-Tuning"}),
    "hydra": frozenset({"-l", "-L", "-P", "-s", "-t", "-f", "-V"}),
    "sqlmap": frozenset({"--batch", "--level", "--risk", "--dbs", "--tables", "--crawl"}),
}

# Maximum reasonable target length; rejects absurd inputs early.
_MAX_TARGET_LEN = 255


def normalize(value: str) -> str:
    """NFKC-normalize and reject null bytes / control characters.

    NFKC folds compatibility characters so visually-equivalent variants collapse to a
    canonical form before any allowlist regex is applied. Null bytes and C0/C1 control
    characters are rejected outright.
    """
    if not isinstance(value, str):
        raise PolicyViolation("value must be a string")
    if "\x00" in value:
        raise PolicyViolation("null byte in input")
    norm = unicodedata.normalize("NFKC", value).strip()
    for ch in norm:
        if unicodedata.category(ch).startswith("C"):  # Cc, Cf, Cs, Co, Cn
            raise PolicyViolation(f"control/format character not allowed: {ch!r}")
    return norm


def validate_target(value: str, scope: Optional[List[str]] = None) -> str:
    """Validate an IP / CIDR / hostname target against a positive allowlist.

    Accepts: IPv4/IPv6 address, IPv4/IPv6 CIDR network, or an RFC 1123 hostname/FQDN.
    If ``scope`` is given (a list of CIDR strings), an IP/CIDR target must fall within
    one of them (the NETWORK_SCOPE_ALLOWLIST gate). Hostnames bypass scope here because
    they are not resolved at validation time; resolution-time scope is a roadmap item.

    Returns the normalized target, or raises PolicyViolation.
    """
    norm = normalize(value)
    if not norm:
        raise PolicyViolation("empty target")
    if len(norm) > _MAX_TARGET_LEN:
        raise PolicyViolation("target too long")

    ip_obj = None
    # Try IP address, then CIDR network, then hostname — first positive match wins.
    try:
        ip_obj = ipaddress.ip_address(norm)
    except ValueError:
        try:
            ip_obj = ipaddress.ip_network(norm, strict=False)
        except ValueError:
            ip_obj = None

    if ip_obj is None:
        if not _HOSTNAME_RE.match(norm):
            raise PolicyViolation(f"target is neither a valid IP/CIDR nor hostname: {norm!r}")
        return norm

    if scope:
        if not _in_scope(norm, scope):
            raise PolicyViolation(f"target {norm!r} is outside the network scope allowlist")
    return norm


def _in_scope(target: str, scope: List[str]) -> bool:
    try:
        t = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    for entry in scope:
        try:
            allowed = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if t.version == allowed.version and t.subnet_of(allowed):
            return True
    return False


def validate_url(value: str, scope: Optional[List[str]] = None) -> str:
    """Validate an http(s) URL whose host passes the target allowlist.

    Path/query are restricted to a conservative character set. Used by URL-target tools
    (sqlmap, gobuster, nikto).
    """
    norm = normalize(value)
    m = re.match(
        r"^(https?)://"
        r"([A-Za-z0-9.\-]+|\[[0-9A-Fa-f:]+\])"   # host or [ipv6]
        r"(:\d{1,5})?"                              # optional port
        r"(/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?$",  # optional safe path
        norm,
    )
    if not m:
        raise PolicyViolation(f"not a valid http(s) URL: {norm!r}")
    host = m.group(2).strip("[]")
    # Reuse target validation for the host portion (IP or hostname, scope-checked).
    validate_target(host, scope=scope)
    return norm


def validate_flags(tool: str, flags: str) -> List[str]:
    """Validate free-text flags against the per-tool SAFE_FLAGS allowlist.

    Splits on whitespace. Each token that looks like a flag (starts with '-') must be in
    the tool's allowlist; each non-flag token (a value) must match the narrow value
    pattern. Tools without a SAFE_FLAGS entry reject all flags (fail closed).

    Returns the validated token list, or raises PolicyViolation.
    """
    norm = normalize(flags) if flags else ""
    if not norm:
        return []
    allowed = SAFE_FLAGS.get(tool)
    if allowed is None:
        raise PolicyViolation(f"tool {tool!r} has no SAFE_FLAGS allowlist; free-text flags denied")

    tokens: List[str] = []
    for tok in norm.split():
        if tok.startswith("-"):
            if tok not in allowed:
                raise PolicyViolation(f"flag {tok!r} not in SAFE_FLAGS[{tool}]")
        else:
            if not _VALUE_TOKEN_RE.match(tok):
                raise PolicyViolation(f"flag value {tok!r} contains disallowed characters")
        tokens.append(tok)
    return tokens
