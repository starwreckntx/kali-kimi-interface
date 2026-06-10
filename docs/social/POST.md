# Social post copy — KKI IRP Governance Stack

Ready-to-paste copy for announcing the governance layer. All claims match the repo and the
live-hardware verification. Pick a platform, paste, attach the article link.

---

## Short description (one-liner / repo blurb / link preview)

A stdlib-only governance layer that sits between an AI agent and Kali Linux: no dangerous
tool runs without input validation, per-invocation binary attestation, an explicit human
`APPROVE`, and a tamper-evident audit trail. Default-deny, verified on live hardware.

---

## LinkedIn post

I connected an AI agent to a real penetration-testing toolkit — then I built the cage before
I opened the door. Most builders show what their agent can do. I want to show what mine was
prevented from doing.

When you wire a language model to live tools, one generated JSON object becomes `nmap` or
`masscan` running against a real network. The distance between "the model decided to" and "it
happened" is a single function call. I work around high-consequence physical processes, so I
treated the agent the way industrial systems treat hazardous machinery: interlocks, lockout,
and a logbook.

So I built the KKI IRP Governance Stack — and the whole thing runs on the Python standard
library. No exotic dependencies. One rule everything serves:

→ No dangerous tool runs without passing validation, verifying the binary against an approved
SHA-256 fingerprint, getting an explicit human APPROVE + nonce, and leaving an append-only,
tamper-evident record. Default-deny: no answer, wrong answer, or no operator all mean NO.

And to head off the obvious critique — this isn't a permission popup. Consent is one layer in
a chain (validate → attest → rate-limit → approve → audit) where any single link can halt the
run on its own.

The part I'm proudest of: on the first live run on Kali hardware, a test "failed" — the
governed scan was denied on consent timeout, so it never ran. That wasn't a bug. That was the
default-deny holding under real conditions. Exactly what you want.

Then I attacked my own cage. An adversarial review of the stack turned up two gaps — binary
attestation wasn't enforced for tools that write to disk, and a legacy menu still built a
shell string — and I closed both before shipping. Finding your own holes is the job.

Verified on Kali 6.18.3: attestation matches sha256sum /usr/bin/nmap, rate/interface limits
reject bad calls before a process spawns, consent fails closed, and the audit chain catches a
single-byte tamper at the exact entry. 107 automated tests, 0 failures.

Stated plainly because security earns trust by being honest about its edges: audit signing is
session-local today (asymmetric keys are the upgrade path), the hash baseline is
trust-on-first-use, no kernel sandbox yet, multi-agent is roadmap.

Understand every layer. Control every variable. Build the failsafe yourself.

Open source, for authorized testing and education. 🛰️

#AISecurity #OffensiveSecurity #AIagents #Cybersecurity #KaliLinux #AIgovernance

---

## X / Twitter thread

**1/**
I gave an AI a hacking toolkit — then built the cage first.

Wire a model to real tools and one JSON object becomes nmap/masscan hitting a live network.
The fix isn't a smarter model. It's an honest, default-deny boundary around it.

Here's how it works 🧵

**2/**
One rule everything serves:

No dangerous tool runs without →
✅ input validation
✅ per-invocation binary SHA-256 attestation
✅ explicit human APPROVE + nonce
✅ tamper-evident audit entry

No answer / wrong answer / no operator = DENY. Always.

**3/**
It checks the binary EVERY time it runs.
realpath + trusted-dir containment + fresh SHA-256.
PATH hijack, symlink, swapped binary → fingerprint changes → execution stops.

And the operator approves the exact hash that will run. No time-of-check/time-of-use gap.

**4/**
The memory can't be quietly edited.
Append-only, hash-chained, HMAC-tagged log.
Flip one byte later → verification names the exact entry that was touched.

**5/**
Proudest moment: first live run, a test "failed" — the governed scan was DENIED on consent
timeout, so it never ran.

Not a bug. That's default-deny holding under real conditions. When in doubt, the machine does
nothing.

**6/**
Verified on live Kali 6.18.3:
• attestation == sha256sum /usr/bin/nmap
• rate/interface caps reject before a process spawns
• consent fails closed
• audit catches a 1-byte tamper
107 tests, 0 failures.

And the whole thing is stdlib-only.

**7/**
Stated plainly (security earns trust by being honest):
• audit signing is session-local — asymmetric keys are the upgrade path
• no kernel sandbox yet
• multi-agent is roadmap

Understand every layer. Control every variable. Build the failsafe yourself.

Open source. 🛰️

---

## GitHub Release / PR note (short)

**KKI IRP Governance Stack — governed autonomy for offensive tooling**

A stdlib-only consent, attestation, and audit layer between AI agents and Kali Linux.
Enforces a hard invariant — no `danger-full-access` tool executes without validation,
per-invocation SHA-256 attestation, an operator `APPROVE <nonce>`, and an append-only
tamper-evident audit entry. Default-deny throughout.

Verified on Kali 6.18.3: 5/5 live-hardware acceptance checks pass (incl. privileged
syn-scan), 107 automated tests, 0 failures. See `docs/WHITEPAPER.md` and
`docs/IRP_GOVERNANCE.md`.
