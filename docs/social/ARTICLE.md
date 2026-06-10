# I gave an AI a hacking toolkit — then I built the cage first

*How a stdlib-only governance layer keeps an autonomous agent from running `nmap` (or worse) without a human saying yes.*

**By Joseph (Starwreck) Byram — Hue & Logic Labs**

---

There's a moment when you wire a language model up to real tools and realize what you've
actually done. It's not abstract anymore. The model writes a little JSON object, and on the
other side of that object is `masscan` blasting a network at a hundred thousand packets a
second, or `sqlmap` chewing on a login form. The distance between "the model decided to" and
"it happened" is one function call.

I work around high-consequence physical processes. The rule there is simple and unforgiving:
understand every layer, control every variable, and build the failsafe yourself before you
ever pour. You don't trust that nothing will go wrong. You design so that when something
does, it fails *toward* safety. I wanted the same discipline for an AI operating offensive
security tools.

So before I let the agent loose, I built the cage. It's called the **Kali Kimi Interface
(KKI) IRP Governance Stack**, and the whole thing runs on the Python standard library — no
exotic dependencies, no daemon, no kernel magic.

## The one rule everything else serves

> No dangerous tool runs without passing validation, proving the binary is what it claims to
> be, getting an explicit human `APPROVE`, and leaving a tamper-evident record.

Everything in the system exists to make that sentence true. Here's how it breaks down.

**It checks the input before it trusts it.** Targets have to look like real IPs or hostnames
— anything with shell metacharacters, Unicode look-alikes, or null bytes gets rejected up
front. Commands are always run as argument arrays, never as a shell string. Injection
doesn't get a foothold.

**It checks the *binary* before it runs it.** Every single time a tool is about to execute,
the system resolves the real path, confirms it lives in a trusted system directory, and takes
a fresh SHA-256 fingerprint. Swap the binary, hijack the PATH, plant a symlink — the
fingerprint changes and execution stops.

**It asks a human — and means it.** For anything classified `danger-full-access`, the agent
hits a consent gate. The operator sees the tool, the target, and the binary's hash, plus a
one-time nonce, and has to type `APPROVE <nonce>` exactly. No answer? Wrong answer? Nobody
there? All of those mean **no**. The default is deny. Always.

**It remembers, and you can't quietly edit the memory.** Every decision and execution lands
in an append-only, hash-chained, HMAC-tagged log. Flip a single byte in a saved log later and
a verification pass will tell you exactly which entry was touched.

## The part I'm proudest of: it failed correctly

When I ran the acceptance tests on real Kali hardware the first time, one test "failed." The
governed `nmap` run came back denied — *consent timeout, operator did not authorize* — so the
scan never happened.

That wasn't a bug. That was the system doing its job. My test had a flawed approval stub, so
no valid `APPROVE` ever reached the gate, and the gate did the only correct thing: it refused
to run a dangerous tool. The default-deny held under real conditions. I fixed the stub, and
with a proper approval the scan ran, the audit chain verified clean, and a deliberate
tamper in the log got caught at the exact entry.

That's the whole philosophy in one screenshot: when in doubt, the machine does nothing.

## What's proven, and what I won't pretend

On live Kali (6.18.3), all five acceptance checks pass — attestation matches
`sha256sum /usr/bin/nmap`, the rate ceiling and interface allowlist reject bad calls before a
process even spawns, consent fails closed, and the audit chain catches tampering. The full
automated suite is 106 passing tests.

And the limits, stated plainly because pretending otherwise is how people get hurt: the audit
signing is session-local today (asymmetric keys are the upgrade path), there's no kernel
sandbox yet, and multi-agent coordination is still on the roadmap. Real security work earns
trust by being honest about its edges.

## Why this matters beyond my lab

We're going to keep handing capabilities to autonomous systems. The question isn't whether
the model is smart enough — it's whether the boundary around it is honest, default-deny, and
auditable. You don't need a research budget or a vendor's black box to build that. A few
thousand lines of plain Python can keep a human sovereign over the machine and leave a record
nobody can erase.

Understand every layer. Control every variable. Build the failsafe yourself.

---

*KKI is open source, for authorized security testing and education. Architecture and the full
verification suite are in the repository under `docs/IRP_GOVERNANCE.md`, `docs/WHITEPAPER.md`,
and `tests/test_kali_integration.py`.*
