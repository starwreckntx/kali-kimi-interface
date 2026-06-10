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
understand every layer, identify and constrain the variables that can hurt you, and build the
failsafe yourself before you ever pour. You don't trust that nothing will go wrong. You design
so that when something does, it fails *toward* safety. So I treated the AI agent the way
industrial systems treat hazardous machinery — interlocks, lockout, and a logbook — not the
way software usually treats a new feature.

So before I let the agent loose, I built the cage. It's called the **Kali Kimi Interface
(KKI) IRP Governance Stack**, and the whole thing runs on the Python standard library — no
exotic dependencies, no daemon, no kernel magic.

Most builders show what their agent *can* do. I want to show what mine was *prevented* from
doing.

## The one rule everything else serves

> No dangerous tool runs without passing validation, verifying the binary matches an approved
> fingerprint, getting an explicit human `APPROVE`, and leaving a tamper-evident record.

Everything in the system exists to make that sentence true. Here's how it breaks down.

**It checks the input before it trusts it.** Targets have to look like real IPs or hostnames
— anything with shell metacharacters, Unicode look-alikes, or null bytes gets rejected up
front. Commands are always run as argument arrays, never as a shell string. Injection
doesn't get a foothold.

**It checks the *binary* before it runs it.** Every single time a tool is about to execute,
the system resolves the real path, confirms it lives in a trusted system directory, and
verifies a fresh SHA-256 against an approved fingerprint. Swap the binary, hijack the PATH,
plant a symlink — the fingerprint diverges and execution stops. (To be precise: this verifies
the binary matches the fingerprint captured at startup; it isn't a claim about supply-chain
provenance.)

**It asks a human — and means it.** For anything classified `danger-full-access`, the agent
hits a consent gate. The operator sees the tool, the target, and the binary's hash, plus a
one-time nonce, and has to type `APPROVE <nonce>` exactly. No answer? Wrong answer? Nobody
there? All of those mean **no**. The default is deny. Always.

**It keeps a tamper-evident memory.** Every decision and execution lands in an append-only,
hash-chained, HMAC-tagged log. Flip a single byte in a saved log later and a verification pass
tells you exactly which entry was touched. (Hash-chaining doesn't stop a privileged actor from
deleting the file — it makes alteration *evident*, which is the property that matters in an
audit.)

And here's the part critics miss: none of these four is *the* control. The control is the
**chain** — validate → attest → rate-limit → approve → audit — and any single link can halt
the run on its own. The human `APPROVE` is one gate among several, not the whole model. This
isn't a glorified permission popup; consent is a layer, not the architecture.

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

## Then I audited the cage I built

Building the failsafe isn't the end — you have to attack it. So I ran an adversarial review of
my own stack before it shipped, and I found two gaps. First, binary attestation was being
hard-enforced only for the most dangerous tools; tools that *write* to disk could slip through
on an unverified binary. Second, the legacy interactive menu still built a shell command
string — a classic injection seam, even if only a human could reach it. I closed both: state-
mutating tools now require a verified binary too, and the menu runs argument arrays with no
shell. I also caught myself overstating one guarantee in my own docs and corrected it. Finding
your own holes and writing them down is the job.

## What's proven, and what I won't pretend

On live Kali (6.18.3), all five acceptance checks pass — attestation matches
`sha256sum /usr/bin/nmap`, the rate ceiling and interface allowlist reject bad calls before a
process even spawns, consent fails closed, and the audit chain catches tampering. The full
automated suite is 107 passing tests.

And the limits, stated plainly because pretending otherwise is how people get hurt: the audit
signing is session-local today (asymmetric keys are the upgrade path), the hash baseline is
trust-on-first-use, there's no kernel sandbox yet, and multi-agent coordination is still on
the roadmap. Real security work earns trust by being honest about its edges.

## Why this matters beyond my lab

We're going to keep handing capabilities to autonomous systems. The question isn't whether
the model is smart enough — it's whether the boundary around it is honest, default-deny, and
auditable. You don't need a research budget or a vendor's black box to build that. A few
thousand lines of plain Python can keep a human sovereign over the machine and leave a record
that can't be quietly altered without it showing.

Understand every layer. Constrain the variables that can hurt you. Build the failsafe yourself.

---

*KKI is open source, for authorized security testing and education. Architecture and the full
verification suite are in the repository under `docs/IRP_GOVERNANCE.md`, `docs/WHITEPAPER.md`,
and `tests/test_kali_integration.py`.*
