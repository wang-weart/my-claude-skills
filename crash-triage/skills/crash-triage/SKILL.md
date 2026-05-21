---
name: crash-triage
description: >-
  Triages and classifies program crashes by bug class and exploitability. Use
  when reviewing a crashing input, an AddressSanitizer report, a GDB/LLDB
  backtrace, or a core dump; when deciding whether a crash is a real
  memory-safety bug worth reporting or a benign input rejection; or when
  prioritizing a batch of fuzzer-found crashes. Reproduces a PoC under
  sanitizers/debugger and emits a severity-ranked verdict.
---

# Crash Triage

Turn a crash into a decision. Given a crashing input plus a target binary — or a
trace you already have — classify the crash by bug class, judge its severity and
exploitability, point at the responsible source frame, and recommend one action.

This is the post-crash counterpart to static (angr) and dynamic (Frida) analysis:
it answers "is this crash a real, reportable bug, and how bad is it?"

## When to Use

- A fuzzer (AFL++, libFuzzer, honggfuzz) produced crashing inputs to review
- You have an ASAN/UBSan report, a GDB/LLDB backtrace, or a core dump to interpret
- Deciding whether a crash is a genuine memory-safety bug or working-as-intended
  input rejection (an assert/abort on malformed data)
- Prioritizing a pile of crashes — which to file upstream first, which to ignore
- Distinguishing a write primitive from a read, a null deref from controlled corruption

## When NOT to Use

- You need to *find* bugs in a binary without source → use angr-analyzer
- You need live runtime hooking/tracing of a process → use frida-instrument
- The crash is in managed code (Python/JS/Java) with a native stack trace already
  pointing at the line — read it directly
- You want to set up the fuzzer itself — that's harness/rig work, out of scope here

## Quick Reference

| Task | Command |
|------|---------|
| Reproduce + classify (file arg) | `{baseDir}/scripts/crash-triage.sh -b ./bin-asan -i poc -x "@@"` |
| Reproduce + classify (stdin) | `{baseDir}/scripts/crash-triage.sh -b ./bin-asan -i poc -m stdin` |
| Classify an existing trace | `{baseDir}/scripts/crash-triage.sh -t asan.log --label <id>` |
| Classify from stdin | `cat trace.txt \| {baseDir}/scripts/crash-triage.sh -t -` |
| JSON verdict only | `{baseDir}/scripts/crash-triage.sh -t asan.log --json` |
| Triage a directory | `for f in crashes/*; do {baseDir}/scripts/crash-triage.sh -b ./bin -i "$f" --label "$(basename "$f")"; done` |

## Prerequisites

- **python3** (stdlib only — no pip install needed for classification)
- For reproduction: the **target binary**, ideally an **ASAN+UBSan build**
  (`-fsanitize=address,undefined -g`), which gives the most precise verdict
- Optional: **gdb** or **lldb** for a backtrace fallback when there's no ASAN report

## Classification Taxonomy

The classifier maps a trace to one class. Severity and action follow from it:

| Class | Signature | Severity | Default action |
|-------|-----------|----------|----------------|
| **memory-bug** | ASAN: `heap/stack/global-buffer-overflow`, `heap-use-after-free`, `double-free`, etc. | HIGH | file-upstream |
| **segv** | `SIGSEGV` / `EXC_BAD_ACCESS` / ASAN `SEGV`; non-null addr | HIGH | file-upstream |
| **segv** (null) | Faulting address < 0x1000 (null/small-offset deref) | MED | investigate |
| **ubsan** | `UndefinedBehaviorSanitizer` / `runtime error:` | MED–HIGH | investigate |
| **assertion** | `SIGABRT`, `__assert_fail`, `Assertion … failed`, `abort` | LOW | ignore-intended |
| **trap** | `SIGTRAP` / `EXC_BREAKPOINT` / `__builtin_trap` / `SIGILL` | MED | investigate |
| **arith** | `SIGFPE` / division by zero | MED | investigate |
| **leak** | `LeakSanitizer` / detected memory leaks | LOW | investigate |
| **hang** | timeout / no crash signal | LOW | investigate |
| **no-frames** | no usable frames or signal | UNKNOWN | investigate (re-capture) |

**Severity nuance the verdict applies for you:**
- A **write** overflow outranks a **read** (write primitives are more exploitable).
- A **null deref** (addr near 0) is real but usually lower impact than corruption at
  a controlled address — confirm whether the pointer/offset is attacker-influenced.
- An **assertion/abort** is usually the target correctly rejecting bad input. Escalate
  only when the assert guards an invariant the input shouldn't be able to violate.
- A **trap** is often a compiler-inserted check (checked arithmetic / bounds guard),
  not raw corruption — read the top-frame source to tell which.

## Workflow

1. **Scope.** One crash or many? For a batch, loop the directory (see Quick
   Reference) and collect verdicts before reasoning about priority.

2. **Get a trace.** Either point the tool at the binary + PoC to reproduce it, or
   feed a trace you already have with `-t`. Prefer an **ASAN build** — it converts
   a vague SIGSEGV into a precise "heap-buffer-overflow WRITE of size 4".

3. **Read the verdict.** The tool prints class / severity / top frame / action /
   reasoning. The top frame is the first *application* frame (sanitizer and libc
   interceptor frames are skipped).

4. **Confirm at the source.** Open the top-frame `file:line` and read the few lines
   around it. This is what separates "file-upstream" from "ignore-intended":
   - Is the faulting access bounded by something derived from input?
   - Is this the target's own validation rejecting malformed input (→ intended)?
   - For a trap: is it a `__builtin_trap` from a safe-math/bounds check (→ likely WAI)?

5. **De-duplicate.** Two crashes with the same top frame are probably one bug.
   Group them and report the cluster once.

6. **Output.** For a batch, produce one markdown table, severity-descending:
   `id | class | severity | top_frame | action | rationale`. Follow with a short
   paragraph: counts by class and what you'd do next.

## Reproducing with the right build

The single biggest lever on verdict quality is building the target with sanitizers:

```bash
# C/C++: ASAN + UBSan with frame pointers and line info
CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
CXXFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
  <your normal configure/make>
```

Then triage against that binary. Without it, you fall back to a debugger backtrace,
which still classifies the signal but can't tell a heap overflow read from a write.

## Tone

Be decisive. "This is a heap-buffer-overflow WRITE in `Parser::readToken` at
parser.c:996 — file upstream" beats "this could potentially be a memory issue that
may warrant further review." When something is genuinely ambiguous, say so and pick
the next step rather than hedging forever.

## Common Mistakes

- **Trusting a bare SIGSEGV.** A debugger-only SEGV can't distinguish null deref from
  controlled corruption. Rebuild with ASAN before declaring severity.
- **Filing every assert as a bug.** Most asserts on fuzzed input are the parser doing
  its job. Check whether the input was *supposed* to be rejectable.
- **Reporting duplicates.** Cluster by top frame first; one root cause can spray
  dozens of distinct inputs.
- **Triaging non-reproducing crashes silently.** If the PoC doesn't reproduce on a
  fresh build, say so — don't classify a stale `trace.txt` as if it were live.

## Don't

- Don't try to *fix* the bug from this skill — classifying and (optionally) drafting
  an upstream report is the end state.
- Don't modify the crash inputs or overwrite a captured trace without saying so.
