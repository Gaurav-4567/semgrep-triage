---
layout: page
title: "Designing an LLM-powered SAST triage tool: open source, local-first, with anti-hallucination guardrails"
---
I shipped v0.1 of [sg-triage](https://github.com/Gaurav-4567/semgrep-triage), an open-source CLI that uses Claude to triage Semgrep findings. While preparing this writeup I went looking for prior art on r/netsec and discovered Semgrep themselves built this category in 2023 and have continued investing in it ([Semgrep Assistant](https://semgrep.dev/blog/2023/gpt4-and-semgrep-detailed/), now Semgrep Multimodal).

That's worth addressing upfront: this isn't a novel idea. The category exists and has a commercial incumbent. What I'd argue is uncommon is a few specific design choices that make sense if you assume LLMs hallucinate and you want to ship something a skeptical security engineer would actually trust.

This post walks through those design choices.

## A real verdict, before anything else

Semgrep flagged this code in Flask's CLI module (`src/flask/cli.py:1023`):

```python
eval(compile(f.read(), startup, "exec"), ctx)
```

Rule: `python.lang.security.audit.eval-detected.eval-detected`. CWE-95: eval injection. If you saw this in a 200-finding report, what would you do? Mark it as a bug: you waste time. Wave it through: you might miss real bugs. Skip it: you're just adding to the unreviewed pile.

Here's what sg-triage produced (in ~10 seconds, for ~$0.02 in API costs):

> **Verdict: false_positive (high confidence)**
>
> The eval() call is executing code from the PYTHONSTARTUP environment variable, which is a standard Python interpreter feature. PYTHONSTARTUP is set by the user running the Python process, not by external attackers. The "attacker" would need to control the environment variable of the process they're already running, which means they already have code execution capability.
>
> **Evidence quotes** (verified to appear verbatim in source):
>
> ```
> startup = os.environ.get("PYTHONSTARTUP")
> if startup and os.path.isfile(startup):
> eval(compile(f.read(), startup, "exec"), ctx)
> ```

That verdict reads like a senior security engineer's assessment after spending 5-10 minutes with the code. The quotes are verbatim, programmatically validated. The reasoning ties directly to visible code, not vibes.

When I ran sg-triage on Django, I got 28 verdicts of this quality across 50 Python findings, for $0.91 total. 28 findings I no longer needed to look at. The other 22 went to "needs human review" with specific notes about what context the LLM couldn't see.

## What this is, and what it isn't

sg-triage does one job: take Semgrep JSON, send each finding to Claude with surrounding code context, return a verdict in one of three buckets: real bug, false positive, or needs human review. MIT-licensed, runs locally, you bring your own Anthropic API key.

It is not magic. It is not autofix. It is not a replacement for security review. Every verdict is a senior-engineer-quality first-pass triage that you read and accept or reject. The goal is to reduce the volume that needs human attention, not to eliminate human attention.

Three constraints shaped every design decision:

1. **LLMs hallucinate.** Anything we can verify programmatically, we should.
2. **False negatives destroy trust.** Wrong "this is a real bug" is recoverable. Wrong "this is fine, ignore it" can ship vulnerabilities.
3. **Skeptical engineers won't use a black box.** Every verdict needs to expose its reasoning and its evidence.

The rest of this post is how those constraints turned into specific code.

## Design choice 1: Three verdict buckets, not two

The obvious schema for a triage tool is binary: this finding is real, or it's a false positive. Two buckets, clean output, easy to act on.

I use three: `false_positive`, `likely_true_positive`, `needs_human_review`. The third bucket is the most important one in the schema, and it's the one a binary system can't have.

The reasoning is asymmetry of errors. When sg-triage gets a verdict wrong, there are two failure modes:

- **Wrong "likely_true_positive":** the tool flags something as a real bug when it isn't. The human looks at it, says "no, that's fine," and ignores it. Cost: the human's time.
- **Wrong "false_positive":** the tool says a real vulnerability is fine. The human trusts it, doesn't look further. Cost: a real vulnerability ships to production.

These are not the same kind of wrong. The second one ends careers and breaches companies. The first one is annoying. Any triage tool that treats them symmetrically is calibrated wrong for security work.

Three buckets encode the asymmetry directly. The LLM is told, in the system prompt, that uncertainty must default to `needs_human_review`. The prompt is explicit about what counts as enough evidence for each verdict:

- `false_positive` requires verbatim quotes from visible code that demonstrate why the finding doesn't apply. The verifier (covered later) enforces this.
- `likely_true_positive` requires identifiable user input flowing to a dangerous sink, traceable in the visible code.
- `needs_human_review` is the safe default when the LLM can see something suspicious but can't trace the data flow with the context it has.

In practice this means the tool routes findings to humans more often than a confident binary system would. That's the point. A false positive that gets routed to a human is cheap. A real bug marked as false positive is catastrophic.

The Django run is illustrative. Out of 50 Python findings, 28 came back as `false_positive` (high confidence), 0 as `likely_true_positive`, and 22 as `needs_human_review`. A binary system would have been forced to label those 22 as either FP or TP. Either choice would have been wrong some percentage of the time, and given that any wrong "FP" call is the catastrophic kind, the safe choice would have been to label all 22 as TP, at which point the tool has done nothing useful for those findings.

Three buckets is a small schema decision. It changes everything about the prompt, the verifier, and the trust model.

## Design choice 2: Evidence quotes as a hard requirement for false-positive verdicts

When the LLM returns a `false_positive` verdict, it must include verbatim quotes from the code that justify the verdict. Empty `evidence_quotes` array on a `false_positive` is a schema violation: the Pydantic model rejects it, and the orchestrator routes the finding to `needs_human_review` with a note explaining why.

This is the single most important guardrail in the tool.

The reason is specific to how LLMs fail. When an LLM is uncertain and forced to commit, it doesn't say "I don't know." It generates plausible-sounding justification. The justification reads like real reasoning, references things that sound like they could be in the code, and is wrong. Anyone who has used an LLM extensively has seen this. The technical term is "hallucination," but the practical reality is "confident bullshit."

Requiring evidence quotes attacks this failure mode directly. To produce a false-positive verdict, the LLM has to point at specific lines in the code we sent it. Those lines are then programmatically checked: does this string actually appear, verbatim (whitespace-normalized), in the code we showed the model?

If the quote is fabricated, the check fails. If the check fails, the verdict gets downgraded to `needs_human_review` with the original LLM output preserved alongside the verifier's complaint. The human sees both and decides.

The Flask `eval` example earlier in this doc illustrates the mechanic. Claude returned three evidence quotes:

> ```python
> startup = os.environ.get("PYTHONSTARTUP")
> if startup and os.path.isfile(startup):
>     eval(compile(f.read(), startup, "exec"), ctx)
> ```

Each one appears verbatim in `src/flask/cli.py`. The verifier confirms that, the verdict stands, and the user sees the high-confidence FP.

If Claude had hallucinated a quote, say `if not is_admin_user():`, the verifier would have caught it. The verdict would have come out as needs_human_review with a note: "LLM cited code that does not appear in source: `if not is_admin_user():`."

A few details worth noting about the matching:

- **Whitespace is normalized.** Runs of spaces and tabs collapse to single spaces; leading and trailing whitespace is stripped. This handles cases where the LLM correctly identifies code but reformats indentation.
- **Line-number prefixes are stripped from the haystack.** When the prompt shows code as `1023 | eval(compile(...))`, the matcher strips the `1023 | ` before checking, so the LLM can quote without the line number.
- **The match is substring, not regex.** The LLM cannot use this as an injection vector because nothing it returns is interpreted as code.

What this guardrail does NOT catch:

- **Real quotes used to justify wrong reasoning.** The LLM can quote real code and then misinterpret what it means. The verifier checks "did you cite real code"; it does not check "did you understand it." That's a harder problem and is partly addressed by the second verifier layer (covered next).
- **Quotes that are real but irrelevant.** The verifier doesn't check whether the quoted code is logically connected to the verdict. A determined LLM could cite arbitrary surrounding code and write reasoning that doesn't depend on it.

Both of these are real limitations. The verifier is not a proof system. It's a cheap, fast sanity check that catches the most common and most dangerous failure mode, fabrication, and is honest about what it leaves to humans.

The asymmetry of errors argument from the previous section applies here too. A verifier that's too aggressive (rejects legitimate verdicts) costs the user some FP findings they could have closed quickly. A verifier that's too lenient (accepts fabricated reasoning) ships wrong "this is fine" verdicts to production. The current implementation leans aggressive on this check, downgrading on any failed quote match. That's the safe direction, and the next section explains why the second verifier check is calibrated differently.

## Design choice 3: The verifier, what it catches and what it doesn't

The verifier is two checks that run after every LLM call. They are not symmetric. One is a hard fail that downgrades the verdict; the other is an advisory signal that surfaces information to the user without changing the verdict. This asymmetry is a deliberate choice that was made after the first version of the verifier, which treated both as hard fails, produced unusable output in real testing.

### Check 1: Evidence quotes must appear in source (hard fail)

Covered in the previous section. Every string in the LLM's `evidence_quotes` array has to appear verbatim (whitespace-normalized) in the code that was sent to the model. If any quote fails this check, the verdict is downgraded to `needs_human_review` and the failed quote is recorded in `verification_notes`.

This is enforced as a hard fail because the failure mode it catches, quote fabrication, is unambiguous. If the LLM cites a string and that string is not in the code we sent it, the LLM is wrong. There is no innocent explanation. The substring check has a false-alarm rate near zero in practice.

### Check 2: Reasoning grounding (advisory only)

After Claude produces a verdict, the reasoning text gets scanned for identifier-like tokens: function names, variable names, dotted references like `os.path.isfile`, calls like `func()`, backtick-quoted code references. Each token is then checked against the prompt context: does this identifier actually appear in the code we showed the model?

The intuition is the same as the quote check: if the LLM mentions a function or variable that doesn't exist in the code we sent it, something might be wrong. Either the LLM made the identifier up, or it's referencing framework knowledge from its training data, or it's reasoning by contrast about code that isn't there.

The token extraction uses four regex patterns:

- Backtick-quoted tokens
- Function calls of the form `name()`
- Dotted references like `module.function`
- Camel-case and snake-case identifiers

Hits are filtered through a small whitelist of generic English and security vocabulary, then the survivors get reported. Critically: they get reported as `advisory_warnings` on the finding, not as verifier failures. The verdict does not change. The user sees a separate "Advisory note" section in the terminal and markdown reports, the JSON output includes the warnings under their own key, and life continues.

This was not the original design. The first version of the verifier treated grounding the same as the quote check: any flagged token downgraded the verdict. That version performed poorly enough in testing that I changed the policy.

### Why grounding is advisory, not hard

Two runs convinced me to split the checks.

The first was a Django scan. Confident `false_positive` verdicts kept getting downgraded because the reasoning referenced framework class names like `BoundField`, `ErrorList`, and `MD5PasswordHasher`. These are real Django classes. Claude knows them from training. They are not hallucinations. They were just not in the immediate code window we sent the model. Under hard-fail grounding, legitimate verdicts went to `needs_human_review` for what amounted to "Claude correctly knew what Django code looks like."

The second was a small project with 8 Python findings. Under hard-fail grounding, all 8 finished as `needs_human_review`. The tool produced zero actionable verdicts on a scan where at least two findings were clearly false positives. Looking at the downgraded verdicts, the pattern was consistent: three failure modes, none of them actually fabrication.

**Generic English that escaped the whitelist.** The verifier flagged words like `intercepted`, `service`, and `elsewhere` when the reasoning used them. These are ordinary English words, not code references, but they look like identifiers and the whitelist didn't cover them. Expanding the whitelist is possible but turns into an arms race: every new domain introduces new ordinary words.

**Framework knowledge.** Tokens like `__init__`, framework class names, and proper-noun references to libraries get flagged when the LLM mentions them while reasoning. These are real things Claude knows from training. Flagging them as if they were hallucinations isn't useful; they're just background knowledge being applied.

**Reasoning by contrast.** This is the most interesting case and the one that finally settled the decision. In the small-project scan, a `pickle.dump` call was flagged by a Semgrep rule that targets unsafe deserialization (`pickle.load` / `pickle.loads`). Claude correctly identified that the rule was misapplied: `dump` is serialization, not deserialization, and the rule is about deserializing untrusted data. The reasoning quoted the actual `pickle.dump` line and explained the distinction along these lines:

> The rule targets `pickle.load` and `pickle.loads`, which deserialize potentially untrusted data. This call is `pickle.dump`, which serializes a trusted internal object to a file. The rule does not apply.

The grounding check flagged `pickle.load` and `pickle.loads` as ungrounded tokens. They are, in fact, ungrounded; they don't appear in the file. But they are exactly the right things to mention. The LLM was reasoning about what the rule is intended to catch, by naming the things the rule actually matches. Under hard-fail grounding, this confident `false_positive` verdict was downgraded to `needs_human_review`. The reasoning was correct, the verdict was right, and the verifier broke the most useful finding in the scan.

After that case, I split the two checks. Quote check stays hard: fabrication is unambiguous, false-alarm rate is near zero, and the cost of missing a fabricated FP is high. Grounding becomes advisory: the false-alarm rate is too high to use as a verdict gate, but the signal is still worth surfacing because some of the flagged tokens really will be hallucinations.

After the split, the same 8-finding scan produces two confident false-positive verdicts, including the `pickle.dump` case. Both are stable across repeated runs. The grounding warnings are still emitted (the user sees them) but they no longer destroy the verdict they were trying to evaluate.

### What the user sees now

When a finding has advisory warnings, the report shows them in a separate "Advisory note" section, with a one-paragraph explanation that flagged tokens often mean reasoning-by-contrast or framework knowledge rather than fabrication, and that the user should read the reasoning carefully. The verdict and confidence are unaffected. A reader who skims past the advisory section and trusts the verdict is doing the same thing as before the verifier existed, and that is the point. The grounding check is a hint, not a gate.

The hard quote check still does its job. Every `false_positive` verdict in the output is one where Claude pointed at specific real code, and the tool checked that the code is actually there. That is the strong guarantee. The advisory check adds visibility into the reasoning without claiming more than it can deliver.

### What the verifier catches

**Fabricated quotes.** The hard check. Claude sometimes invents code that doesn't exist in the file. The substring check catches this every time. Verdict gets downgraded.

**Confidently wrong references in reasoning.** The advisory check. When Claude mentions a function or attribute that doesn't appear in the visible context, the user gets a warning. Most warnings are false alarms (framework knowledge, reasoning by contrast), but some are real hallucinations, and the user has the information to judge.

### What the verifier does NOT catch

The same list as before. These are inherent limits of post-hoc verification, not specific to the hard/soft split:

**Logically wrong reasoning over real code.** The LLM can quote real code, reference real identifiers, and still misinterpret what they do. The verifier sees real references and a coherent narrative. It cannot judge whether the narrative is correct.

**Cherry-picked quotes.** The LLM could cite real but irrelevant code. The verifier doesn't check whether the quoted code is logically connected to the conclusion.

**Subtle dataflow errors.** Claims like "this input flows through `escape()` before reaching the sink" are true if the path goes through `escape()` and false if a branch was missed. The verifier doesn't trace dataflow.

**Framework knowledge gaps.** When Claude assumes Django's `ErrorList` escapes its output or that Flask's `Markup()` is safe in a given context, the verifier doesn't validate the assumption; it only flags references that aren't in the visible code. With grounding now advisory, those flags don't downgrade the verdict, but they also still don't validate the assumption.

These limitations are real and significant. They are also not unique to this tool. The honest move is to acknowledge them, not to claim verification solves them.

### Why imperfect verification is still worth doing

The hard quote check raises the bar for the most common and most dangerous failure mode. A naive LLM triage tool can be fooled by any plausible-sounding reasoning, including pure fabrication. With the quote check, fabrication has to be plausible AND consistent with code that exists. That is a meaningfully higher bar; most LLM fabrication in testing is sloppy enough to fail the substring check.

The advisory grounding check raises the visibility of the second-order failure mode (reasoning that wanders past visible code) without forcing the tool to downgrade verdicts it cannot actually invalidate. The user sees a hint and decides.

The asymmetry-of-errors framing still applies, but it now lives at the per-check level rather than the per-tool level. Quote check: false-positive verifier complaints are nearly free, false-negative complaints would let fabricated FPs ship, so the policy leans strict. Grounding check: false-positive complaints are expensive (the small-project scan lost every actionable verdict to them), false-negative complaints cost some visibility on a small number of real hallucinations, so the policy leans advisory. Different cost structures, different policies. The split is the design.


## Design choice 4: Caching that survives unrelated edits

Every triaged finding gets cached at `~/.sg-triage/cache/<fingerprint>.json`. Cached verdicts are returned instantly with no API cost. This is the difference between a tool you run once and a tool you can put in CI.

The interesting question is what the fingerprint should be. The naive answer is "hash the finding": rule ID, file path, line number, matched code. That works for a single scan, but breaks the moment someone edits the file. Adding a comment to line 5 shifts every line below, and a finding that was on line 200 is now on line 201. With a line-number-sensitive fingerprint, every finding in the file gets re-triaged. On a 500-finding codebase, that's $10 of API costs after a one-character commit.

The fingerprint sg-triage uses is `SHA256(prompt_version + rule_id + file_path + matched_code + containing_function_source)`, truncated to 16 hex characters. Two properties:

- **Line-number-independent.** Adding a comment elsewhere in the file doesn't change the fingerprint. The cache survives.
- **Sensitive to changes that actually affect the verdict.** If the matched code changes, or if the function containing it changes, the fingerprint changes, and the finding gets re-triaged. This is the right behavior: when someone edits the function around the finding, the previous verdict may no longer apply.

The `prompt_version` field in the fingerprint matters too. When I bump the prompt between releases, the fingerprint of every cached entry changes, and the entire cache invalidates automatically. This means I can iterate on the prompt without worrying about stale verdicts. There's no manual cache-bust step, no migration script, no "did you remember to clear the cache" footgun.

`--no-cache` skips both read and write for a run. Use this when you want fresh verdicts (e.g., after upgrading the model or evaluating prompt changes). In v0.2 this flag will be renamed to `--force` because the current name is ambiguous.

Caching is not glamorous. It's also the difference between a tool you can run nightly and a tool that costs $10 every time someone edits a comment.

## Design choice 5: File path is provenance, not importance

When the LLM triages a finding, it sees the file path the finding came from. The natural reaction, for humans and for LLMs, is to use the path as a signal of importance. A finding in `src/auth/login.py` feels more concerning than one in `tests/fixtures/example.py`. A finding in `vendor/third_party/lib.py` feels easier to dismiss than one in your own code.

This intuition is wrong, and the system prompt explicitly tells the LLM not to use it.

The reason is subtle. File paths legitimately carry **provenance** information: whether code is test code, vendored code, example code, generated code. That's relevant to verdicts: a SQL injection in test fixture code is genuinely less exploitable than the same pattern in production handlers. The LLM should use this.

What file paths do NOT reliably carry is **importance**. A bug in vendored code is still a bug. An issue in `examples/` might be code users copy-paste into their own projects. A finding in a sleepy-looking utility module might be in the most-called function in the codebase. The LLM cannot tell from the path alone.

The prompt threads this distinction explicitly:

> **File path as provenance vs. importance.** Use the file path to identify whether code is test fixtures, examples, vendored libraries, or generated. These are legitimate provenance signals that affect exploitability. Do NOT treat the file path as a signal of importance. A "vendored" finding is not automatically less serious, an "examples/" finding may still ship to users, and a "tests/" finding may still leak credentials. Reason about exploitability from the code, not from the directory name.

This kind of explicit anti-bias instruction is one of the underappreciated levers in prompt design. LLMs absorb a lot of cultural intuitions about code (test code is throwaway, framework code is trustworthy, vendor code is someone else's problem) that aren't reliable for security analysis. Naming those intuitions and telling the LLM to override them produces measurably more cautious verdicts.

A related anti-bias instruction in the prompt: deployment context (e.g., "this endpoint is internal-only" or "this app is behind a WAF") is treated as `needs_human_review`, never as `false_positive`. The LLM cannot verify network topology from code, and it shouldn't be asked to. If a verdict's logic depends on "this endpoint isn't exposed to the internet," that decision belongs to a human who knows the deployment.

## What I tried and rejected

A handful of design choices that didn't make it into v0.1, with reasons.

**Binary FP/TP verdicts.** Covered above: three buckets is non-negotiable for security work.

**Asking the LLM for a confidence score (0.0 to 1.0).** Tried this in early prototyping. The LLM produces numbers that look meaningful but aren't well-calibrated: a 0.85 from one finding and a 0.85 from another don't represent the same probability of being correct. I switched to coarse buckets (`low`, `medium`, `high`) which are easier for the LLM to use consistently and easier for the human to act on.

**Letting the LLM decide whether to call the verifier.** Considered exposing verification as an optional step the LLM could request when uncertain. Rejected because it introduces an obvious incentive for the LLM to skip verification when it's confident, exactly the case where confidence is least correlated with correctness. Verification runs unconditionally on every verdict.

**Caching at the file level instead of the finding level.** Would be cheaper to cache and invalidate, but breaks the property that editing one function doesn't invalidate verdicts on unrelated functions in the same file. Per-finding caching with the function-source fingerprint is more granular work, but produces a cache that actually behaves correctly.

**Multi-turn LLM conversations to refine verdicts.** The pattern would be: LLM produces a verdict, sg-triage feeds back the verifier's complaints, LLM revises. Rejected for v0.1 because it doubles the latency and cost per finding for an unclear quality gain. The verifier is a quality gate, not a feedback loop. If the LLM fabricates, route to human; don't ask the LLM to try again.

**Auto-fix.** This was tempting and I deliberately did not build it. The Semgrep blog from 2023 shows their own auto-fix experiments produced ~40% directly committable output and ~40% useful starting points. Those are decent numbers for a code suggestion, but auto-fix in security context has a worse failure mode than triage: a wrong fix can introduce a new vulnerability while looking like it closed one. Triage that says "look at this" is honest about what it is. A fix that confidently rewrites your code and is subtly wrong is a different category of risk. Maybe v3 territory; not v0.1.

**A web UI.** sg-triage is a CLI. The output formats (JSON for CI, Markdown for sharing, terminal panels for interactive use) cover the deployment patterns I care about. A web UI is a different product with different concerns (auth, persistence, multi-user state). Out of scope.

## Open problems

Things I haven't figured out yet. Some I'll work on for v0.2; others I'd genuinely like input on.

**Verifier vocabulary handling.** The current grounding check uses a hand-maintained whitelist of generic English and security terms. This is brittle. Add a new class of false-positive (e.g., the verifier flags "interpolation" as ungrounded), and the fix is appending another word to a frozenset. A static English wordlist as the base, plus framework-aware loosening when the file is clearly framework code, would be structurally better. I haven't decided how to scope "framework-aware."

**How much code context is enough.** Right now sg-triage extracts the containing function plus one hop of called functions. More context costs tokens and probably improves verdict quality up to a point, but I don't know where that point is, and I haven't measured it carefully. Two hops? The full file? The full module? An empirical question I'd like to answer.

**Calibration on real engagement.** The Django run produced verdicts I read and judged as good, but my judgment is one data point. A small hand-labeled corpus (50-100 findings with ground truth) would let me measure verdict accuracy quantitatively rather than narratively. This is the next thing I'm building.

**Whether the asymmetry-of-errors framing actually matches user preference.** I designed the tool around "wrong FP > wrong TP." Some users may genuinely prefer fewer needs_review verdicts even at the cost of occasional wrong FP closures, because the human time saved exceeds the bug-shipped cost in their environment. v0.2 might expose a `--strict` / `--lenient` mode that exposes this tradeoff to the user. Right now I'm guessing, and I'd rather know.

## Try it

sg-triage is on GitHub: [github.com/Gaurav-4567/semgrep-triage](https://github.com/Gaurav-4567/semgrep-triage). MIT licensed, ~$0.02 per Python finding triaged, runs locally with your own Anthropic API key.

Quickstart in four commands:

```
git clone https://github.com/Gaurav-4567/semgrep-triage.git
cd semgrep-triage
pip install -e .
sg-triage triage /path/to/findings.json /path/to/your/repo --output-md report.md
```

Honest ask: if you run it on a real codebase and find verdicts that are clearly wrong, especially `false_positive` verdicts that should have been `needs_human_review`, please open an issue with the rule ID and your reasoning. That feedback drives the prompt design directly. Same goes for verdicts where the verifier flagged something it shouldn't have.

This is v0.1. Most of the rough edges are listed above. The interesting question for me is which of those rough edges you actually hit, and which ones don't matter in practice.

- Gaurav
