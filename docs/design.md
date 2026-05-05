# Designing an LLM-powered SAST triage tool — open source, local-first, with anti-hallucination guardrails

Last weekend I shipped v0.1 of [sg-triage](https://github.com/Gaurav-4567/semgrep-triage), an open-source CLI that uses Claude to triage Semgrep findings. While preparing this writeup I went looking for prior art on r/netsec and discovered Semgrep themselves built this category in 2023 and have continued investing in it ([Semgrep Assistant](https://semgrep.dev/blog/2023/gpt4-and-semgrep-detailed/), now Semgrep Multimodal).

That's worth addressing upfront: this isn't a novel idea. The category exists and has a commercial incumbent. What I'd argue is uncommon is a few specific design choices that make sense if you assume LLMs hallucinate and you want to ship something a skeptical security engineer would actually trust.

This post walks through those design choices.

## A real verdict, before anything else

Semgrep flagged this code in Flask's CLI module (`src/flask/cli.py:1023`):

```python
eval(compile(f.read(), startup, "exec"), ctx)
```

Rule: `python.lang.security.audit.eval-detected.eval-detected`. CWE-95: eval injection. If you saw this in a 200-finding report, what would you do? Mark it as a bug — you waste time. Wave it through — you might miss real bugs. Skip it — you're just adding to the unreviewed pile.

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

That verdict reads like a senior security engineer's assessment after spending 5-10 minutes with the code. The quotes are verbatim — programmatically validated. The reasoning ties directly to visible code, not vibes.

When I ran sg-triage on Django, I got 14 verdicts of this quality across 50 Python findings, for $0.92 total. 14 findings I no longer needed to look at. The other 36 went to "needs human review" with specific notes about what context the LLM couldn't see.

## What this is, and what it isn't

sg-triage does one job: take Semgrep JSON, send each finding to Claude with surrounding code context, return a verdict in one of three buckets — real bug, false positive, or needs human review. MIT-licensed, runs locally, you bring your own Anthropic API key.

It is not magic. It is not autofix. It is not a replacement for security review. Every verdict is a senior-engineer-quality first-pass triage that you read and accept or reject. The goal is to reduce the volume that needs human attention — not to eliminate human attention.

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

The Django run is illustrative. Out of 50 Python findings, 14 came back as `false_positive` (high confidence), 0 as `likely_true_positive`, and 36 as `needs_human_review`. A binary system would have been forced to label those 36 as either FP or TP. Either choice would have been wrong some percentage of the time, and given that any wrong "FP" call is the catastrophic kind, the safe choice would have been to label all 36 as TP — at which point the tool has done nothing useful for those findings.

Three buckets is a small schema decision. It changes everything about the prompt, the verifier, and the trust model.

## Design choice 2: Evidence quotes as a hard requirement for false-positive verdicts

When the LLM returns a `false_positive` verdict, it must include verbatim quotes from the code that justify the verdict. Empty `evidence_quotes` array on a `false_positive` is a schema violation — the Pydantic model rejects it, and the orchestrator routes the finding to `needs_human_review` with a note explaining why.

This is the single most important guardrail in the tool.

The reason is specific to how LLMs fail. When an LLM is uncertain and forced to commit, it doesn't say "I don't know." It generates plausible-sounding justification. The justification reads like real reasoning, references things that sound like they could be in the code, and is wrong. Anyone who has used an LLM extensively has seen this — the technical term is "hallucination," but the practical reality is "confident bullshit."

Requiring evidence quotes attacks this failure mode directly. To produce a false-positive verdict, the LLM has to point at specific lines in the code we sent it. Those lines are then programmatically checked: does this string actually appear, verbatim (whitespace-normalized), in the code we showed the model?

If the quote is fabricated, the check fails. If the check fails, the verdict gets downgraded to `needs_human_review` with the original LLM output preserved alongside the verifier's complaint. The human sees both and decides.

The Flask `eval` example earlier in this doc illustrates the mechanic. Claude returned three evidence quotes:

> ```python
> startup = os.environ.get("PYTHONSTARTUP")
> if startup and os.path.isfile(startup):
>     eval(compile(f.read(), startup, "exec"), ctx)
> ```

Each one appears verbatim in `src/flask/cli.py`. The verifier confirms that, the verdict stands, and the user sees the high-confidence FP.

If Claude had hallucinated a quote — say, `if not is_admin_user():` — the verifier would have caught it. The verdict would have come out as needs_human_review with a note: "LLM cited code that does not appear in source: `if not is_admin_user():`."

A few details worth noting about the matching:

- **Whitespace is normalized.** Runs of spaces and tabs collapse to single spaces; leading and trailing whitespace is stripped. This handles cases where the LLM correctly identifies code but reformats indentation.
- **Line-number prefixes are stripped from the haystack.** When the prompt shows code as `1023 | eval(compile(...))`, the matcher strips the `1023 | ` before checking, so the LLM can quote without the line number.
- **The match is substring, not regex.** The LLM cannot use this as an injection vector because nothing it returns is interpreted as code.

What this guardrail does NOT catch:

- **Real quotes used to justify wrong reasoning.** The LLM can quote real code and then misinterpret what it means. The verifier checks "did you cite real code"; it does not check "did you understand it." That's a harder problem and is partly addressed by the second verifier layer (covered next).
- **Quotes that are real but irrelevant.** The verifier doesn't check whether the quoted code is logically connected to the verdict. A determined LLM could cite arbitrary surrounding code and write reasoning that doesn't depend on it.

Both of these are real limitations. The verifier is not a proof system. It's a cheap, fast sanity check that catches the most common and most dangerous failure mode — fabrication — and is honest about what it leaves to humans.

The asymmetry of errors argument from the previous section applies here too. A verifier that's too aggressive (rejects legitimate verdicts) costs the user some FP findings they could have closed quickly. A verifier that's too lenient (accepts fabricated reasoning) ships wrong "this is fine" verdicts to production. The current implementation leans aggressive, downgrading on any verifier complaint. That's the safe direction.

## Design choice 3: The verifier — what it catches, what it doesn't

The verifier is two checks that run after every LLM call. Both are cheap, both are imperfect, both make the tool meaningfully more trustworthy than "ask Claude, trust the answer."

### Check 1: Evidence quotes must appear in source

Covered in the previous section. Every string in the LLM's `evidence_quotes` array has to appear verbatim (whitespace-normalized) in the code that was sent to the model. If any quote fails this check, the verdict is downgraded to `needs_human_review` and the failed quote is recorded in the verdict's verifier notes.

### Check 2: Reasoning grounding

This is the more interesting check. After Claude produces a verdict, the reasoning text gets scanned for identifier-like tokens — function names, variable names, dotted references like `os.path.isfile`, calls like `func()`, backtick-quoted code references like `\`request.path\``. Each token is then checked against the prompt context: does this identifier actually appear in the code we showed the model?

The intuition: if the LLM mentions a function or variable that doesn't exist in the code we sent it, something is wrong. Either the LLM made the identifier up (hallucination), or it's referencing framework knowledge from its training data that may or may not match the actual implementation.

The token extraction uses four regex patterns:

- Backtick-quoted tokens: `\`identifier\``
- Function calls: `name()`
- Dotted references: `module.function`
- Camel-case or snake-case identifiers: `BoundField`, `password_validated`

Hits get filtered through a vocabulary whitelist (`_GENERIC_VOCAB`) of generic English and security terms — words like "function," "variable," "input," "validation," "framework." Without this whitelist, the verifier would flag every reasoning paragraph for using ordinary English. With it, the verifier flags only words that look like code references but don't appear in the code.

If any flagged token survives the whitelist, the verdict is downgraded — same as a failed quote check. The original LLM verdict is preserved; the user sees both.

### What the verifier catches

Three real failure modes:

**Fabricated identifiers.** Claude sometimes invents function names that sound plausible. In a real run, Claude wrote a verdict for a Django finding that referenced `request.get_host()` — a real Django method, but one that didn't appear in the code we sent it. The verifier flagged it. The verdict (which was confidently `false_positive`) got downgraded to `needs_human_review`. A human looking at the original verdict could decide if the reasoning was correct despite the missing code reference, but the tool wouldn't auto-close it.

**Fabricated quotes.** Less common with capable models, but happens. Easy to catch.

**Confident over-reach beyond visible context.** When the LLM reasons about callers or parent classes it can't see, those references get flagged. This is technically not "hallucination" — Claude knows real Django classes from training — but the user should still be told that the verdict relies on context the tool didn't actually verify.

### What the verifier does NOT catch

Honest list of failure modes the verifier cannot detect:

**Logically wrong reasoning over real code.** The LLM can quote real code, reference real identifiers, and still misinterpret what they do. If Claude looks at `validate_input(x)` and assumes it's a sanitizer when it's actually just a length check, the verifier sees real code references and a coherent narrative. It cannot judge whether the narrative is correct.

**Cherry-picked quotes.** The LLM could cite real but irrelevant code to justify a verdict. The verifier doesn't check whether the quoted code is logically connected to the conclusion.

**Subtle dataflow errors.** "This input flows through `escape()` before reaching the sink" — true if the code path goes through `escape()`, false if there's a branch the LLM didn't trace. The verifier doesn't trace dataflow; it only checks whether the names mentioned exist.

**Framework knowledge gaps.** When Claude assumes Django's `ErrorList` escapes its output (it does) or that Flask's `Markup()` is safe in a given context (it depends), those assumptions come from training data. The verifier doesn't validate them; it only flags references that aren't in the visible code.

These limitations are real and significant. They are also not unique to this tool. Any LLM-based reasoning system has them. The honest move is to acknowledge them, not to claim verification solves them.

### Why imperfect verification is still worth doing

Two reasons.

First, it raises the bar. A naive LLM triage tool can be fooled by any plausible-sounding reasoning, including pure fabrication. With the verifier, fabrication has to be plausible AND consistent with code that exists. That's a meaningfully higher bar — most LLM hallucinations in my testing are sloppy enough to fail the substring check.

Second, the asymmetry-of-errors argument. The cost of the verifier being too aggressive (false positives flagged for review when the LLM was actually right) is small — the user looks at one more finding. The cost of the verifier being too lenient (a fabricated FP verdict accepted) can be large — a real bug closed by mistake. Erring toward strict verification matches the cost structure of security work.

The verifier in v0.1 leans aggressive. On the Django run, several confident `false_positive` verdicts got downgraded because the reasoning referenced framework class names (`BoundField`, `ErrorList`, `MD5PasswordHasher`) that Claude knows from training but weren't in the immediate code. Those verdicts were probably correct. Downgrading them cost the user some FPs they could have closed quickly. This is a known tradeoff and a v0.2 priority — possibly via a static English wordlist as the base whitelist, possibly via a "framework-aware" mode that loosens checks when the file is clearly framework code.

Either way, the design principle holds: when the verifier is uncertain whether the LLM is right, it routes to human review rather than guessing. The point isn't to be a proof system. It's to be honest about what we've actually verified.

## Design choice 4: Caching that survives unrelated edits

Every triaged finding gets cached at `~/.sg-triage/cache/<fingerprint>.json`. Cached verdicts are returned instantly with no API cost. This is the difference between a tool you run once and a tool you can put in CI.

The interesting question is what the fingerprint should be. The naive answer is "hash the finding" — rule ID, file path, line number, matched code. That works for a single scan, but breaks the moment someone edits the file. Adding a comment to line 5 shifts every line below, and a finding that was on line 200 is now on line 201. With a line-number-sensitive fingerprint, every finding in the file gets re-triaged. On a 500-finding codebase, that's $10 of API costs after a one-character commit.

The fingerprint sg-triage uses is `SHA256(prompt_version + rule_id + file_path + matched_code + containing_function_source)`, truncated to 16 hex characters. Two properties:

- **Line-number-independent.** Adding a comment elsewhere in the file doesn't change the fingerprint. The cache survives.
- **Sensitive to changes that actually affect the verdict.** If the matched code changes, or if the function containing it changes, the fingerprint changes, and the finding gets re-triaged. This is the right behavior — when someone edits the function around the finding, the previous verdict may no longer apply.

The `prompt_version` field in the fingerprint matters too. When I bump the prompt between releases, the fingerprint of every cached entry changes, and the entire cache invalidates automatically. This means I can iterate on the prompt without worrying about stale verdicts — there's no manual cache-bust step, no migration script, no "did you remember to clear the cache" footgun.

`--no-cache` skips both read and write for a run. Use this when you want fresh verdicts (e.g., after upgrading the model or evaluating prompt changes). In v0.2 this flag will be renamed to `--force` because the current name is ambiguous.

Caching is not glamorous. It's also the difference between a tool you can run nightly and a tool that costs $10 every time someone edits a comment.

## Design choice 5: File path is provenance, not importance

When the LLM triages a finding, it sees the file path the finding came from. The natural reaction — for humans and for LLMs — is to use the path as a signal of importance. A finding in `src/auth/login.py` feels more concerning than one in `tests/fixtures/example.py`. A finding in `vendor/third_party/lib.py` feels easier to dismiss than one in your own code.

This intuition is wrong, and the system prompt explicitly tells the LLM not to use it.

The reason is subtle. File paths legitimately carry **provenance** information — whether code is test code, vendored code, example code, generated code. That's relevant to verdicts: a SQL injection in test fixture code is genuinely less exploitable than the same pattern in production handlers. The LLM should use this.

What file paths do NOT reliably carry is **importance**. A bug in vendored code is still a bug. An issue in `examples/` might be code users copy-paste into their own projects. A finding in a sleepy-looking utility module might be in the most-called function in the codebase. The LLM cannot tell from the path alone.

The prompt threads this distinction explicitly:

> **File path as provenance vs. importance.** Use the file path to identify whether code is test fixtures, examples, vendored libraries, or generated. These are legitimate provenance signals that affect exploitability. Do NOT treat the file path as a signal of importance — a "vendored" finding is not automatically less serious, an "examples/" finding may still ship to users, and a "tests/" finding may still leak credentials. Reason about exploitability from the code, not from the directory name.

This kind of explicit anti-bias instruction is one of the underappreciated levers in prompt design. LLMs absorb a lot of cultural intuitions about code (test code is throwaway, framework code is trustworthy, vendor code is someone else's problem) that aren't reliable for security analysis. Naming those intuitions and telling the LLM to override them produces measurably more cautious verdicts.

A related anti-bias instruction in the prompt: deployment context (e.g., "this endpoint is internal-only" or "this app is behind a WAF") is treated as `needs_human_review`, never as `false_positive`. The LLM cannot verify network topology from code, and it shouldn't be asked to. If a verdict's logic depends on "this endpoint isn't exposed to the internet," that decision belongs to a human who knows the deployment.

## What I tried and rejected

A handful of design choices that didn't make it into v0.1, with reasons.

**Binary FP/TP verdicts.** Covered above — three buckets is non-negotiable for security work.

**Asking the LLM for a confidence score (0.0 to 1.0).** Tried this in early prototyping. The LLM produces numbers that look meaningful but aren't well-calibrated — a 0.85 from one finding and a 0.85 from another don't represent the same probability of being correct. I switched to coarse buckets (`low`, `medium`, `high`) which are easier for the LLM to use consistently and easier for the human to act on.

**Letting the LLM decide whether to call the verifier.** Considered exposing verification as an optional step the LLM could request when uncertain. Rejected because it introduces an obvious incentive for the LLM to skip verification when it's confident — exactly the case where confidence is least correlated with correctness. Verification runs unconditionally on every verdict.

**Caching at the file level instead of the finding level.** Would be cheaper to cache and invalidate, but breaks the property that editing one function doesn't invalidate verdicts on unrelated functions in the same file. Per-finding caching with the function-source fingerprint is more granular work, but produces a cache that actually behaves correctly.

**Multi-turn LLM conversations to refine verdicts.** The pattern would be: LLM produces a verdict, sg-triage feeds back the verifier's complaints, LLM revises. Rejected for v0.1 because it doubles the latency and cost per finding for an unclear quality gain. The verifier is a quality gate, not a feedback loop. If the LLM fabricates, route to human; don't ask the LLM to try again.

**Auto-fix.** This was tempting and I deliberately did not build it. The Semgrep blog from 2023 shows their own auto-fix experiments produced ~40% directly committable output and ~40% useful starting points. Those are decent numbers for a code suggestion, but auto-fix in security context has a worse failure mode than triage: a wrong fix can introduce a new vulnerability while looking like it closed one. Triage that says "look at this" is honest about what it is. A fix that confidently rewrites your code and is subtly wrong is a different category of risk. Maybe v3 territory; not v0.1.

**A web UI.** sg-triage is a CLI. The output formats (JSON for CI, Markdown for sharing, terminal panels for interactive use) cover the deployment patterns I care about. A web UI is a different product with different concerns (auth, persistence, multi-user state). Out of scope.