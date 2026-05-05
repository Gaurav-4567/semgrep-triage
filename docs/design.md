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
