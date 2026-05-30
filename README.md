# sg-triage

**Cut Semgrep noise without trusting an LLM blindly.** Every false-positive verdict is grounded in verifiable quotes from your code.

`sg-triage` is a Python CLI that takes Semgrep JSON output, sends each finding to Claude with the surrounding code context, and produces a triage report. Every finding gets one of three verdicts: likely a real bug, likely a false positive, or needs human review. False-positive verdicts come with verbatim quotes from your code, programmatically checked to catch the most obvious failure mode of LLM-based tools â€” fabricated reasoning.

> âš ï¸ **Status: v0.1, early experimental release.** This tool does NOT replace a security engineer's review. It triages findings into three buckets and reduces the volume that need human attention. Read [Limitations](#limitations) before using on anything you'd put in production.

## What sg-triage does

For each Semgrep finding, the tool:

1. Parses the Semgrep JSON output
2. Extracts the surrounding code context using tree-sitter (the containing function, file imports, called functions one hop deep)
3. Sends the finding plus context to Claude, with a structured prompt designed for security triage
4. Validates Claude's response: false-positive verdicts must include verbatim quotes from the code (enforced), and identifier references in the reasoning that don't appear in the visible code are surfaced as advisory warnings
5. Produces a report in three formats: terminal panels, structured JSON, or shareable Markdown

Findings that fail the quote check, or that Claude isn't confident about, are routed to `needs_human_review` rather than guessed at. The tool is designed to fail toward "ask a human" instead of toward "wrong answer."

## A real example

Semgrep flags this code in Flask's CLI module (`src/flask/cli.py:1023`):

```python
eval(compile(f.read(), startup, "exec"), ctx)
```

The rule is `python.lang.security.audit.eval-detected.eval-detected`. Looking at this in isolation, an automated triage tool â€” or a tired engineer skimming a 200-finding report â€” might either flag this as a real bug or wave it through.

`sg-triage` triaged this as **`false_positive`** with **high confidence**. Here's the verdict it produced:

> The eval() call is executing code from the PYTHONSTARTUP environment variable, which is a standard Python interpreter feature. The code reads from `startup = os.environ.get("PYTHONSTARTUP")` and only executes if `os.path.isfile(startup)` is true. PYTHONSTARTUP is a Python interpreter convention that allows users to configure their own interactive shell startup script â€” it is set by the user running the Python process, not by external attackers. This is equivalent to the user running arbitrary Python code themselves, which they can already do by simply invoking the Python interpreter. The "attacker" would need to control the environment variable of the process they're already running, which means they already have code execution capability.

**Evidence quotes** (verified to appear verbatim in the source):

```
startup = os.environ.get("PYTHONSTARTUP")
if startup and os.path.isfile(startup):
eval(compile(f.read(), startup, "exec"), ctx)
```

This is the kind of verdict a senior security engineer would write after spending 5â€“10 minutes reading the surrounding code. `sg-triage` produced it in roughly 10 seconds for about $0.02 in API costs.

The full Markdown report from running `sg-triage` on Django is in [`examples/django-report.md`](examples/django-report.md).

## Quickstart

You'll need:
- Python 3.10+
- Semgrep installed (`pip install semgrep`)
- An Anthropic API key ([get one here](https://console.anthropic.com/settings/keys))
- $5â€“20 of Anthropic API credit to start (you pay Anthropic directly; this tool charges nothing)

Install:

```bash
git clone https://github.com/Gaurav-4567/semgrep-triage.git
cd semgrep-triage
pip install -e .
```

Set your API key (or use a `.env` file):

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

Run Semgrep on a Python project, then triage the output:

```bash
cd /path/to/your/project
semgrep --config=auto --json --output=findings.json .

cd /path/to/semgrep-triage
sg-triage triage /path/to/your/project/findings.json /path/to/your/project \
  --output-md report.md
```

Open `report.md` to see the triage results.

## Cost

You pay Anthropic directly for API usage. There is no SaaS layer, no telemetry, no per-seat licensing.

| Scenario | Approximate cost |
|---|---|
| One Python finding triaged | ~$0.02 |
| 100 Python findings | ~$2 |
| 500 Python findings | ~$10 |
| Re-running on the same code | $0 (cached) |

Verdicts are cached locally per finding. Re-running on the same code returns instantly with no API cost. Edits to the relevant function invalidate the cache automatically and trigger re-triage.

For comparison: a senior security engineer triaging 100 findings manually takes 4â€“8 hours. Commercial SAST AI add-ons run $20â€“100 per developer per month.

## Why Claude (and not a free API)?

The most common question about a tool like this is: why does it cost money â€” why not use a free LLM API?

The answer is data privacy, and it's specific to what this tool does. `sg-triage` reads your source code and sends it to an LLM provider. For that, the provider's training-data policy matters more than the price.

The only free LLM API capable of running this workload is Google's Gemini free tier. Per [Google's Gemini API terms](https://ai.google.dev/gemini-api/terms), content you submit on the *unpaid* tier is used to improve and develop Google's products, services, and machine-learning technologies â€” meaning your code can be used for training, and human reviewers may read it. (Regional exception: users in the EEA, Switzerland, and the UK are covered by the paid-tier data terms even on the free tier.) Sending proprietary code to a free tier that trains on it is a non-starter for security work.

Paid APIs don't have this problem. Anthropic's [Commercial Terms](https://www.anthropic.com/legal/commercial-terms) state that "Anthropic may not train models on Customer Content from Services." OpenAI's API and Google's *paid* Gemini tier have equivalent no-training defaults. So the real distinction isn't "Anthropic versus everyone else" â€” it's "a paid API versus a free tier that trains on your inputs." Any of the paid options keeps your code out of training data.

`sg-triage` uses Anthropic specifically because that's what its verdicts were calibrated against â€” the prompt, the verifier thresholds, and the example outputs are all tuned and validated on Claude Sonnet 4.5. Other paid providers would likely work, but they're unvalidated; multi-provider support is a possible future direction. For v0.1, the recommendation is simple: bring an Anthropic API key, pay roughly $0.02 per finding, and your code is never used for training.

## How it works

**Code context extraction.** When Semgrep flags a line, `sg-triage` uses tree-sitter to find the function containing the match, the file's imports, and any functions called from within the matching function (resolved one hop deep). Whatever the extractor cannot resolve â€” a third-party function definition, a module-level match â€” is recorded as an "extraction note" and surfaced to the LLM as missing context. The pipeline is honest about what it didn't see.

**LLM call.** Each finding is sent to Claude (Sonnet 4.5 by default) with a structured prompt designed for security triage. The prompt includes calibration instructions that bias toward `needs_human_review` on uncertainty, explicit warnings about common false-positive patterns AND common false-negative traps (cases that look like FPs but aren't), and a hard requirement that false-positive verdicts include verbatim code quotes as evidence. The LLM is forced to return its verdict via Anthropic's tool-use, which gives us schema-level validation.

**Verification.** After every LLM call, two checks run â€” and they are deliberately *not* symmetric:

1. **Quote check (hard).** Each evidence quote must appear verbatim in the code we sent (whitespace-normalized). A failed quote check downgrades the verdict to `needs_human_review` and records the reason in `verification_notes`. Fabricated quotes are unambiguous, so this check gates the verdict.
2. **Grounding check (advisory).** Identifier-like tokens in the reasoning (function names, dotted references) that don't appear in the visible code are surfaced as `advisory_warnings`. This does **not** change the verdict. It started as a hard fail and was softened after testing showed it flagged framework class names and reasoning-by-contrast far more often than real hallucinations â€” softening it roughly doubled the confident false-positive verdicts on real scans with no loss of safety.

The original verdict and any verifier notes are preserved in the report. **The verifier doesn't prevent hallucinations â€” the hard quote check catches the dangerous, common case (fabrication) and routes it back to the human, while the advisory grounding check adds visibility into the reasoning without over-claiming what it can prove.** The full rationale for the hard/soft split, with worked examples, is in the [design doc](docs/design.md).

**Caching.** Each finding is fingerprinted as a hash of `(prompt_version, rule_id, file_path, matched_code, containing_function_source)`. Cached verdicts persist at `~/.sg-triage/cache/`. The cache invalidates automatically when the prompt changes between releases or when the relevant code changes; line-number shifts from unrelated edits don't invalidate it. Use `--no-cache` to force re-triage.

**Concurrency.** Up to 5 LLM calls run in parallel via a thread pool. Per-finding errors are isolated â€” a single crashing finding never kills the run.

## Output formats

**Terminal:** colored panels per finding, sorted by actionability (likely real bugs first, then needs-review, then false positives), followed by a summary.

**JSON** (`--output-json report.json`): structured report matching the project's Pydantic schema. For CI integration and programmatic consumption.

**Markdown** (`--output-md report.md`): shareable report with per-finding details, per-rule statistics, and a footer with run metadata. Render in a Markdown viewer or paste in a PR comment.

## Limitations

You should know the following before using `sg-triage`:

**Scope:**
- v0.1 supports Python source files only. HTML, JavaScript, Go, etc. findings are routed to `needs_human_review` with a note. Multi-language support is on the v0.2 roadmap.
- Semgrep is the only supported scanner input.
- Free tier of Semgrep redacts the matched code in JSON output (`"requires login"`); we read the actual lines from disk using the file path and line numbers.

**What's been validated â€” and what hasn't:**
- v0.1's verdicts have been spot-checked on three real Python codebases: Flask (4 findings), a small private project (8 findings), and a 50-finding slice of Django â€” about 62 findings total. All of that validation was on **Claude Sonnet 4.5**, on **Python**, on **web or web-adjacent code**.
- What has **not** been validated: other languages; other Claude models (Haiku, Opus, or Sonnet versions other than 4.5); codebases with confirmed CVEs â€” which means the tool's false-negative rate (real bugs it wrongly calls `false_positive`) is currently **unmeasured**; and non-web Python such as data-science notebooks, ML pipelines, or CLI tooling. Treat verdicts outside this validated envelope with extra skepticism, and please open issues when you find wrong ones (see [Contributing](#contributing)).

**LLM-related risks:**
- LLMs hallucinate. The verifier catches the obvious cases (fabricated quotes) but cannot catch every subtle reasoning error. Treat verdicts as a senior engineer's first-pass triage, not as ground truth.
- Verdicts on the same finding can vary slightly between fresh runs. Cached verdicts are stable. If consistency matters, lean on the cache.
- The tool sees only the code in the matched function and one hop of called functions. Vulnerabilities that depend on dataflow further away than that will tend toward `needs_human_review`, which is the safe default.

**Things this tool does NOT do:**
- It does not replace a security engineer's review.
- It does not auto-fix vulnerabilities.
- It does not run Semgrep for you (Semgrep is a separate tool you run first).
- It does not understand business context (e.g., "this endpoint is internal-only and behind a WAF"). Those decisions stay with humans; the tool routes them to `needs_human_review` with a note about what to verify.

## Roadmap (v0.2 and beyond)

- **Prompt caching** â€” Anthropic's prompt-caching feature should reduce input cost by ~35%. Mostly free win.
- **Per-project configuration** (`.sg-triage.yml`) â€” declare trust assumptions like "this directory is internal-only" or "these functions are validated sanitizers."
- **JavaScript and Go support** â€” multi-language extractor architecture is already in place; we just need to enable additional grammars.
- **Baseline file** â€” checkable-into-the-repo verdict store for team-shared triage state.
- **Better verifier vocabulary handling** â€” the current allowlist is hand-maintained. Replace with a static English wordlist or a framework-aware mode.
- **Optional Haiku-first routing** â€” use Haiku for initial verdicts and escalate to Sonnet only on uncertainty. Could cut cost by 50â€“70%.

## Contributing

This is a personal project, very early. Issues and PRs welcome. If you've run the tool on a codebase and found verdicts that are clearly wrong (especially false positives that should have been `needs_human_review`), please open an issue with the rule ID and your reasoning â€” that feedback drives the prompt design.

## License

MIT.
