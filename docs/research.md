# Goldman Sachs: AI Control Layer (HackYeah 2026 research)

> Background research, kept for reference. The chosen product and its acceptance criteria are in [TOLLGATE.md](../TOLLGATE.md). Ideas B to E below were partly folded into Tollgate; see its feature tiers.

> "Build a flexible AI control layer to secure and govern interactions with Agentic AI systems (AI agents, MCP services, LLMs, APIs) ... Create the ultimate hybrid defense system for the generative AI era!"

Research checked 2026-10-03. Every URL below was fetched live (HTTP 200 / HF Hub API), except where it is marked otherwise.

---

## 1. Problem reference

Sources:
- `CRITERIA AI Control Layer.pdf` (partner task pack, not in this repo): task, requirements, evaluation
- `RULES AI Control Layer.pdf` (partner task pack, not in this repo): legal terms, submission, prize, weights

What to build: a lightweight **gateway / proxy / middleware / SDK wrapper** that "intercepts and governs interactions with AI systems". It must cover agent↔agent, app↔agent, agent↔MCP and agent↔model traffic.

| # | Problem | Key quote |
|---|---|---|
| **P1** | **Authn / access control for agents** | "Without local enforcement, agentic systems can easily access resources they shouldn't access, impersonate other actors and perform harmful and irreversible actions." |
| **P2** | **Input validation / prompt injection** | "AI systems interpret natural language as execution logic, making them highly vulnerable to such attacks as prompt injection." |
| **P3** | **Output filtering / data leakage (PII, secrets)** | "a lack of rigorous filtering means AI systems can return sensitive data." The layer must "inspect, redact, or block unsafe interactions in real-time". |
| **P4** | **Memory access and runaway resource use** | Agents "can trigger unauthorized data retrievals or get trapped in runaway execution loops ... unexpectedly high resource consumption." |
| **P5** | **Budget governance (commercial and local models)** | "manage budgets for both external commercial APIs and locally hosted models": token spend, compute time, resource access. |
| **P6** | **Historical attack mitigation using an external signature feed** | "detect or mitigate known historical attacks on AI infrastructure (i.e. where signatures of such attacks can be fed from some externally managed system)", for example "malicious code execution, unsafe deserialization, or supply-chain exploits targeting model repositories." |
| **P7** | **Centralized policy engine** | "A single config source ... managing controls, sensitivity thresholds (Block vs Redact or adherence %), allowed LLM models, and resource/financial budgets." Judges **edit config live**: "can they adjust in real-time". |
| **P8** | **Hybrid defense** | "must implement a hybrid defense architecture utilizing both non-AI (deterministic) and AI-based (semantic) controls." |
| **P9** | **Security reporting and audit** | "real-time metrics (blocked interactions, budget usage) for management and exportable audit logs designed for security teams" + an interactive dashboard + "performance telemetry". |
| **P10** | **Self-testing suite** | "automated testing suite showcasing both positive (allowed) and negative (blocked/redacted) test cases". Judges run it themselves. |
| **P11** | **Broader threat coverage** | "analyze the AI ecosystem deeply and review available sources (e.g. OWASP)": go beyond the listed examples. |

---

## 2. Judging criteria and hard constraints

**Weights: the two PDFs disagree. Plan for both.**

| Criterion | CRITERIA.pdf | RULES.pdf |
|---|---|---|
| Robustness of solution and quality of guardrails | 30% | 30% |
| Architecture and performance efficiency | 20% | 20% |
| Security reporting | 20% | 20% |
| Completeness of self-testing suite | **15%** | **20%** |
| Practical implementability and scalability | **15%** | **10%** |

RULES is the legal document, so its weights probably govern. Either way the test suite is worth 15-20%, so treat it as a first-class product.

**Required deliverables (CRITERIA §3):**
1. A working control layer that is easy to integrate, plus a demo agent (your own or an existing one), plus **a simple architecture diagram**.
2. **A sample policy file** that is documented and shows **different strictness/adherence levels and budget rules**.
3. **An interactive dashboard** showing controls, security posture, blocked threats and cost/resource metrics.
4. **An executable test suite** with positive and negative cases, covering budget limits and exploit mitigation.

**Submission (RULES §5):** on HackTribe, in EN or PL. It must contain:
- project title
- team name
- members (1-6)
- description
- a **PDF of at most 10 slides** (screenshots, repo, demo links)

**Timing (RULES §5):**
- The window is "no earlier than 11:00 PM on October 3rd" to "no later than 11:00PM on October 4th".
- The start time looks like a typo for 11:00 AM. **Confirm on Discord.**
- Nothing changed after the deadline is considered.

**Judging process:**
- Phase 1: mentors review the submission. You need **≥50% of the points** to be eligible for a prize.
- Phase 2: live pitch by finalists.
- Prizes: 6k / 5k / 4k PLN.

**How judges test (CRITERIA §6):**
- They **run your test suite**.
- They send **spontaneous ad-hoc prompts** to the running layer.
- They **edit config files / feeds** (change rules, remove controls, adjust thresholds) and watch whether the change takes effect live.
- They ask for **performance telemetry**.
- They review the architecture, dashboards and logs.

**Technical constraints:**
- Free choice of stack. Building on OSS is fine, but **check licenses**.
- **No paid APIs are provided.** Everything must run locally (Ollama is suggested).
- No datasets are provided, so you bring your own test prompts.

**Not evaluated:** "agents, applications and other unrelated components will not be subject to assessment". The demo agent can be trivial. Put the effort into the layer.

---

## 3. Data sources

All Hugging Face entries were checked with the HF Hub API. "Gated" means you accept terms with an HF login, usually approved instantly.

| Name | Contents | Access / license | URL | Serves |
|---|---|---|---|---|
| deepset/prompt-injections | ~660 labeled injection/benign prompts (EN+DE) | HF download, Apache-2.0 | https://huggingface.co/datasets/deepset/prompt-injections | P2, P10 |
| Lakera/gandalf_ignore_instructions | ~1k real "ignore instructions" attacks from the Gandalf game | HF, MIT | https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions | P2, P10 |
| xTRam1/safe-guard-prompt-injection | ~10k synthetic injection/safe prompts (classification) | HF, no license tag (treat as research use only) | https://huggingface.co/datasets/xTRam1/safe-guard-prompt-injection | P2, P8 |
| reshabhs/SPML_Chatbot_Prompt_Injection | System prompt + user prompt pairs with injection labels (chatbot context) | HF, MIT | https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection | P2, P10 |
| jackhhao/jailbreak-classification | Jailbreak vs benign prompts | HF, Apache-2.0 | https://huggingface.co/datasets/jackhhao/jailbreak-classification | P2, P10 |
| TrustAIRLab/in-the-wild-jailbreak-prompts | 15k in-the-wild jailbreak prompts (DAN etc., CCS'24) | HF, MIT | https://huggingface.co/datasets/TrustAIRLab/in-the-wild-jailbreak-prompts | P2, P6 (signatures) |
| JailbreakBench/JBB-Behaviors | 100 harmful + 100 benign behaviors, standard jailbreak benchmark | HF, MIT | https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors | P2, P10 |
| walledai/AdvBench | 500 harmful instructions (GCG paper) | HF, **gated**, MIT | https://huggingface.co/datasets/walledai/AdvBench | P2, P10 |
| allenai/wildjailbreak | 262k vanilla/adversarial harmful and **contrastive benign** prompts (good for false-positive tests) | HF, **gated**, ODC-BY | https://huggingface.co/datasets/allenai/wildjailbreak | P2, P8, P10 |
| nvidia/Aegis-AI-Content-Safety-Dataset-2.0 | 33k annotated human↔LLM interactions with a safety taxonomy | HF, CC-BY-4.0 | https://huggingface.co/datasets/nvidia/Aegis-AI-Content-Safety-Dataset-2.0 | P3, P8 |
| lmsys/toxic-chat | 10k real user prompts with toxicity and jailbreak labels | HF, CC-BY-NC-4.0 | https://huggingface.co/datasets/lmsys/toxic-chat | P2, P10 |
| PKU-Alignment/BeaverTails | 300k+ QA pairs, 14 harm categories | HF, CC-BY-NC-4.0 | https://huggingface.co/datasets/PKU-Alignment/BeaverTails | P3, P10 |
| ai4privacy/pii-masking-400k | 400k PII-masked texts in 6 languages (a newer 1M+ release exists: `pii-masking-openpii-1m`) | HF, custom license (check terms) | https://huggingface.co/datasets/ai4privacy/pii-masking-400k | P3, P10 |
| gretelai/synthetic_pii_finance_multilingual | Synthetic **financial documents** with labeled PII (IBAN, account numbers...) | HF, Apache-2.0 | https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual | P3 (GS-relevant demo) |
| AgentDojo | Agent tool-use environments with indirect prompt injection attacks (banking, travel, slack) | GitHub, pip, MIT | https://github.com/ethz-spylab/agentdojo | P1, P2, P10 |
| InjecAgent | 1k+ indirect-injection test cases for tool-integrated agents | GitHub, MIT | https://github.com/uiuc-kang-lab/InjecAgent | P2, P10 |
| BIPIA | Indirect prompt injection benchmark (email/table/code) | GitHub, **archived**, custom license | https://github.com/microsoft/BIPIA | P2 |
| OSV.dev API | Open vulnerability DB (CVE/GHSA/PYSEC) for PyPI/npm. Live query for e.g. `langchain` returns CVE-2023-36258 PALChain RCE | REST `POST https://api.osv.dev/v1/query`, free, no auth, CC-BY | https://osv.dev/ | **P6 (external signature feed)** |
| GitHub Advisory DB | GHSA advisories, also as a git repo | Web/API, CC-BY-4.0 | https://github.com/advisories | P6 |
| NVD CVE API 2.0 | Official CVE feed | REST, free API key recommended. **Unverified by curl (403 to bots)**, site is known to exist | https://nvd.nist.gov/developers/vulnerabilities | P6 |
| MITRE ATLAS data | Adversarial ML tactics/techniques/case studies as YAML (machine-readable) | GitHub, Apache-2.0 | https://github.com/mitre-atlas/atlas-data (site: https://atlas.mitre.org/) | P6, P9 (tag events with ATLAS IDs), P11 |
| OWASP Top 10 for LLM Apps 2025 | LLM01 Prompt Injection ... LLM10 Unbounded Consumption | Web, CC-BY-SA | https://genai.owasp.org/llm-top-10/ | P11, P9 (map controls) |
| OWASP Top 10 for Agentic Applications 2026 | ASI01 Goal Hijack, ASI02 Tool Misuse, ASI03 Identity/Privilege, ASI04 Supply Chain, ASI05 RCE, ASI06 Memory Poisoning, ASI07 Inter-agent, ASI08 Cascading, ASI09 Trust, ASI10 Rogue | Web | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | P1, P4, P11 |
| AVID | AI vulnerability database / taxonomy | Web | https://avidml.org/ | P6, P11 |
| EU AI Act (Reg. 2024/1689) | Legal text: logging (Art. 12), human oversight (Art. 14), robustness/cybersecurity (Art. 15) | EUR-Lex, free. Returned 202 (bot challenge), known to exist | https://eur-lex.europa.eu/eli/reg/2024/1689/oj | P9 (compliance framing in pitch) |
| HF pickle security docs | Background on unsafe deserialization in model files | Web | https://huggingface.co/docs/hub/security-pickle | P6 |

**No dataset is required at runtime.** Use the sets above to:
- build a curated `tests/corpus/` of about 200-500 prompts,
- measure detection and false-positive rates,
- seed signature files.

---

## 4. Technologies

| Tech | Why | P# |
|---|---|---|
| **LiteLLM** (proxy, MIT outside `enterprise/`) | OpenAI-compatible gateway in front of Ollama and 100+ providers. It already has per-key budgets, rate limits, cost tracking and guardrail hooks. You can extend it instead of writing a proxy. https://github.com/BerriAI/litellm | P5, P7, P9 |
| **FastAPI** (own proxy) | If you write your own: an OpenAI-compatible `/v1/chat/completions` + MCP passthrough in about 300 LOC, with full control of the pipeline and latency. https://github.com/fastapi/fastapi | all |
| **Ollama** | Local models, required because there are no paid APIs. Pull a chat model (e.g. `qwen3`) plus guard models `llama-guard3`, `granite3-guardian`, `shieldgemma`. https://ollama.com/library/llama-guard3 | P8, P5 |
| **Llama Prompt Guard 2 (22M / 86M)** | Small DeBERTa injection/jailbreak classifier (gated, Llama license). The 22M version runs on CPU in ~10-20 ms, so it is the fast semantic layer. https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M | P2, P8 |
| **protectai/deberta-v3-base-prompt-injection-v2** | Apache-2.0 injection classifier with an ONNX export, 7.5M downloads. Use it if you want to avoid the Llama gate. https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2 | P2, P8 |
| **Qwen3Guard-Gen-0.6B** | Apache-2.0, small generative safety classifier for prompts and responses, with severity levels. That maps directly to "adherence %". https://huggingface.co/Qwen/Qwen3Guard-Gen-0.6B | P3, P8 |
| **Llama Guard 3 1B / Granite Guardian 3.3 8B** | Heavier semantic judges with policy taxonomies. Granite Guardian also covers RAG groundedness and function-call risk. Use as the slow tier or async audit. https://huggingface.co/ibm-granite/granite-guardian-3.3-8b | P3, P8 |
| **Microsoft Presidio** (MIT) | Deterministic + NER PII detection and anonymization, with custom recognizers (IBAN, PESEL, card numbers via Luhn). https://github.com/microsoft/presidio | P3 |
| **gitleaks / detect-secrets / trufflehog** | Secret regex sets (API keys, tokens) that you can lift into the output filter. https://github.com/gitleaks/gitleaks | P3 |
| **NeMo Guardrails** (Apache-2.0) | Colang dialog/topic rails plus input/output rails. A good reference, but heavy. Borrow ideas rather than adopt it. https://github.com/NVIDIA/NeMo-Guardrails | P2, P3 |
| **Guardrails AI** (Apache-2.0) | Validator hub (regex, PII, toxic, competitor mention...) with structured output validation. https://github.com/guardrails-ai/guardrails | P3 |
| **LLM Guard** (MIT, **archived Jul 2026**) | Ready-made input/output scanners (secrets, anonymize, invisible text, code). Still pip-installable, but do not build the core on it. https://github.com/protectai/llm-guard | P2, P3 |
| **OPA / Rego** or **Cedar** (Apache-2.0) | Declarative authorization: "agent X may call tool Y on resource Z". Hot-reloads policy bundles, which suits the live-config judging. https://github.com/open-policy-agent/opa, https://github.com/cedar-policy/cedar | P1, P7 |
| **MCP Python SDK** | Build an MCP proxy that intercepts `tools/list` and `tools/call`, applies allowlists and argument checks, and detects tool-description poisoning. https://github.com/modelcontextprotocol/python-sdk | P1, P2 |
| **mcp-scan** (Apache-2.0) | Scans MCP servers for tool poisoning and rug-pulls. Use as a reference or as a pre-flight control. https://github.com/invariantlabs-ai/mcp-scan | P1, P6 |
| **ModelScan / picklescan** | Detect unsafe deserialization (pickle opcodes `GLOBAL os.system`) in model files. This is the direct answer to "unsafe deserialization, supply-chain exploits targeting model repositories". https://github.com/protectai/modelscan, https://github.com/mmaitre314/picklescan | P6 |
| **OSV API** | Feed for the "externally managed signatures" requirement: check the agent's declared deps and model-repo loaders against live CVEs. https://osv.dev/ | P6 |
| **OpenTelemetry + Prometheus client** | Per-control latency spans, counters (blocked/redacted/allowed), token/cost gauges. This covers the "performance telemetry" the judges ask for. https://github.com/open-telemetry/opentelemetry-python | P9 |
| **Langfuse** (MIT core) / **Arize Phoenix** (**ELv2**) | LLM tracing UIs. Optional: a custom dashboard tells the story better, and Phoenix's ELv2 license is fine for a demo but note it. https://github.com/langfuse/langfuse | P9 |
| **Streamlit** or **Grafana** | Fastest dashboard route. Streamlit plus SQLite needs no setup. Grafana looks enterprise-grade but is AGPL and adds a stack. https://github.com/streamlit/streamlit | P9 |
| **promptfoo** (MIT) | Declarative red-team/eval runner with assertions in YAML. Can serve as the test suite, or alongside pytest. https://github.com/promptfoo/promptfoo | P10 |
| **garak** (Apache-2.0) | NVIDIA LLM vulnerability scanner with probes for DAN, encoding, injection, leakage. Run it against the gateway as an "independent attacker" demo. https://github.com/NVIDIA/garak | P10, P11 |
| **PyRIT** (MIT, `microsoft/PyRIT`) | Microsoft red-team orchestration (multi-turn attacks, converters such as base64/leetspeak). https://github.com/microsoft/PyRIT | P10 |
| **pytest** | Judges need "ready to run": `pytest -q` with parametrized allow/block cases is the lowest-friction option. | P10 |

---

## 5. Solution ideas

### Idea A: "Tollgate", a hybrid policy gateway with a live policy file (recommended core)

**Pitch.**
- An OpenAI-compatible reverse proxy (FastAPI) sits between any agent and any model (Ollama locally, commercial APIs via the same interface).
- A second listener proxies MCP `tools/call`.
- Every request goes through a pipeline of controls declared in **one `policy.yaml`**, which is hot-reloaded through a file watcher.
- **Tier 0 (deterministic, under 2 ms):**
  - API-key → agent identity → RBAC (allowed models, tools, data scopes)
  - regex/Luhn/IBAN PII and secrets
  - signature match against the external feed
  - token/cost/loop budgets
- **Tier 1 (fast semantic, ~15 ms):** Prompt Guard 2 22M or the ProtectAI DeBERTa injection classifier.
- **Tier 2 (deep semantic, escalation only):** Qwen3Guard / Llama Guard via Ollama. It runs only when Tier 1 is uncertain or the policy asks for `strict`.
- Each control has a mode `off|monitor|redact|block` and a threshold.
- Each named profile (`dev`, `standard`, `strict`) changes modes and thresholds. This is exactly the "strictness/adherence levels" deliverable.
- Every decision becomes a JSONL audit event tagged with OWASP LLM/ASI and MITRE ATLAS IDs, plus an OTel span.

**Hits:** P1-P10, all five criteria. The latency-tiered design is the "Architecture and performance efficiency" story.

**Stack:** FastAPI, httpx, Ollama, transformers/ONNX Runtime (Prompt Guard), Presidio (or plain regex), PyYAML + watchdog, SQLite, Streamlit, pytest, Prometheus client.

**MVP (~20h, 4 people):**
- Dev 1: proxy + pipeline + policy loader/hot reload.
- Dev 2: deterministic controls (PII/secrets/RBAC/budgets/loop detection by repeated-call hashing).
- Dev 3: semantic tiers + signature feed (OSV pull plus a local `signatures.yaml` of known jailbreak strings and RCE patterns such as `__import__('os')`, `pickle.loads`, `PALChain`).
- Dev 4: dashboard + pytest corpus (~150 cases from deepset/Lakera/JBB + hand-written finance PII) + slides.

**Demo moment:**
1. A judge types a jailbreak and gets blocked. The dashboard ticks up and shows the OWASP tag and which tier caught it, with its latency.
2. The judge edits `policy.yaml`, switching `pii.mode: block → redact` or dropping the budget to $0.01.
3. With no restart, the next request is redacted or gets a 429 budget exhaustion.
4. `pytest` prints green on 150 cases.

**Risks:**
- Semantic false positives on benign finance prompts. Mitigation: a WildJailbreak contrastive-benign set in the tests, and tunable thresholds.
- Gated Llama models. Mitigation: fall back to the ProtectAI Apache model.
- CPU latency of Tier 2. Mitigation: escalation only, plus an async "monitor" mode.

### Idea B: "AgentPassport", identity and least-privilege for agent↔MCP traffic

**Pitch.**
- Focuses on P1/P4 and OWASP ASI02/03/06.
- Each agent gets a signed short-lived token (JWT) with capability scopes.
- An MCP proxy enforces, through OPA/Cedar:
  - tool allowlists
  - argument constraints (e.g. `transfer.amount <= 1000`, no `rm -rf`, path jail)
  - human-in-the-loop for irreversible actions
  - read scopes on shared memory/vector stores
- It also detects tool-description poisoning and rug-pulls (description hash pinning, as mcp-scan does), and loop/recursion depth per trace.

**Hits:** P1, P4, P7, P11. Strong on robustness and novelty, weaker on budget/reporting unless you add them.

**Stack:** MCP Python SDK, OPA (sidecar) or cedarpy, PyJWT, AgentDojo banking suite as the attack harness.

**MVP:**
- An MCP proxy over 2-3 demo tools (fake bank: `get_balance`, `transfer`, `read_email`).
- A Rego policy.
- AgentDojo-style injected email that tries to make the agent call `transfer`. It gets blocked by policy even though the LLM was fooled.

**Demo moment:** the LLM falls for the injection, and the layer still stops the transfer. That proves defense in depth beyond prompt classifiers.

**Risks:**
- Narrower scope than the brief, so it must be combined with A to cover budgets and dashboard.
- MCP protocol edge cases eat hours.

### Idea C: "Supply-Chain Sentinel", a historical-exploit and signature feed service

**Pitch.**
- Treat P6 literally. A separate "threat intel" microservice publishes a versioned signature bundle that the gateway pulls on a timer. This is the "externally managed system".
- The bundle merges:
  - OSV/GHSA advisories for AI libraries (langchain, transformers, ray, mlflow, llama-index)
  - jailbreak fingerprints (normalized n-gram/MinHash signatures from in-the-wild-jailbreak-prompts and DAN variants)
  - code-exec patterns in tool arguments and outputs
  - pickle-opcode rules
- The gateway scans:
  - prompts
  - tool arguments
  - **model downloads** (via ModelScan/picklescan) before a local model is loaded
  - agent dependency manifests

**Hits:** P6, P11, and the "Robustness" criterion. A differentiator most teams will hand-wave.

**Stack:** FastAPI feed server, OSV API, datasketch (MinHash), picklescan/modelscan, a malicious-pickle PoC file you craft yourselves.

**MVP:**
- A feed endpoint plus pull/verify (sha256 signed bundle).
- 3 detectors: jailbreak fuzzy-hash, code-exec regex, pickle scan.

**Demo moment:**
1. Load a "model" `.pkl` that would spawn a shell. The gateway refuses it and cites the advisory.
2. Push a new signature to the feed. Within 10 s the previously-allowed prompt is blocked.

**Risks:** standalone it does not satisfy the full brief. It is best as a module of A.

### Idea D: "CFO Mode", budget and runaway-agent governor

**Pitch.**
- Hierarchical budgets (org → team → agent → session) in tokens, dollars and **GPU-seconds for local models** (measured wall-clock × configured $/s rate).
- Enforced by:
  - pre-flight token estimation
  - a streaming cut-off when the budget is hit mid-response
  - circuit breakers on loops (same tool + same args N times, depth > K, burst rate)
  - model downgrade routing (soft limit → cheaper/local model; hard limit → block)
- The dashboard shows burn-down per agent and forecasted exhaustion.

**Hits:** P4, P5, P9. A management-friendly reporting story.

**Stack:** LiteLLM proxy budgets/keys as the base + custom callback for local-model compute cost, Redis or SQLite counters, Streamlit.

**MVP:** LiteLLM config with 3 virtual keys + a custom hook + a runaway-loop demo agent.

**Demo moment:** a deliberately looping agent gets auto-downgraded to a local model, then cut off. The chart shows the spike and the stop.

**Risks:**
- LiteLLM internals and enterprise-only features (some guardrail/budget features are gated under `enterprise/`). Verify early, or implement the counters yourselves.

### Idea E: "Red Team in a Box", a continuous self-test and posture score

**Pitch.**
- Make P10 a product, not an afterthought.
- `pytest` plus promptfoo/garak suites run against the live gateway on every policy change.
- The output is a **posture score**: per-control TPR/FPR on curated corpora (JBB benign/harmful, deepset, gretel finance PII), mapped to OWASP LLM/ASI coverage.
- A policy change that drops the score triggers a warning before reload ("policy CI").

**Hits:** P10, P9, P7. Lifts the suite criterion (15-20%) and reporting (20%).

**Stack:** pytest-parametrize over JSONL corpora, promptfoo YAML, garak probes (encoding, dan, promptinject), results to SQLite → dashboard tab.

**MVP:**
- 200 labeled cases.
- A confusion matrix per control.
- A coverage heatmap OWASP × control.

**Demo moment:**
1. A judge disables the injection control in `policy.yaml`.
2. The dashboard posture drops from 94% to 61% in real time.
3. The ASI01 cell turns red.

**Risks:** it is only a wrapper around a gateway, so it needs A.

### Recommendation

Build **A as the spine, with E's posture score and a slice of C's live signature feed bolted on.** Use B's MCP tool-argument policy only if time allows (stretch: one Rego rule on a fake `transfer` tool).

Why:
- A alone hits every formal requirement (P1-P10), and every one of those is checked.
- The tiered deterministic → small classifier → LLM judge pipeline, with per-tier latency in telemetry, scores directly on robustness (30%) and architecture/performance (20%).
- E turns the test suite (15-20%) and reporting (20%) into a visible live score. It also answers the judges' "we'll modify your config" test better than anyone else, because you show the impact of their change.
- C's signed external feed is the only credible answer to P6, which most teams will skip.
- Keep it Python, local Ollama, and one `policy.yaml`. Write the README section "judge quick start: `docker compose up && pytest`" first.
