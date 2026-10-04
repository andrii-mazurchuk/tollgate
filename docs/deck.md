---
marp: true
size: 16:9
paginate: true
footer: "Tollgate · github.com/andrii-mazurchuk/tollgate"
---

<style>
:root { --ink: #0f172a; --mute: #64748b; --line: #cbd5e1; --soft: #f1f5f9; --blue: #2563eb; --bluebg: #eff6ff; --red: #dc2626; --redbg: #fef2f2; }
section {
  background: #fff; color: var(--ink);
  font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  font-size: 28px; line-height: 1.25;
  padding: 40px 60px 50px;
  display: flex !important; flex-direction: column !important; justify-content: center !important;
}
h1 { font-size: 54px; line-height: 1.1; margin: 0 0 22px; color: var(--ink); font-weight: 800; }
h1 em { font-style: normal; color: var(--blue); }
h1 .r { color: var(--red); }
.kick { font-size: 22px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; color: var(--mute); margin: 0 0 8px; }
.tag { position: absolute; top: 26px; right: 40px; font-size: 14px; font-weight: 700; letter-spacing: .08em; color: var(--mute);
  border: 1.5px solid var(--line); border-radius: 5px; padding: 2px 8px; }
.big { font-size: 42px; line-height: 1.2; font-weight: 700; margin: 18px 0 0; }
.mute { color: var(--mute); }
.blue { color: var(--blue); } .red { color: var(--red); }
footer { color: #94a3b8; font-size: 14px; left: 60px; }
section::after { color: #94a3b8; font-size: 14px; }
code { background: var(--soft); color: var(--ink); border-radius: 6px; padding: 2px 10px; }
section img { border: 1px solid var(--line); border-radius: 10px; box-shadow: 0 4px 18px rgba(15,23,42,.10); }

/* call chain */
.chain { display: flex; gap: 14px; align-items: stretch; }
.call { flex: 1; border: 3px solid var(--line); border-radius: 14px; padding: 16px 18px; background: var(--soft); }
.call .n { font-size: 22px; color: var(--mute); font-weight: 800; }
.call .t { font-size: 32px; font-weight: 700; margin: 4px 0 10px; line-height: 1.15; }
.call .v { font-size: 28px; font-weight: 800; color: var(--blue); }
.call.bad { border-color: var(--red); background: var(--redbg); }
.call.bad .v { color: var(--red); }
.arr { align-self: center; font-size: 40px; color: var(--mute); }

/* leaked PR */
.pr { margin-top: 20px; border: 3px solid var(--red); border-radius: 14px; background: var(--redbg); padding: 14px 22px; }
.pr .h { font-size: 22px; font-weight: 800; color: var(--red); letter-spacing: .06em; }
.pr .b { font-family: Consolas, "Courier New", monospace; font-size: 28px; line-height: 1.4; margin-top: 6px; }
.x { background: var(--ink); color: var(--ink); border-radius: 3px; }

/* incident grid */
.grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; }
.inc { border: 2px solid var(--line); border-radius: 14px; padding: 14px 18px; background: var(--soft); }
.inc .d { font-size: 20px; color: var(--mute); font-weight: 700; }
.inc .p { font-size: 30px; font-weight: 800; margin: 2px 0 6px; }
.inc .h { font-size: 26px; line-height: 1.2; color: var(--red); font-weight: 600; }
.inc .w { font-size: 16px; color: var(--mute); margin-top: 6px; text-transform: uppercase; letter-spacing: .08em; }

/* boxes / architecture */
.row { display: flex; gap: 18px; align-items: stretch; }
.box { flex: 1; border: 3px solid var(--line); border-radius: 16px; padding: 20px 22px; background: var(--soft); font-size: 26px; }
.box b { display: block; font-size: 34px; margin-bottom: 8px; }
.box.tg { border-color: var(--blue); background: var(--bluebg); flex: 1.2; }
.box.tg b { color: var(--blue); }
.badge { display: inline-block; font-size: 22px; font-weight: 700; border-radius: 999px; padding: 4px 14px; margin: 4px 6px 4px 0;
  border: 2px solid var(--blue); color: var(--blue); background: #fff; }
.badge.soon { border: 2px dashed var(--line); color: var(--mute); }

/* metrics */
.m { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 18px 30px; }
.m div b { display: block; font-size: 64px; line-height: 1.05; font-weight: 800; }
.m div span { font-size: 22px; color: var(--mute); }
.m .miss b { color: var(--mute); }
.m .miss { border-left: 4px dashed var(--line); padding-left: 14px; }

/* keyword list */
.kw { font-size: 34px; line-height: 1.25; margin: 0; padding: 0; list-style: none; }
.kw li { margin: 0 0 16px; } .kw li b { color: var(--blue); }
.kw li span { display: block; font-size: 22px; color: var(--mute); font-weight: 400; }
.kw.tight { font-size: 28px; } .kw.tight li { margin: 0 0 8px; } .kw.tight li span { font-size: 19px; }
</style>

<!-- 1 · ONE INCIDENT -->

<p class="kick">May 2025 · GitHub MCP · Claude</p>

# One public issue. <span class="r">Private life, published.</span>

<div class="chain">
<div class="call"><div class="n">1</div><div class="t">Read issue in public repo</div><div class="v">✓ allowed</div></div>
<div class="arr">→</div>
<div class="call"><div class="n">2</div><div class="t">Read owner's private repos</div><div class="v">✓ allowed</div></div>
<div class="arr">→</div>
<div class="call"><div class="n">3</div><div class="t">Open public pull request</div><div class="v">✓ allowed</div></div>
</div>

<div class="pr"><div class="h">PUBLIC PULL REQUEST #2 · "ABOUT THE AUTHOR"</div><div class="b">
private repo&nbsp; <b>J██████ Star</b><br>
moving to&nbsp;&nbsp;&nbsp; <b>South Am█████</b><br>
salary&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <b>$███,███</b>
</div></div>

---

<!-- 2 · IT KEEPS HAPPENING -->

# It keeps happening.

<div class="grid">
<div class="inc"><div class="d">MAY 2025</div><div class="p">GitHub MCP</div><div class="h">Private repos leaked into public PR</div><div class="w">research demo</div></div>
<div class="inc"><div class="d">JUL 2025</div><div class="p">Supabase MCP</div><div class="h">Support ticket pulled out secret tokens</div><div class="w">research demo</div></div>
<div class="inc"><div class="d">JUL 2025</div><div class="p">Replit Agent</div><div class="h">Production database deleted during code freeze</div><div class="w">in the wild</div></div>
<div class="inc"><div class="d">JUL 2025</div><div class="p">Amazon Q · VS Code</div><div class="h">Shipped prompt: wipe disk and cloud</div><div class="w">in the wild · v1.84.0</div></div>
<div class="inc"><div class="d">JUL 2025</div><div class="p">Gemini CLI</div><div class="h">README silently sent credentials away</div><div class="w">research demo · fixed</div></div>
<div class="inc"><div class="d">SEP 2025</div><div class="p">postmark-mcp</div><div class="h">Every email secretly BCC'd to attacker</div><div class="w">in the wild · 1,643 installs</div></div>
</div>

---

<!-- 3 · THE GAP -->

<p class="kick">The gap</p>

# Each call is fine. <em>The sequence is the attack.</em>

<div class="chain">
<div class="call"><div class="n">READS</div><div class="t">Outsider text</div><div class="v">untrusted</div></div>
<div class="arr">+</div>
<div class="call"><div class="n">READS</div><div class="t">Private data</div><div class="v">private</div></div>
<div class="arr">+</div>
<div class="call bad"><div class="n">WRITES</div><div class="t">Somewhere public</div><div class="v">= leak</div></div>
</div>

<p class="big mute">Permissions check calls one by one. Nobody watches the session.</p>

---

<!-- 4 · TOLLGATE -->

<div class="tag">ARCHITECTURE · 20%</div>

<p class="kick">Tollgate</p>

# Every agent call <em>passes one gate.</em>

<div class="row">
<div class="box"><b>Agents</b>Claude Code<br>any MCP client</div>
<div class="arr">→</div>
<div class="box tg"><b>Tollgate</b>tools per role<br>content check, local<br>session data flow</div>
<div class="arr">→</div>
<div class="box"><b>Tools & models</b>GitHub, databases, files<br>LLMs</div>
</div>

<p class="big mute">One policy file. One MCP server per role.</p>

---

<!-- 5 · SAME ATTACK, STOPPED -->

<div class="tag">ROBUSTNESS · 30%</div>

# Same attack. <span class="r">Stopped at step 3.</span>

![w:1100](img/deck2-steps.png)

<p class="big">“The session read outsiders' text and holds private data, so sending data out could leak it.”</p>

---

<!-- 6 · HOW IT'S USED. Connectivity wording lives ONLY in the badge block below: move a name from .soon to plain when it ships. -->

<div class="tag">IMPLEMENTABILITY · 10%</div>

<p class="kick">Day to day</p>

# Enroll once. <em>Then just work.</em>

<div class="row">
<div class="box"><b>1 · Enroll</b>laptop joins once<br>admin picks its roles</div>
<div class="arr">→</div>
<div class="box" style="flex:1.35"><b>2 · Connect</b><code style="font-size:24px;white-space:nowrap">tollgate connect claude-code</code></div>
<div class="arr">→</div>
<div class="box tg"><b>3 · Work</b>every tool call checked<br>you see only the blocks</div>
</div>

<div style="margin-top:26px">
<span class="badge">✓ Claude Code</span><span class="badge">✓ Codex</span><span class="badge">✓ Cursor</span><span class="badge">✓ Gemini CLI</span><span class="badge">✓ Hermes</span><span class="badge">✓ any MCP server</span>
</div>
<p class="mute" style="font-size:24px;margin:10px 0 0">Built-in tools too: shell, files, web. Via hooks.</p>

---

<!-- 7 · SECURITY TEAM'S VIEW -->

<div class="tag">SECURITY REPORTING · 20%</div>

# Every laptop. Every agent. <em>Every block.</em>

![w:1000](img/deck2-map.png)

<div class="row" style="align-items:center; margin-top:10px">
<div style="flex:1">
<p class="big" style="margin:0">Text never leaves the laptop.</p>
<p class="mute" style="font-size:26px;margin:0">Server keeps the decision + a fingerprint.</p>
</div>
</div>

---

<!-- 8 · PROOF -->

<div class="tag">SELF-TEST SUITE · 20% · PERFORMANCE · 20%</div>

# Proof: <code style="font-size:44px">uv run tollgate test</code>

<div class="m">
<div><b>377</b><span>fast tests · +7 slow</span></div>
<div><b>1,411</b><span>eval cases · 30% held out</span></div>
<div><b>&lt; 1 ms</b><span>hub checks, p95</span></div>
<div><b class="blue">0.967</b><span>PII recall</span></div>
<div><b class="blue">0.009</b><span>injection false positives</span></div>
<div class="miss"><b>0.837</b><span>injection recall · <b style="display:inline;font-size:22px;color:var(--ink)">missed</b> target 0.85</span></div>
</div>

<p class="mute" style="font-size:24px;margin-top:22px">All checks: FPR 0.048 · posture 0.931 · tier 1 p95 ~2.5 ms. Taint catches what text checks miss.</p>

---

<!-- 9 · WHY IT'S SECURE + WHO BUYS -->

<div class="tag">SECURITY · SCALABILITY · 10%</div>

<div class="row" style="gap:50px">
<div style="flex:1.1">
<p class="kick">Why it holds</p>
<ul class="kw tight">
<li><b>Fails closed</b><span>hub down or bad key = call denied</span></li>
<li><b>Per-install secrets</b><span>no shared default keys</span></li>
<li><b>Signed threat feed</b><span>tampered bundle rejected</span></li>
<li><b>Key per agent launch</b><span>revoke laptop = all its keys dead</span></li>
<li><b>Console accounts</b><span>Admin / Viewer, every change attributed</span></li>
<li><b>Company-wide</b><span>enforced via managed settings</span></li>
</ul>
</div>
<div style="flex:1">
<p class="kick">Who buys</p>
<ul class="kw">
<li>Security teams rolling out coding agents</li>
<li>Banks, fintech, regulated industries</li>
<li>Anyone letting agents near private data</li>
</ul>
</div>
</div>

---

<!-- 10 · TRY IT -->

<div class="tag">IMPLEMENTABILITY · 10%</div>

# Try it in <em>5 minutes.</em>

<div class="box" style="font-family:Consolas,'Courier New',monospace; font-size:32px; line-height:1.55; flex:none">
uv sync<br>
uv run tollgate up --scripted-model<br>
uv run tollgate test<br>
<span class="mute">→ open /console and /edge</span>
</div>

<p class="big"><em class="blue" style="font-style:normal">github.com/andrii-mazurchuk/tollgate</em> <span class="mute" style="font-size:28px">· public · MIT</span></p>

<p class="mute" style="font-size:26px;margin-top:14px">Next: edge/hub split + policy sync · model door v2 (Anthropic, streaming)<br>budgets in money · memory controls · SSO</p>

<!--
SOURCES (checked 2026-10-04)
1  GitHub MCP, Invariant Labs, 2025-05-26: issue in public repo ukend0464/pacman ("About The Author" injection) made Claude Desktop (GitHub MCP, "Always Allow") read private repos and open public PR #2 with private repo "Jupiter Star", plan to relocate to South America, salary.
   https://invariantlabs.ai/blog/mcp-github-vulnerability
   https://simonwillison.net/2025/May/26/github-mcp-exploited/
2  Supabase MCP, General Analysis, 2025-07-08: support ticket instructions → Cursor agent with service_role (bypasses RLS) read integration_tokens and wrote them back into the ticket.
   https://www.generalanalysis.com/blog/supabase-mcp-blog
3  Replit Agent, 2025-07-18: deleted SaaStr (Jason Lemkin) production DB (1,206 executives, 1,196 companies) during an explicit code freeze.
   https://www.theregister.com/2025/07/22/replit_saastr_response/
   https://www.heise.de/en/news/Artificial-intelligence-Vibe-coding-service-Replit-deletes-production-database-10499597.html
4  Amazon Q Developer for VS Code v1.84.0, released 2025-07-17 with an injected prompt to "clean a system to a near-factory state and delete file-system and cloud resources"; AWS: malformed, not executed; fixed in 1.85.
   https://www.bleepingcomputer.com/news/security/amazon-ai-coding-agent-hacked-to-inject-data-wiping-commands/
5  Gemini CLI, Tracebit, disclosed 2025-07-28 (fixed v0.1.14, 2025-07-25): README prompt injection + allow-listed "grep" prefix → silent env | curl credential exfiltration.
   https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack
6  postmark-mcp (npm), Koi Security, Sep 2025: v1.0.16 (2025-09-17) added a BCC of every email to phan@giftshop[.]club; 1,643 downloads.
   https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html
   https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/
-->
