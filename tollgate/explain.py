"""Plain-English explanations for the edge UI: rule ID -> (why, what you can do), tool -> short human name.

Every rule ID the gateway or content pipeline can emit has an entry (tests/test_explain.py greps for them).
"""
from urllib.parse import quote

AGENTS = {"role-1": "Intern bot", "role-2": "Support assistant"}

TOOLS = {
    "github.issues.read": "Read an issue",
    "github.repo.read": "Read a file from a repository",
    "github.pr.create": "Open a pull request",
    "tickets.read": "Read a support ticket",
    "tickets.reply": "Reply to a support ticket",
    "tickets.query": "Query the support database",
    "files.fs.list": "List files",
    "files.fs.read": "Read a file",
    "files.fs.write": "Write a file",
    "files.fs.delete": "Delete a file",
    # the agent's own tools, seen through POST /hook
    "builtin.Bash": "Run a shell command",
    "builtin.Read": "Read a file on the laptop",
    "builtin.Write": "Write a file on the laptop",
    "builtin.Edit": "Edit a file on the laptop",
    "builtin.Grep": "Search files on the laptop",
    "builtin.Glob": "Find files on the laptop",
    "builtin.WebFetch": "Fetch a web page",
    "builtin.WebSearch": "Search the web",
    "builtin.Prompt": "Send a prompt to the agent",
}

_ADMIN = "Ask your security lead to change the policy if this is needed for your work."
_DATA = "Nothing to do: the data reached your agent with the sensitive parts masked."
_FLAG = "Nothing to do now. Be careful with what your agent does next: it has read this text."
_SECRET = "Remove the secret from the text, or ask your security lead if it must be shared."

# rule -> (why, what you can do)
RULES: dict[str, tuple[str, str]] = {
    # role / key / policy
    "auth.invalid": ("The key was missing or not valid.", "Copy the key again from Setup."),
    "role.denied": ("This tool is not available to your agent's role.", _ADMIN),
    "role.builtin_denied": ("Your agent's role may not use this built-in tool.", _ADMIN),
    "role.constraint": ("The arguments are outside what your role allows (for example a path or a query type).",
                        "Change the request to stay inside the allowed limits."),
    "role.approval": ("This tool needs a person to approve each use.", "Wait for the approval, or ask your security lead."),
    "pin.changed": ("The tool's description changed since the gateway started, which can mean a tampered server.",
                    "Tell your security lead; the gateway must be restarted to trust the tool again."),
    "loop.cutoff": ("Your agent repeated the same call too many times in a row.",
                    "Check whether your agent is stuck in a loop, then start a new session."),
    "taint.flow": ("The session read text written by outsiders and also holds private data, so sending data out "
                   "could leak it.", "Start a new session (new key) for this task, without reading untrusted text."),
    # model door
    "model.denied": ("This model is not allowed for your role.", "Use one of the models listed for your role."),
    "budget.exceeded": ("Your role used up today's token budget.", "Wait until tomorrow (UTC) or ask for a larger budget."),
    "upstream.error": ("The model server did not answer.", "Check that the model server (Ollama) is running."),
    "request.invalid": ("The request was not in the expected format.", "Send {model, messages: [...]} as JSON."),
    "request.stream": ("Streaming replies are not supported yet.", "Send stream: false."),
    # content pipeline
    "content.blocked": ("The text contained something the content check blocks.", "Remove the blocked item from the text and try again."),
    "content.redact_failed": ("Sensitive data could not be masked safely, so the call was stopped.",
                              "Send the data in a simpler format."),
    "content.truncated": ("The text was very long, so only its start and end were checked.",
                          "Nothing to do; send shorter text for a full check."),
    "content.error": ("The content check failed internally and let the text through.", "Tell your security lead."),
    "pii.iban": ("A bank account number (IBAN) was found.", _DATA),
    "pii.pesel": ("A Polish national ID number (PESEL) was found.", "Remove the ID number from the text."),
    "pii.nip": ("A Polish tax number (NIP) was found.", _DATA),
    "pii.card": ("A payment card number was found.", _DATA),
    "pii.email": ("An email address was found.", _DATA),
    "pii.email_obf": ("A disguised email address was found.", _DATA),
    "secret.private_key": ("A private key was found.", _SECRET),
    "secret.github_token": ("A GitHub token was found.", _SECRET),
    "secret.github_pat": ("A GitHub access token was found.", _SECRET),
    "secret.slack_token": ("A Slack token was found.", _SECRET),
    "secret.aws_key": ("An AWS access key was found.", _SECRET),
    "secret.kv": ("A password or credential was found.", _SECRET),
    "secret.entropy": ("A long random-looking token, probably a secret, was found.", _SECRET),
    "inj.md_exfil": ("An image link that could send data to an outside server was found.",
                     "Do not render this text as markdown."),
    "inj.html_exfil": ("An HTML image that could send data to an outside server was found.",
                       "Do not render this text as HTML."),
    "inj.ref_exfil": ("A hidden image link that could send data out was found.", "Do not render this text as markdown."),
    "inj.ignore_prev": ("The text tries to make the AI ignore its instructions.", _FLAG),
    "inj.ignore_prev_pl": ("The text (in Polish) tries to make the AI ignore its instructions.", _FLAG),
    "inj.role_switch": ("The text tries to take over the AI's role.", _FLAG),
    "inj.hide_from_user": ("The text tells the AI to hide something from you.", _FLAG),
    "sig.": ("The text matches a known attack from the threat feed.", "Do not use this text; tell your security lead."),
    "t2.injection": ("The injection check found hidden instructions aimed at the AI.", _FLAG),
    "t2.suspect": ("The injection check found text that may contain instructions aimed at the AI.", _FLAG),
    "t2.deferred": ("The text was long, so the injection check skipped it; the data-flow check still applies.",
                    "Nothing to do."),
    "t2.sampled": ("The text was long, so the injection check looked at parts of it.", "Nothing to do."),
    "t2.unavailable": ("The injection check was not loaded; the other checks still ran.",
                       "Nothing to do; it loads on first use."),
    # approvals
    "approval.requested": ("The call is waiting for a person to approve it.", "Wait; it times out if nobody answers."),
    "approval.approved": ("A person approved this call.", "Nothing to do."),
    "approval.denied": ("A person denied this call.", "Ask your security lead why, or change the task."),
    "approval.timeout": ("Nobody approved the call in time, so it was stopped.", "Try again when someone can approve it."),
}

FALLBACK = ("A Tollgate check flagged this call.", "See the technical details.")
# rules that only add information; they are not the reason for a verdict
INFO = ("t2.deferred", "t2.sampled", "t2.unavailable", "content.truncated")


def rule(rule_id: str) -> tuple[str, str]:
    if rule_id in RULES:
        return RULES[rule_id]
    head = rule_id.split(".")[0] + "."
    return RULES.get(head, FALLBACK)


def tool(name: str | None, door: str = "tool") -> str:
    if door == "model":
        return f"Chat with the model {name}"
    return TOOLS.get(name or "", (name or "unknown tool").replace(".", " "))


STATE = {"clean": "Clean", "untrusted": "Untrusted", "holds_private": "Holds private data"}


def state_words(state: str | None) -> list[str]:
    return [STATE[s] for s in (state or "clean").split("+") if s in STATE]


def effect(before: str | None, after: str | None) -> str:
    b, a = set((before or "clean").split("+")), set((after or "clean").split("+"))
    new = a - b - {"clean"}
    if not new:
        return "No change to the session."
    parts = {"untrusted": "is now Untrusted: it read text written by outsiders",
             "holds_private": "now holds private data"}
    return "The session " + " and ".join(parts[s] for s in ("untrusted", "holds_private") if s in new) + "."


VERB = {"allow": "went through", "redact": "went through with sensitive data masked", "block": "was blocked",
        "approve": "needed a person's approval"}


def main_reason(ev: dict) -> dict | None:
    """The reason that decided the verdict: blocking/approval reasons first, then flags, never pure info."""
    rs = [r for r in ev.get("reasons") or [] if r.get("rule") not in INFO]
    for pref in (("taint.", "role.", "pin.", "loop.", "model.", "budget.", "approval.", "upstream.", "request.",
                  "content.blocked"), ("secret.", "pii.", "sig."), ("inj.", "t2.")):
        for r in rs:
            if r.get("rule", "").startswith(pref):
                return r
    return rs[0] if rs else None


def event(ev: dict) -> dict:
    """{sentence, why, todo, effect, tool_name, rules} for one audit event dict."""
    name = tool(ev.get("tool"), ev.get("door", "tool"))
    v = ev.get("verdict", "allow")
    r = main_reason(ev)
    why, todo = rule(r["rule"]) if r else ("Every check passed.", "Nothing to do.")
    sentence = f"{name}: {VERB.get(v, v)}."
    if v == "allow" and r and r["rule"].startswith(("inj.", "t2.")):
        sentence = f"{name}: went through, flagged as containing hidden instructions."
    return {"sentence": sentence, "why": why, "todo": todo, "tool_name": name,
            "effect": effect(ev.get("state_before"), ev.get("state_after")),
            "rules": [x.get("rule") for x in ev.get("reasons") or []]}


# check that produced a rule, for "Data-flow rule: blocked" (most specific prefix first)
CHECKS = (("taint.", "Data-flow rule"), ("role.constraint", "Argument check"), ("role.approval", "Approval rule"),
          ("role.", "Role check"), ("auth.", "Key check"), ("pin.", "Tool pin check"), ("loop.", "Loop guard"),
          ("model.", "Model check"), ("budget.", "Budget"), ("approval.", "Approval"), ("secret.", "Secret detector"),
          ("pii.", "Personal-data detector"), ("sig.", "Threat feed"), ("inj.", "Injection check"),
          ("t2.", "Injection check"), ("content.", "Content check"), ("upstream.", "Model server"),
          ("request.", "Request check"))


def check_name(rule_id: str | None) -> str:
    return next((name for pref, name in CHECKS if (rule_id or "").startswith(pref)), "Tollgate check")


def details_url(base: str, session_id: str, trace_id: str | None = None, ui: str = "edge") -> str:
    """Link to one step in the local edge/console; hash route matches stepHref/sessHref (encodeURIComponent)."""
    q = lambda s: quote(str(s), safe="-_.!~*'()")  # noqa: E731 - encodeURIComponent's unreserved set
    return f"{base.rstrip('/')}/{ui}/#/sessions/{q(session_id)}" + (f"/{q(trace_id)}" if trace_id else "")


def next_step(rule_id: str | None, base: str | None, session_id: str, trace_id: str) -> str:
    """' What you can do: <todo> Details: <url>' appended to a deny message (no link without a base URL)."""
    out = f" What you can do: {rule(rule_id)[1]}" if rule_id else ""
    return out + (f" Details: {details_url(base, session_id, trace_id)}" if base else "")
