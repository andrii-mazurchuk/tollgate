"""Mock tickets MCP server: support tickets in an in-memory SQLite. `query` is dual-use (reads and writes)."""
import sqlite3

from fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("tickets")

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.executescript("""
CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT);
CREATE TABLE tickets (id INTEGER PRIMARY KEY, customer_id INTEGER, subject TEXT, body TEXT, reply TEXT);
CREATE TABLE faq (id INTEGER PRIMARY KEY, question TEXT, answer TEXT);
INSERT INTO customers VALUES (1, 'Jan Kowalski', 'jan@acme.pl'), (2, 'Anna Nowak', 'anna@acme.pl');
INSERT INTO tickets VALUES (1, 1, 'Login fails', 'I cannot log in since Monday.', NULL),
                           (2, 2, 'Invoice', 'Please resend my last invoice.', NULL);
INSERT INTO faq VALUES (1, 'How do I reset my password?', 'Use the "Forgot password" link.');
""")


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def read(id: int) -> str:
    """Read a ticket."""
    row = DB.execute("SELECT subject, body FROM tickets WHERE id = ?", (id,)).fetchone()
    return f"#{id} {row[0]}\n\n{row[1]}" if row else f"Ticket #{id} not found."


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
def reply(id: int, text: str) -> str:
    """Reply to a ticket."""
    DB.execute("UPDATE tickets SET reply = ? WHERE id = ?", (text, id))
    return f"Replied to ticket #{id}."


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
def query(sql: str) -> list[list]:
    """Run SQL against the tickets database (tables: tickets, customers, faq)."""
    return [list(r) for r in DB.execute(sql).fetchall()]
