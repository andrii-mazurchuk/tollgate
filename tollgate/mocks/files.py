"""Mock files MCP server over a dict-backed fake filesystem."""
from fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("files")

FS: dict[str, str] = {
    "/workspace/a.txt": "hello from the workspace\n",
    "/workspace/notes/todo.md": "- ship tollgate\n",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def fs_list(path: str) -> list[str]:
    """List files under a directory."""
    prefix = path.rstrip("/") + "/"
    return sorted(p for p in FS if p.startswith(prefix))


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def fs_read(path: str) -> str:
    """Read a file."""
    if path not in FS:
        raise ValueError(f"no such file: {path}")
    return FS[path]


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
def fs_write(path: str, content: str) -> str:
    """Write a file."""
    FS[path] = content
    return f"wrote {len(content)} bytes to {path}"


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
def fs_delete(path: str) -> str:
    """Delete a file."""
    FS.pop(path, None)
    return f"deleted {path}"
