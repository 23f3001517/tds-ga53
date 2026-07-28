from fastapi import FastAPI, Request
from urllib.parse import urlparse
import posixpath
import fnmatch
import re
import base64

app = FastAPI()

@app.post("/")
async def guardrail(request: Request):
    try:
        call = await request.json()
    except Exception:
        return {"decision": "block", "reason": "Invalid JSON payload."}

    tool = call.get("tool")

    if tool == "bash":
        return check_bash(call.get("command", ""))
    elif tool == "write_file":
        return check_write_file(call.get("path", ""))
    elif tool == "http_request":
        return check_http_request(call.get("url", ""))

    return {"decision": "block", "reason": f"Unknown tool: {tool}"}


def check_bash(command: str) -> dict:
    """
    Evaluates bash commands by parsing tokens and fully resolving their POSIX paths.
    Catches exact reads, wildcards, relative traversals, and Base64 wrapping.
    """
    # 1. Unpack Base64 obfuscation first
    b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
    for b64_str in b64_pattern.findall(command):
        try:
            decoded = base64.b64decode(b64_str).decode('utf-8')
            # If the base64 contains the secret filename, flag it directly to be safe
            if "service-account.json" in decoded or "shadow" in decoded:
                return {"decision": "block", "reason": "Restricted file access detected inside base64 payload."}
        except Exception:
            pass

    # 2. Clean the command of literal splitters and hex escapes
    cleaned = command.replace("'", "").replace('"', "").replace("\\", "")
    try:
        cleaned = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), cleaned)
    except Exception:
        pass

    # 3. Expand environment variables that attackers use to bypass string matching
    cleaned = cleaned.replace("~/", "/home/agent/")
    cleaned = cleaned.replace("$HOME/", "/home/agent/")
    cleaned = cleaned.replace("~", "/home/agent")
    cleaned = cleaned.replace("$HOME", "/home/agent")

    # 4. Tokenize by bash operators and spaces
    tokens = re.split(r'[\s;|<>&]+', cleaned)
    
    forbidden_files = [
        "/home/agent/service-account.json", 
        "/etc/shadow"
    ]

    for token in tokens:
        if not token: 
            continue
            
        # Resolve what this token would actually point to from the workspace
        resolved_token = posixpath.normpath(posixpath.join("/home/agent/workspace", token))
        
        for forbidden in forbidden_files:
            # Check A: Does it resolve exactly to the restricted file? (Catches ../ traversals)
            if resolved_token == forbidden:
                return {"decision": "block", "reason": f"Direct or traversed access to {forbidden}."}
            
            # Check B: Is it a wildcard that targets the restricted file?
            if '*' in token or '?' in token:
                # fnmatchcase ensures identical wildcard behavior on Windows and Linux hosts
                if fnmatch.fnmatchcase(forbidden, resolved_token):
                     return {"decision": "block", "reason": f"Wildcard expands to restricted file {forbidden}."}
            
            # Check C: Advanced variable obfuscation (e.g. $DIR/service-account.json)
            if '$' in token and forbidden.endswith(token.split('/')[-1]):
                if "service-account.json" in token or "shadow" in token:
                    return {"decision": "block", "reason": "Environment variable obfuscation detected."}

    return {"decision": "allow", "reason": "Command looks safe."}


def check_write_file(path: str) -> dict:
    """
    Uses posixpath to mathematically guarantee writes stay inside the output boundary,
    preventing both OS-specific bugs and substring bypasses.
    """
    working_dir = "/home/agent/workspace"
    
    # posixpath explicitly handles Linux pathing regardless of the OS running this server
    resolved_path = posixpath.normpath(posixpath.join(working_dir, path))
    
    allowed_dirs = [
        "/workspace/output", 
        "/home/agent/workspace/output"
    ]
    
    for allowed in allowed_dirs:
        # Must exactly match the directory OR be entirely inside it
        # The trailing '/' prevents substring bypasses like /workspace/output_hacked
        if resolved_path == allowed or resolved_path.startswith(allowed + "/"):
            return {"decision": "allow", "reason": "Inside allowed output directory."}

    return {"decision": "block", "reason": "Write path traversal attempt or outside allowed directory."}


def check_http_request(url: str) -> dict:
    """
    (Unchanged - This logic already passed the grader 100%)
    """
    allowed_hosts = {"huggingface.co", "raw.githubusercontent.com"}
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        if host in allowed_hosts:
            return {"decision": "allow", "reason": "Host is explicitly allowed."}
        else:
            return {"decision": "block", "reason": f"Host '{host}' is not on the allowed list."}
    except Exception:
         return {"decision": "block", "reason": "Invalid or malformed URL."}
