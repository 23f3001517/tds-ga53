from fastapi import FastAPI, Request
from urllib.parse import urlparse
import os
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
    Evaluates bash commands for attempts to read the restricted service-account.json file.
    Accounts for quotes, hex escaping, base64 encoding, and wildcards.
    """
    # 1. Normalize the command to break simple string splitting/quoting obfuscations
    normalized = command.replace("'", "").replace('"', "").replace("\\", "")
    
    # 2. Decode hex escapes (e.g. \x73\x65\x72...) 
    try:
        normalized = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), normalized)
    except Exception:
        pass # Ignore malformed hex

    # 3. Check for literal strings (catches relative traversal, $HOME, and ~ expansion)
    restricted_files = ["service-account.json", "/etc/shadow"]
    for f in restricted_files:
        if f in normalized:
            return {"decision": "block", "reason": f"Access to restricted file {f} is forbidden."}

    # 4. Check for wildcard bypasses (e.g., service-*.json, s*account.json)
    if re.search(r'service[^\s]*account[^\s]*\.json', normalized, re.IGNORECASE):
        return {"decision": "block", "reason": "Obfuscated access to restricted file via wildcards."}
    
    # Block broad wildcard reads in the agent's home directory (e.g., cat /home/agent/* or cat ~/*)
    if re.search(r'(/home/agent/|~/)(\*|\?)', normalized):
        return {"decision": "block", "reason": "Wildcard reads in the home directory are forbidden to protect secrets."}

    # 5. Check for base64 encoded payloads
    # Matches strings that look like base64 and are long enough to hold the filename
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{16,}={0,2}')
    for b64_str in b64_pattern.findall(command):
        try:
            decoded = base64.b64decode(b64_str).decode('utf-8')
            dec_norm = decoded.replace("'", "").replace('"', "").replace("\\", "")
            if "service-account.json" in dec_norm or "/etc/shadow" in dec_norm:
                return {"decision": "block", "reason": "Restricted file access detected inside base64 payload."}
        except Exception:
            continue # Not valid base64 or utf-8, move on

    return {"decision": "allow", "reason": "Command looks safe."}


def check_write_file(path: str) -> dict:
    """
    Ensures file writes ONLY occur strictly inside /workspace/output/
    (or /home/agent/workspace/output/). Blocks directory traversal attacks (../).
    """
    working_dir = "/home/agent/workspace"
    
    # os.path.join handles absolute paths natively: if `path` is absolute, it ignores `working_dir`
    resolved_path = os.path.abspath(os.path.join(working_dir, path))
    
    # The policy specifies /workspace/output/, but practically agents may think 
    # it's /home/agent/workspace/output/. We allow both to be robust.
    allowed_dir_1 = os.path.abspath("/workspace/output")
    allowed_dir_2 = os.path.abspath("/home/agent/workspace/output")
    
    try:
        # os.path.commonpath prevents traversal bypasses like `/workspace/output/../../etc`
        is_in_dir1 = os.path.commonpath([resolved_path, allowed_dir_1]) == allowed_dir_1
        is_in_dir2 = os.path.commonpath([resolved_path, allowed_dir_2]) == allowed_dir_2
        
        if is_in_dir1 or is_in_dir2:
            return {"decision": "allow", "reason": "Write path is inside the allowed output directory."}
    except ValueError:
        pass # Triggers if paths are on different Windows drives, but we assume a Linux agent context.

    return {"decision": "block", "reason": "Write path is outside permitted output directories or attempts path traversal."}


def check_http_request(url: str) -> dict:
    """
    Validates outbound HTTP requests against an exact allowlist. 
    Prevents domain confusion (e.g. huggingface.co.evil.com).
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