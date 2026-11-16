#!/usr/bin/env python3
"""DexRed Ollama Tool-Call Middleware

Sits between LiteLLM and Ollama. Intercepts responses where the model
outputs tool calls as XML/text in content instead of structured tool_calls,
parses them, and returns a proper OpenAI-compatible response.

Models like Qwen 2.5 Coder generate:
  content: '<xml>{"name": "shell", "arguments": {"command": "curl ..."}}</xml>'
  tool_calls: null

This middleware converts that to:
  content: null
  tool_calls: [{"id": "call_xxx", "type": "function", "function": {"name": "shell", "arguments": "{...}"}}]

Usage:
  python3 tools/ollama-middleware/proxy.py --port 11435 --ollama http://127.0.0.1:11434
  Then point LiteLLM at http://127.0.0.1:11435 instead of 11434
"""

import argparse
import json
import re
import sys
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
import urllib.error

OLLAMA_URL = "http://127.0.0.1:11434"

TOOL_PATTERNS = [
    re.compile(r"<tools?>\s*(\{.*?\})\s*</tools?>", re.DOTALL),
    re.compile(r"<xml>\s*(\{.*?\})\s*</xml>", re.DOTALL),
    re.compile(r"```json\s*(\{[^`]*\"name\"[^`]*\"arguments\"[^`]*\})\s*```", re.DOTALL),
    re.compile(r"```\s*(\{[^`]*\"name\"[^`]*\"arguments\"[^`]*\})\s*```", re.DOTALL),
]

# XML attribute-style: <function name="shell" arguments='{"command": "curl ..."}' />
FUNC_ATTR_PATTERN = re.compile(
    r"""<function\s+name=["']([^"']+)["']\s+arguments=["'](.+?)["']\s*/?>""",
    re.DOTALL,
)
# Broader: anything inside <response>...</response> or <tool_call>...</tool_call>
RESPONSE_WRAPPER = re.compile(r"<(?:response|tool_call)>(.*?)</(?:response|tool_call)>", re.DOTALL)


def extract_tool_calls(content: str) -> tuple[list[dict], str]:
    """Extract tool calls from content text. Returns (tool_calls, remaining_content)."""
    if not content:
        return [], content

    tool_calls = []
    remaining = content

    for pattern in TOOL_PATTERNS:
        for match in pattern.finditer(content):
            try:
                data = json.loads(match.group(1))
                name = data.get("name", "")
                args = data.get("arguments", {})
                if name:
                    tool_calls.append({
                        "id": f"call_{uuid.uuid4().hex[:8]}",
                        "type": "function",
                        "function": {
                            "name": name,
                            "arguments": json.dumps(args) if isinstance(args, dict) else str(args),
                        },
                    })
                    remaining = remaining.replace(match.group(0), "").strip()
            except (json.JSONDecodeError, KeyError):
                continue

    # XML attribute-style: <function name="shell" arguments='{...}' />
    if not tool_calls:
        for match in FUNC_ATTR_PATTERN.finditer(content):
            name = match.group(1)
            args_str = match.group(2)
            try:
                args = json.loads(args_str)
            except json.JSONDecodeError:
                args = {"raw": args_str}
            tool_calls.append({
                "id": f"call_{uuid.uuid4().hex[:8]}",
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": json.dumps(args) if isinstance(args, dict) else str(args),
                },
            })
            remaining = remaining.replace(match.group(0), "").strip()

    # Unwrap <response>...</response> wrappers and scan inner content for function tags
    if not tool_calls:
        for wrapper in RESPONSE_WRAPPER.finditer(content):
            inner = wrapper.group(1).strip()
            for fmatch in FUNC_ATTR_PATTERN.finditer(inner):
                name = fmatch.group(1)
                args_str = fmatch.group(2)
                try:
                    args = json.loads(args_str)
                except json.JSONDecodeError:
                    args = {"raw": args_str}
                tool_calls.append({
                    "id": f"call_{uuid.uuid4().hex[:8]}",
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": json.dumps(args) if isinstance(args, dict) else str(args),
                    },
                })
            if tool_calls:
                remaining = remaining.replace(wrapper.group(0), "").strip()

    # Raw JSON object
    if not tool_calls:
        try:
            data = json.loads(content.strip())
            if isinstance(data, dict) and "name" in data and "arguments" in data:
                tool_calls.append({
                    "id": f"call_{uuid.uuid4().hex[:8]}",
                    "type": "function",
                    "function": {
                        "name": data["name"],
                        "arguments": json.dumps(data["arguments"]) if isinstance(data["arguments"], dict) else str(data["arguments"]),
                    },
                })
                remaining = ""
        except (json.JSONDecodeError, KeyError):
            pass

    return tool_calls, remaining


def patch_openai_response(body: dict) -> dict:
    """Patch an OpenAI-format response to extract tool calls from content."""
    choices = body.get("choices", [])
    for choice in choices:
        msg = choice.get("message", {})
        content = msg.get("content", "")
        existing_calls = msg.get("tool_calls")

        if existing_calls:
            continue

        tool_calls, remaining = extract_tool_calls(content)
        if tool_calls:
            msg["tool_calls"] = tool_calls
            msg["content"] = remaining if remaining else None
            choice["finish_reason"] = "tool_calls"
    return body


def patch_ollama_response(body: dict) -> dict:
    """Patch an Ollama native API response."""
    msg = body.get("message", {})
    content = msg.get("content", "")
    existing_calls = msg.get("tool_calls")

    if existing_calls:
        return body

    tool_calls, remaining = extract_tool_calls(content)
    if tool_calls:
        msg["tool_calls"] = tool_calls
        msg["content"] = remaining if remaining else ""
    return body


class MiddlewareHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write(f"[middleware] {fmt % args}\n")
        sys.stderr.flush()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        req = urllib.request.Request(
            f"{OLLAMA_URL}{self.path}",
            data=body,
            headers={k: v for k, v in self.headers.items() if k.lower() != "host"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=600) as resp:
                resp_body = resp.read()
                try:
                    data = json.loads(resp_body)

                    if self.path.startswith("/v1/"):
                        data = patch_openai_response(data)
                    else:
                        data = patch_ollama_response(data)

                    patched = json.dumps(data).encode()

                    tool_calls = []
                    if "choices" in data:
                        for c in data.get("choices", []):
                            tc = c.get("message", {}).get("tool_calls", [])
                            if tc:
                                tool_calls = tc
                    elif "message" in data:
                        tool_calls = data.get("message", {}).get("tool_calls", [])

                    if tool_calls:
                        names = [t["function"]["name"] for t in tool_calls]
                        self.log_message("Extracted tool calls: %s", ", ".join(names))

                    self.send_response(resp.status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(patched)))
                    self.end_headers()
                    self.wfile.write(patched)
                except json.JSONDecodeError:
                    self.send_response(resp.status)
                    for k, v in resp.headers.items():
                        if k.lower() not in ("transfer-encoding", "content-length"):
                            self.send_header(k, v)
                    self.send_header("Content-Length", str(len(resp_body)))
                    self.end_headers()
                    self.wfile.write(resp_body)

        except urllib.error.HTTPError as e:
            err_body = e.read()
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(err_body)))
            self.end_headers()
            self.wfile.write(err_body)
        except Exception as e:
            err = json.dumps({"error": str(e)}).encode()
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(err)))
            self.end_headers()
            self.wfile.write(err)

    def do_GET(self):
        req = urllib.request.Request(f"{OLLAMA_URL}{self.path}", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Type", resp.headers.get("Content-Type", "application/json"))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        except Exception as e:
            err = json.dumps({"error": str(e)}).encode()
            self.send_response(502)
            self.end_headers()
            self.wfile.write(err)


def main():
    parser = argparse.ArgumentParser(description="DexRed Ollama Tool-Call Middleware")
    parser.add_argument("--port", type=int, default=11435)
    parser.add_argument("--ollama", default="http://127.0.0.1:11434")
    args = parser.parse_args()

    global OLLAMA_URL
    OLLAMA_URL = args.ollama

    server = HTTPServer(("0.0.0.0", args.port), MiddlewareHandler)
    print(f"DexRed Ollama Middleware on port {args.port} → {OLLAMA_URL}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
