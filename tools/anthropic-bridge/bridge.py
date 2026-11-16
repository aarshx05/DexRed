#!/usr/bin/env python3
"""CodexSec Anthropic Bridge v2 — Responses API → Messages API translator.

Translates between Codex (OpenAI Responses API) and Anthropic (Messages API).
Handles streaming SSE correctly with line-buffered reading.

Usage:
    export ANTHROPIC_API_KEY="sk-ant-..."
    python3 bridge.py [--port 8087]
"""

import argparse
import http.client
import json
import os
import re
import ssl
import sys
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler


def sanitize_id(raw: str) -> str:
    """Ensure ID matches Anthropic's ^[a-zA-Z0-9_-]+$ requirement."""
    if not raw:
        return f"toolu_{uuid.uuid4().hex[:24]}"
    clean = re.sub(r'[^a-zA-Z0-9_-]', '', raw)
    return clean if clean else f"toolu_{uuid.uuid4().hex[:24]}"

ANTHROPIC_HOST = "api.anthropic.com"
ANTHROPIC_PATH = "/v1/messages"
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
DEFAULT_MODEL = "claude-opus-4-6"
ANTHROPIC_VERSION = "2023-06-01"
ANTHROPIC_BETA = "prompt-caching-2024-07-31"


def responses_to_messages(body: dict) -> dict:
    model = body.get("model", DEFAULT_MODEL)
    if "/" in model:
        model = model.split("/", 1)[1]

    messages = []
    system_parts = []

    for item in body.get("input", []):
        role = item.get("role", "")
        item_type = item.get("type", "")

        if role == "system" or item_type == "system":
            if isinstance(item.get("content"), str):
                system_parts.append(item["content"])
            elif isinstance(item.get("content"), list):
                for c in item["content"]:
                    if isinstance(c, dict):
                        system_parts.append(c.get("text", c.get("content", "")))
                    elif isinstance(c, str):
                        system_parts.append(c)

        elif role == "user":
            content = item.get("content", "")
            if isinstance(content, str):
                messages.append({"role": "user", "content": content})
            elif isinstance(content, list):
                parts = []
                for c in content:
                    if isinstance(c, dict):
                        text = c.get("text", c.get("content", ""))
                        if text:
                            parts.append({"type": "text", "text": text})
                    elif isinstance(c, str):
                        parts.append({"type": "text", "text": c})
                if parts:
                    messages.append({"role": "user", "content": parts})

        elif role == "assistant":
            content = item.get("content", "")
            if isinstance(content, str):
                messages.append({"role": "assistant", "content": content})
            elif isinstance(content, list):
                parts = []
                for c in content:
                    if isinstance(c, dict):
                        ctype = c.get("type", "")
                        if ctype in ("output_text", "text"):
                            parts.append({"type": "text", "text": c.get("text", "")})
                        elif ctype == "tool_use":
                            parts.append({
                                "type": "tool_use",
                                "id": sanitize_id(c.get("id", "")),
                                "name": c.get("name", ""),
                                "input": c.get("arguments", c.get("input", {})),
                            })
                        elif ctype == "function_call":
                            args = c.get("arguments", "{}")
                            if isinstance(args, str) and args.strip():
                                try:
                                    parsed_args = json.loads(args)
                                except json.JSONDecodeError:
                                    parsed_args = {}
                            elif isinstance(args, dict):
                                parsed_args = args
                            else:
                                parsed_args = {}
                            parts.append({
                                "type": "tool_use",
                                "id": sanitize_id(c.get("call_id", c.get("id", ""))),
                                "name": c.get("name", ""),
                                "input": parsed_args,
                            })
                if parts:
                    messages.append({"role": "assistant", "content": parts})

        elif item_type == "function_call":
            args = item.get("arguments", "{}")
            if isinstance(args, str) and args.strip():
                try:
                    parsed_args = json.loads(args)
                except json.JSONDecodeError:
                    parsed_args = {}
            elif isinstance(args, dict):
                parsed_args = args
            else:
                parsed_args = {}
            messages.append({
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "id": sanitize_id(item.get("call_id", item.get("id", ""))),
                    "name": item.get("name", ""),
                    "input": parsed_args,
                }]
            })

        elif item_type == "function_call_output":
            output = item.get("output", "")
            raw_id = item.get("call_id") or item.get("id") or ""
            if not raw_id or raw_id == "None":
                continue
            clean_id = sanitize_id(raw_id)
            messages.append({
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": clean_id,
                    "content": output if isinstance(output, str) else json.dumps(output),
                }]
            })

    # Collect all tool_use IDs from assistant messages so we can validate tool_results
    all_tool_use_ids = set()
    for msg in messages:
        if msg.get("role") == "assistant" and isinstance(msg.get("content"), list):
            for block in msg["content"]:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    all_tool_use_ids.add(block.get("id", ""))

    # Remove tool_result blocks that reference non-existent tool_use IDs
    for msg in messages:
        if msg.get("role") == "user" and isinstance(msg.get("content"), list):
            msg["content"] = [
                block for block in msg["content"]
                if not (isinstance(block, dict) and block.get("type") == "tool_result"
                        and block.get("tool_use_id") not in all_tool_use_ids)
            ]

    # Remove empty user messages after filtering
    messages = [msg for msg in messages if not (
        msg.get("role") == "user" and isinstance(msg.get("content"), list) and len(msg["content"]) == 0
    )]

    # Merge consecutive same-role messages
    merged = []
    for msg in messages:
        if merged and merged[-1]["role"] == msg["role"]:
            prev = merged[-1]["content"]
            curr = msg["content"]
            if isinstance(prev, str):
                prev = [{"type": "text", "text": prev}]
            if isinstance(curr, str):
                curr = [{"type": "text", "text": curr}]
            if isinstance(prev, list) and isinstance(curr, list):
                merged[-1]["content"] = prev + curr
            else:
                merged.append(msg)
        else:
            merged.append(msg)

    if merged and merged[0]["role"] != "user":
        merged.insert(0, {"role": "user", "content": "[conversation continues]"})

    if not merged:
        merged = [{"role": "user", "content": "Hello"}]

    # Cache the first user message (the assessment prompt — same every turn)
    if len(merged) > 2 and merged[0]["role"] == "user":
        content = merged[0].get("content", "")
        if isinstance(content, str) and len(content) > 100:
            merged[0]["content"] = [
                {"type": "text", "text": content, "cache_control": {"type": "ephemeral"}}
            ]

    tools = []
    for tool in body.get("tools", []):
        if tool.get("type") == "function":
            fn = tool.get("function", tool)
            tools.append({
                "name": fn.get("name", ""),
                "description": fn.get("description", ""),
                "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
            })

    request = {
        "model": model,
        "max_tokens": body.get("max_output_tokens", 16384),
        "messages": merged,
        "stream": True,
    }

    # Prompt caching: system prompt and tools are identical every turn.
    # Adding cache_control breakpoints saves ~90% on input tokens after the first call.
    if system_parts:
        system_text = "\n\n".join(system_parts)
        request["system"] = [
            {"type": "text", "text": system_text, "cache_control": {"type": "ephemeral"}}
        ]
    if tools:
        # Cache the tool definitions — mark the last tool with cache_control
        for i, tool in enumerate(tools):
            if i == len(tools) - 1:
                tool["cache_control"] = {"type": "ephemeral"}
        request["tools"] = tools

    temperature = body.get("temperature")
    if temperature is not None:
        request["temperature"] = temperature

    return request


def translate_sse(event_type: str, data: dict, state: dict) -> list:
    events = []
    rid = state.setdefault("response_id", f"resp_{uuid.uuid4().hex[:24]}")
    if "output_items" not in state:
        state["output_items"] = []

    if event_type == "message_start":
        msg = data.get("message", {})
        state["model"] = msg.get("model", "")
        usage = msg.get("usage", {})
        state["cache_read"] = usage.get("cache_read_input_tokens", 0)
        state["cache_create"] = usage.get("cache_creation_input_tokens", 0)
        state["input_tokens"] = usage.get("input_tokens", 0)
        events.append({
            "type": "response.created",
            "response": {"id": rid, "object": "response", "status": "in_progress", "model": state["model"], "output": []}
        })
        events.append({"type": "response.in_progress"})

    elif event_type == "content_block_start":
        block = data.get("content_block", {})
        idx = data.get("index", 0)
        btype = block.get("type", "text")
        state[f"b{idx}_type"] = btype
        state[f"b{idx}_text"] = ""

        if btype == "text":
            iid = f"msg_{uuid.uuid4().hex[:12]}"
            state[f"b{idx}_id"] = iid
            item = {"id": iid, "type": "message", "role": "assistant", "content": [{"type": "output_text", "text": ""}]}
            events.append({"type": "response.output_item.added", "output_index": idx, "item": item})
        elif btype == "tool_use":
            iid = block.get("id", f"toolu_{uuid.uuid4().hex[:24]}")
            state[f"b{idx}_id"] = iid
            state[f"b{idx}_name"] = block.get("name", "")
            state[f"b{idx}_args"] = ""
            item = {"id": iid, "type": "function_call", "name": block.get("name", ""), "call_id": iid, "arguments": ""}
            events.append({"type": "response.output_item.added", "output_index": idx, "item": item})

    elif event_type == "content_block_delta":
        delta = data.get("delta", {})
        idx = data.get("index", 0)

        if delta.get("type") == "text_delta":
            txt = delta.get("text", "")
            state[f"b{idx}_text"] = state.get(f"b{idx}_text", "") + txt
            events.append({
                "type": "response.output_text.delta",
                "output_index": idx,
                "content_index": 0,
                "delta": txt,
            })
        elif delta.get("type") == "input_json_delta":
            partial = delta.get("partial_json", "")
            state[f"b{idx}_args"] = state.get(f"b{idx}_args", "") + partial
            events.append({
                "type": "response.function_call_arguments.delta",
                "output_index": idx,
                "delta": partial,
            })

    elif event_type == "content_block_stop":
        idx = data.get("index", 0)
        btype = state.get(f"b{idx}_type", "text")
        iid = state.get(f"b{idx}_id", "")

        if btype == "tool_use":
            args = state.get(f"b{idx}_args", "{}")
            events.append({
                "type": "response.function_call_arguments.done",
                "output_index": idx,
                "arguments": args,
            })
            state["output_items"].append({
                "id": iid, "type": "function_call",
                "name": state.get(f"b{idx}_name", ""),
                "call_id": iid, "arguments": args,
            })
        elif btype == "text":
            state["output_items"].append({
                "id": iid, "type": "message", "role": "assistant",
                "content": [{"type": "output_text", "text": state.get(f"b{idx}_text", "")}],
            })

        done_item = state["output_items"][-1] if state["output_items"] else {"id": iid}
        events.append({"type": "response.output_item.done", "output_index": idx, "item": done_item})

    elif event_type == "message_delta":
        delta = data.get("delta", {})
        usage = data.get("usage", {})
        state["stop_reason"] = delta.get("stop_reason", "")
        state["output_tokens"] = usage.get("output_tokens", 0)

    elif event_type == "message_stop":
        stop = state.get("stop_reason", "end_turn")
        codex_stop = "tool_use" if stop == "tool_use" else "end_turn"
        events.append({
            "type": "response.completed",
            "response": {
                "id": rid,
                "object": "response",
                "status": "completed",
                "model": state.get("model", ""),
                "output": state.get("output_items", []),
                "stop_reason": codex_stop,
            }
        })

    elif event_type == "error":
        events.append({"type": "error", "error": data.get("error", {"type": "api_error", "message": "Unknown"})})

    return events


class BridgeHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write(f"[bridge] {fmt % args}\n")
        sys.stderr.flush()

    def do_POST(self):
        if self.path.rstrip("/") in ("/v1/responses", "/v1/chat/completions"):
            self.handle_responses()
        else:
            self.send_error(404, f"Not found: {self.path}")

    def do_GET(self):
        if self.path.rstrip("/") == "/v1/models":
            body = json.dumps({"object": "list", "data": [
                {"id": "claude-opus-4-6", "object": "model", "owned_by": "anthropic"},
                {"id": "claude-sonnet-4-6", "object": "model", "owned_by": "anthropic"},
                {"id": "claude-haiku-4-5", "object": "model", "owned_by": "anthropic"},
            ]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.rstrip("/") == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        else:
            self.send_error(404)

    def handle_responses(self):
        content_length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(content_length)
        body = json.loads(raw)

        api_key = ANTHROPIC_API_KEY
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            api_key = auth_header[7:]

        if not api_key:
            self.send_error(401, "ANTHROPIC_API_KEY not set")
            return

        # Debug: dump the input items to see what Codex sends
        for i, item in enumerate(body.get("input", [])):
            itype = item.get("type", item.get("role", "?"))
            if itype == "function_call":
                self.log_message("  input[%d] function_call id=%s call_id=%s name=%s", i, item.get("id"), item.get("call_id"), item.get("name"))
            elif itype == "function_call_output":
                self.log_message("  input[%d] function_call_output call_id=%s", i, item.get("call_id"))

        messages_req = responses_to_messages(body)

        # Debug: log the tool_use IDs and tool_result IDs to catch mismatches
        for i, msg in enumerate(messages_req.get("messages", [])):
            content = msg.get("content", "")
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict):
                        if block.get("type") == "tool_use":
                            self.log_message("  msg[%d] tool_use id=%s name=%s", i, block.get("id"), block.get("name"))
                        elif block.get("type") == "tool_result":
                            self.log_message("  msg[%d] tool_result tool_use_id=%s", i, block.get("tool_use_id"))

        req_body = json.dumps(messages_req).encode()

        self.log_message(
            "-> Anthropic: model=%s msgs=%d tools=%d",
            messages_req.get("model", "?"),
            len(messages_req.get("messages", [])),
            len(messages_req.get("tools", [])),
        )

        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(ANTHROPIC_HOST, context=ctx, timeout=300)

        try:
            conn.request("POST", ANTHROPIC_PATH, body=req_body, headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": ANTHROPIC_VERSION,
                "anthropic-beta": ANTHROPIC_BETA,
                "Accept": "text/event-stream",
            })
            resp = conn.getresponse()
        except Exception as e:
            self.log_message("Connection error: %s", str(e))
            self.send_error(502, f"Anthropic connection failed: {e}")
            conn.close()
            return

        if resp.status != 200:
            error_body = resp.read().decode()
            self.log_message("Anthropic error %d: %s", resp.status, error_body[:300])
            self.send_response(resp.status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(error_body.encode())
            conn.close()
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        state = {}
        current_event = None
        buffer = b""

        while True:
            chunk = resp.read(4096)
            if not chunk:
                break
            buffer += chunk

            while b"\n" in buffer:
                line_bytes, buffer = buffer.split(b"\n", 1)
                line = line_bytes.decode("utf-8", errors="replace").rstrip("\r")

                if line.startswith("event: "):
                    current_event = line[7:].strip()
                elif line.startswith("data: "):
                    if current_event is None:
                        continue
                    try:
                        data = json.loads(line[6:])
                    except json.JSONDecodeError:
                        continue

                    translated = translate_sse(current_event, data, state)
                    for evt in translated:
                        sse_out = f"data: {json.dumps(evt)}\n\n"
                        try:
                            self.wfile.write(sse_out.encode())
                            self.wfile.flush()
                        except BrokenPipeError:
                            conn.close()
                            return
                    current_event = None
                elif line == "":
                    current_event = None

        conn.close()
        cache_read = state.get("cache_read", 0)
        cache_create = state.get("cache_create", 0)
        input_tok = state.get("input_tokens", 0)
        output_tok = state.get("output_tokens", 0)
        cache_pct = round(cache_read / max(cache_read + cache_create + input_tok, 1) * 100)
        self.log_message(
            "Stream complete, stop=%s | in=%d cache_read=%d cache_write=%d out=%d | cache_hit=%d%%",
            state.get("stop_reason", "?"), input_tok, cache_read, cache_create, output_tok, cache_pct
        )


def main():
    parser = argparse.ArgumentParser(description="CodexSec Anthropic Bridge v2")
    parser.add_argument("--port", type=int, default=8087)
    args = parser.parse_args()

    if not ANTHROPIC_API_KEY:
        print("WARNING: ANTHROPIC_API_KEY not set.", file=sys.stderr)

    server = HTTPServer(("127.0.0.1", args.port), BridgeHandler)
    print(f"CodexSec Anthropic Bridge v2 on http://127.0.0.1:{args.port}", file=sys.stderr)
    print(f"  Codex base_url: http://127.0.0.1:{args.port}/v1", file=sys.stderr)
    print(f"  Default model: {DEFAULT_MODEL}", file=sys.stderr)
    print(f"  Anthropic key: {'set' if ANTHROPIC_API_KEY else 'NOT SET'}", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutdown.", file=sys.stderr)
        server.shutdown()


if __name__ == "__main__":
    main()
