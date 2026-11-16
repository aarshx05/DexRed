#!/usr/bin/env bash
# CodexSec Model Setup — Interactive configuration wizard
# Run this before your first security assessment.
set -euo pipefail

CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
CONFIG_FILE="$CODEX_HOME/config.toml"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXAMPLES_DIR="$SCRIPT_DIR/../config-examples"

echo "╔══════════════════════════════════════════════╗"
echo "║         CodexSec — Model Setup               ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Check if config already exists
if [ -f "$CONFIG_FILE" ]; then
    echo "Existing config found at $CONFIG_FILE"
    read -p "Overwrite model settings? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Keeping existing config."
        exit 0
    fi
fi

mkdir -p "$CODEX_HOME"

echo "Choose your model provider:"
echo ""
echo "  1) Claude (Anthropic API key)  — Recommended. Direct, no middleman"
echo "  2) Claude (via OpenRouter)     — Alternative if you have an OpenRouter key"
echo "  3) OpenAI (direct)             — GPT-4.1, o4-mini"
echo "  4) Google Gemini (via OpenRouter)"
echo "  5) Local model (Ollama)        — Free, runs on your machine"
echo "  6) Local model (LM Studio)     — Free, runs on your machine"
echo "  7) Custom provider             — Bring your own config"
echo ""
read -p "Enter choice [1-7]: " choice

case "$choice" in
    1)
        echo ""
        echo "Claude via Anthropic API selected (direct, no middleman)."
        echo ""
        echo "Available models:"
        echo "  a) claude-sonnet-4    — Best balance of speed and quality (recommended)"
        echo "  b) claude-opus-4      — Most capable, slower and costlier"
        echo "  c) claude-haiku-4     — Fastest and cheapest"
        echo ""
        read -p "Choose model [a/b/c]: " model_choice
        case "$model_choice" in
            b) MODEL="claude-opus-4-20250514" ;;
            c) MODEL="claude-haiku-4-20250514" ;;
            *) MODEL="claude-sonnet-4-20250514" ;;
        esac

        if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
            echo ""
            echo "You need an Anthropic API key."
            echo "Get one at: https://console.anthropic.com/settings/keys"
            echo ""
            read -p "Enter your Anthropic API key: " api_key
            echo ""
            echo "Add this to your shell profile (.bashrc, .zshrc, etc.):"
            echo "  export ANTHROPIC_API_KEY=\"$api_key\""
            export ANTHROPIC_API_KEY="$api_key"
        fi

        cp "$EXAMPLES_DIR/anthropic-direct.toml" "$CONFIG_FILE"
        sed -i "s|model = \".*\"|model = \"$MODEL\"|" "$CONFIG_FILE"

        echo ""
        echo "NOTE: The Anthropic Bridge must be running before you start Codex:"
        echo "  python3 tools/anthropic-bridge/bridge.py &"
        ;;
    2)
        echo ""
        echo "Claude via OpenRouter selected."
        echo ""
        echo "Available models:"
        echo "  a) claude-sonnet-4    — Best balance of speed and quality (recommended)"
        echo "  b) claude-opus-4      — Most capable, slower and costlier"
        echo "  c) claude-haiku-4     — Fastest and cheapest"
        echo ""
        read -p "Choose model [a/b/c]: " model_choice
        case "$model_choice" in
            b) MODEL="anthropic/claude-opus-4-20250514" ;;
            c) MODEL="anthropic/claude-haiku-4-20250514" ;;
            *) MODEL="anthropic/claude-sonnet-4-20250514" ;;
        esac

        if [ -z "${OPENROUTER_API_KEY:-}" ]; then
            echo ""
            echo "You need an OpenRouter API key."
            echo "Get one at: https://openrouter.ai/keys"
            echo ""
            read -p "Enter your OpenRouter API key: " api_key
            echo ""
            echo "Add this to your shell profile (.bashrc, .zshrc, etc.):"
            echo "  export OPENROUTER_API_KEY=\"$api_key\""
            export OPENROUTER_API_KEY="$api_key"
        fi

        cp "$EXAMPLES_DIR/openrouter-claude.toml" "$CONFIG_FILE"
        sed -i "s|model = \".*\"|model = \"$MODEL\"|" "$CONFIG_FILE"
        ;;
    3)
        echo ""
        echo "OpenAI direct selected."
        echo ""
        read -p "Model name [o4-mini]: " model_name
        MODEL="${model_name:-o4-mini}"

        if [ -z "${OPENAI_API_KEY:-}" ]; then
            echo ""
            echo "You need an OpenAI API key."
            echo "Get one at: https://platform.openai.com/api-keys"
            echo ""
            read -p "Enter your OpenAI API key: " api_key
            echo ""
            echo "Add this to your shell profile:"
            echo "  export OPENAI_API_KEY=\"$api_key\""
            export OPENAI_API_KEY="$api_key"
        fi

        cp "$EXAMPLES_DIR/openai-direct.toml" "$CONFIG_FILE"
        sed -i "s|model = \".*\"|model = \"$MODEL\"|" "$CONFIG_FILE"
        ;;
    4)
        echo ""
        echo "Google Gemini via OpenRouter selected."

        if [ -z "${OPENROUTER_API_KEY:-}" ]; then
            echo ""
            echo "You need an OpenRouter API key."
            echo "Get one at: https://openrouter.ai/keys"
            echo ""
            read -p "Enter your OpenRouter API key: " api_key
            echo ""
            echo "Add this to your shell profile:"
            echo "  export OPENROUTER_API_KEY=\"$api_key\""
            export OPENROUTER_API_KEY="$api_key"
        fi

        cp "$EXAMPLES_DIR/google-gemini.toml" "$CONFIG_FILE"
        ;;
    5)
        echo ""
        echo "Ollama local selected."
        echo ""

        if ! command -v ollama &>/dev/null; then
            echo "Ollama not found. Install it: https://ollama.com/download"
            exit 1
        fi

        read -p "Model name [qwen3:32b]: " model_name
        MODEL="${model_name:-qwen3:32b}"

        echo "Pulling model $MODEL (this may take a while)..."
        ollama pull "$MODEL"

        cp "$EXAMPLES_DIR/ollama-local.toml" "$CONFIG_FILE"
        sed -i "s|model = \".*\"|model = \"$MODEL\"|" "$CONFIG_FILE"
        ;;
    6)
        echo ""
        echo "LM Studio local selected."
        echo "Make sure LM Studio is running with a model loaded."

        cp "$EXAMPLES_DIR/lmstudio-local.toml" "$CONFIG_FILE"
        ;;
    7)
        echo ""
        echo "Custom provider. Edit $CONFIG_FILE manually."
        echo "See config-examples/ for reference."
        touch "$CONFIG_FILE"
        ;;
    *)
        echo "Invalid choice."
        exit 1
        ;;
esac

echo ""
echo "Config written to: $CONFIG_FILE"
echo ""
echo "Next steps:"
echo "  1. Edit target.toml with your authorized target"
echo "  2. Run: codex --full-auto"
echo ""
