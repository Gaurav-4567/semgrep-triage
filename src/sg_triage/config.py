"""Configuration loading: API keys, model defaults, runtime options.

Loads `.env` from the current working directory (or any parent) when imported.
This means setting ANTHROPIC_API_KEY in a .env file in your project root makes
it available to the CLI without manual environment variable setup.

Environment variables already set take precedence over .env values.
"""

import os

from dotenv import load_dotenv

# Load .env from CWD or parent directories. No-op if no .env exists.
# `override=False` means a real environment variable wins over the .env value.
load_dotenv(override=False)


# --- Model & API defaults ---------------------------------------------------

DEFAULT_MODEL = "claude-sonnet-4-5"
DEFAULT_TEMPERATURE = 0.0
DEFAULT_MAX_TOKENS = 1024


def get_api_key() -> str:
    """Return the Anthropic API key, raising a clear error if not set.

    Looked up from the ANTHROPIC_API_KEY environment variable, which can be
    set directly or loaded from a .env file in the project root.
    """
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. Either:\n"
            "  - Set it in your shell: $env:ANTHROPIC_API_KEY = 'sk-ant-...'\n"
            "  - Or create a .env file in the project root with:\n"
            "      ANTHROPIC_API_KEY=sk-ant-...\n"
            "  - Get a key at: https://console.anthropic.com/settings/keys"
        )
    return key
