"""Open Deep Research agent module.

This package contains the Deep Research agent that conducts multi-step research
using a supervisor-researcher architecture with LangGraph subgraphs.
"""

from src.app.core.tools import SearchAPI
from src.app.core.common.utils import get_api_key_for_model
from src.app.core.common.config import settings
from src.app.core.llm.factory import make_chat_model

# ──────────────────────────────────────
# Deep Research Agent Configuration
# ──────────────────────────────────────

# General
DEEP_RESEARCH_AGENT_NAME = "Deep Research"
ALLOW_CLARIFICATION = False  # automated use: never ask the user questions
MAX_STRUCTURED_OUTPUT_RETRIES = 3

# Research limits
MAX_CONCURRENT_RESEARCH_UNITS = 3
MAX_RESEARCHER_ITERATIONS = 2
MAX_REACT_TOOL_CALLS = 6

# Search
SEARCH_API = SearchAPI.GEMINI if settings.USE_GEMINI else SearchAPI.DUCKDUCKGO

# Models
RESEARCH_MODEL = f"openai:{settings.LLM_MODEL}"
RESEARCH_MODEL_MAX_TOKENS = 10000

COMPRESSION_MODEL = f"openai:{settings.LLM_MODEL}"
COMPRESSION_MODEL_MAX_TOKENS = 8192

FINAL_REPORT_MODEL = f"openai:{settings.LLM_MODEL}"
FINAL_REPORT_MODEL_MAX_TOKENS = 10000


MAX_CONTENT_LENGTH = 50000

# Shared configurable model used across all subgraphs
configurable_model = make_chat_model(
    RESEARCH_MODEL,
    configurable_fields=("model", "max_tokens", "api_key"),
)

writer_model_config = {
    "model": FINAL_REPORT_MODEL,
    "max_tokens": FINAL_REPORT_MODEL_MAX_TOKENS,
    "api_key": get_api_key_for_model(FINAL_REPORT_MODEL),
}

research_model_config = {
    "model": RESEARCH_MODEL,
    "max_tokens": RESEARCH_MODEL_MAX_TOKENS,
    "api_key": get_api_key_for_model(RESEARCH_MODEL),
}

compress_model_config = {
    "model": COMPRESSION_MODEL,
    "max_tokens": COMPRESSION_MODEL_MAX_TOKENS,
    "api_key": get_api_key_for_model(COMPRESSION_MODEL),
}
