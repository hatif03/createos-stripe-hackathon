# Third-party software

Sandtrap uses open-source libraries, each under its own licence (see `pyproject.toml` and `uv.lock`): createos-sandbox, FastAPI, LangGraph,
LangChain, Langfuse, structlog, tenacity, slowapi, prometheus-client, mcp, SQLModel, httpx, rich, psycopg, ddgs.

It also downloads, at setup time, the **capa** standalone binary from Mandiant (Apache-2.0; https://github.com/mandiant/capa) and runs it
inside the analysis sandbox. The binary is not committed (`analyzer/bin/`).
