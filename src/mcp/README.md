# mcp

`server.ts` exposes `infer_policy`, `static_check`, `run_access_tests`, `get_failures`, `explain_rule` over MCP (stdio).
By design there is no parameter that can unlock a non-local target or pass keys; secrets come from the environment.
