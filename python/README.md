# AetherOS Orchestrator

The orchestration layer of AetherOS. Builds on the Rust-backed `aetheros` core to
provide configuration, hybrid memory, intent compilation, and governed task-graph
execution via LangGraph.

Phase 1 ships the configuration system (zero-hardcoding, env-overridable) and the
ephemeral memory foundation. Later phases add the LangGraph StateGraph with human
approval checkpoints, the intent compiler, the policy engine, MCP adapters, and
sandbox control.
