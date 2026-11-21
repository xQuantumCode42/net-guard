# SDD ledger — plan: docs/superpowers/plans/2026-11-21-release-1.0.0.md

- User approved starting implementation and fixed version 1.0.0. Future version changes require their instruction.
- Ruling: execute inline without another plan approval round — user explicitly said start; higher-level authorization takes precedence over skill handoff ceremony.
- Ruling: dedicated new project directory is the isolation boundary; no existing Git checkout or user source to protect. Initialize a local implementation branch rather than create a worktree of a nonexistent repository.
- Pre-flight: policy types feed Store, Backend and desktop; shared definitions live in netguard-core. Backend reports capabilities; UI must not infer protection from rules alone.
- Environment: Windows with VS 2022 available; default Rust 1.61 inadequate, add pinned 1.90 without changing default. Node 20.16. npm needs normal user execution outside filesystem sandbox.
- External dependencies: macOS build/signing/test machine, Linux native runtime and Windows driver signing not yet verified. Do not substitute mocks for release evidence.
