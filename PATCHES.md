
## UTF-8 quoted validation (2026-10-02)

Backport #730 (6ddee598e7b58d9d195973999a9d891a0a43b282): reject NUL, CR and LF
in construction, decoding and serde; keep valid UTF-8, quoting and escapes.
The unchecked constructor remains explicitly unchecked. All-feature workspace
library tests pass on macOS arm64.

The MODSEQ parenthesis encoding is already identical to upstream ad06aac38;
retain one implementation and the fork's additional command/capability checks.
Do not revert that multi-purpose local commit. STATUS SIZE is independently
implemented; adopting the upstream feature/type split is not a maintenance-only
replacement. WITHIN remains outside this patch set.
