

Always read and follow the coding conventions in [STYLE_GUIDE.md](./docs/STYLE_GUIDE.md) when writing or modifying C code in this project.
Use the de-wonk skill when completing an implementation
## Git Commit Conventions

- **Do NOT add "Co-Authored-By" lines to commit messages.** All commits should have only the author's information.
- Use clear, descriptive commit messages following conventional commit format (e.g., "feat:", "fix:", "docs:", "test:", "refactor:", "chore:")
- Keep commits focused and atomic - one logical change per commit

## JS/WASM artifact freshness (ALWAYS rebuild)

The shipped JS/WASM artifacts (`build-wasm*/crabs*.js`/`*.wasm` and the copies in `bindings/wasm/`) are **not rebuilt automatically**. Whenever `src/` C code changes OR a `deps/` submodule (openabe-c, relic) changes, rebuild and re-copy them before declaring the work done — stale copies make binding tests silently run the old binary (tests load the `bindings/wasm/` copies first):

1. Prerequisites: `source /home/victor/emsdk/emsdk_env.sh`; OpenSSL wasm headers staged at `/tmp/wasm-openssl-headers` and `/tmp/openssl-3.4.0` present (re-stage if missing — full notes in `bindings/wasm/README.md` §"Rebuilding from source")
2. Rebuild the dependency wasm archives from the PINNED submodule state: `cd deps/openabe-c && ./build_wasm.sh` (RELIC + OpenABE static libs)
3. Build CRABS itself from the repo root with the pin: `OPENABE_DIR="$PWD/deps/openabe-c" ./build_wasm.sh`
   (the script's default `OPENABE_DIR` points at a separate workspace copy — override it so artifacts match the tracked submodule)
4. `build_wasm.sh` copies its artifacts into `bindings/wasm/` automatically, but does NOT refresh the other consumers of the bindings:
   - `examples/video_platform_p2p/public/` and `cookbook/site/dist/assets/wasm/` also hold copies
5. If the change affects the node (N-API) binding, rebuild `bindings/node` and rerun its tests

Always rerun the binding tests after copying so the fresh binaries are actually exercised.

## Key Patterns
- Ownership is direct create/destroy — `src/` does NOT use reference counting (no `refcounter_t` anywhere; an earlier revision of this file described one)
- Types use `_t` suffix, functions follow `type_action()` naming
- Create functions use `get_clear_memory()`
- Destroy functions free owned members; they are NULL-tolerant (destroying NULL is a no-op)
- Secret-bearing structs are cleansed (OPENSSL_cleanse) before free
- Directories in `src/` are organized by semantic purpose (Buffer/, Workers/, Time/, etc.)
