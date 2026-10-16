

Always read and follow the coding conventions in [STYLE_GUIDE.md](./docs/STYLE_GUIDE.md) when writing or modifying C code in this project.
Use the de-wonk skill when completing an implementation
## Git Commit Conventions

- **Do NOT add "Co-Authored-By" lines to commit messages.** All commits should have only the author's information.
- Use clear, descriptive commit messages following conventional commit format (e.g., "feat:", "fix:", "docs:", "test:", "refactor:", "chore:")
- Keep commits focused and atomic - one logical change per commit

## Key Patterns
- Ownership is direct create/destroy — `src/` does NOT use reference counting (no `refcounter_t` anywhere; an earlier revision of this file described one)
- Types use `_t` suffix, functions follow `type_action()` naming
- Create functions use `get_clear_memory()`
- Destroy functions free owned members; they are NULL-tolerant (destroying NULL is a no-op)
- Secret-bearing structs are cleansed (OPENSSL_cleanse) before free
- Directories in `src/` are organized by semantic purpose (Buffer/, Workers/, Time/, etc.)
