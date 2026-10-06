# PayloadsAllTheThings contribution drafts (local only)

Reference tree: `/home/mrhenrike/llm-local/knowledge/PayloadsAllTheThings`  
(no `/opt/contrib` clone; no fork worktree)

GitHub `has_issues: false` → real contribution path is **PR**, not issue.

## Wave 1 — assessment

Compared local fuzzing / traversal material against existing PAT sections:

- `Directory Traversal/README.md` already covers traversal extensively
- `XSS Injection/3 - XSS Common WAF Bypass.md` already covers WAF bypass
- BRWordList `Vulnerabilidades/DirectoryTransversal.txt` (~889 lines) overlaps the traversal theme; not a clear unique technique write-up

**Result: no-op for a new technique folder** unless you later document a *specific* BR Open Banking / PIX discovery methodology with sanitized payloads, labs, and references (author/title/link/date).

## If you later author a PR

- Follow `_template_vuln/`
- Sanitize: `id` / `whoami`, `[ATTACKER.DOMAIN.TLD]`, `10.10.10.10`, `Administrator` / `User`, `P@ssw0rd`
- References: author, title, link, date (`Month Number, Year`)
- Run markdownlint per CONTRIBUTING.md
- Do **not** include `generated/secrets/**` or offline password dumps

## Optional weak add

A short “Tools” bullet pointing at a public wordlist generator is only appropriate if you personally want that and the tool is public; WordlistXPL-Forge public repo is separate from this offline `generated/` tree.
