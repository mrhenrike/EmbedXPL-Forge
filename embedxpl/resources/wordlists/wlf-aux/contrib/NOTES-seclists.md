# SecLists contribution drafts (local only)

Reference tree: `/usr/share/seclists` (no local fork/clone).

**Do not push from this machine until you personally author and submit.**
SecLists forbids contributions made using AI in any way — finalize text and submission yourself.

## Wave 1 — Discovery BR (PR candidate)

- File: `discovery-br.lst` (75 unique lines after delta vs `common.txt` / `common_pt-br.txt` / `common_directories.txt`)
- Content focus: Open Banking BR API paths, PIX/fiscal/gov discovery tokens (`nfe`, `nfse`, `boleto`, `consulta-cpf`, `bacen`, …)
- Format checks done mechanically:
  - no leading `/`
  - no `#` comment lines
  - `sort -u` / unique
- Suggested upstream path: `Discovery/Web-Content/` (new file + README entry)
- Attribution to record in README entry:
  - Helvio Junior / BRWordList (Open Banking + discovery paths)
  - André Henrique (@mrhenrike) curation into WordlistXPL-Forge offline corpora
- Suggested commit message shape (SecLists Conventional Commits — their rule):
  - `feat(wordlist): Added "discovery-br.txt" by Helvio Junior / mrhenrike`

## Wave 2 — Default credentials (issue first)

- Local sources (not attached wholesale): `../default-creds.lst` (~2042 lines), `../default-creds.json`
- Overlap with `/usr/share/seclists/Passwords/Default-Credentials/` is expected (tomcat, scada, routersploit-style)
- Draft: `DRAFT-issue-default-creds.md`
- Ask maintainers preferred layout before any PR

## Wave 3 — PT-BR passwords (issue only)

- Do **not** attach `../passwords.lst` (~13M lines)
- Draft: `DRAFT-issue-ptbr-passwords.md`
- Propose curated cultural subset after overlap measurement vs `Discovery/Web-Content/common_pt-br.txt` and password language lists

## Denylist (never include in upstream packages)

- `../secrets/**`
- full `../passwords.lst`
- personal profile dumps
- client credentials / tokens
