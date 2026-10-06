# Offline corpora MANIFEST

Local only. Entire `generated/` is gitignored from public GitHub.

## Counts

| File | Unique lines |
|------|-------------:|
| `combo/hash-pass.lst` | 2 |
| `combo/hash-string.lst` | 1,714 |
| `combo/user-pass.lst` | 2,370 |
| `default-creds.lst` | 2,042 |
| `fuzzing.lst` | 889 |
| `passwords.lst` | 13,102,853 |
| `secrets/combo/hash-pass.lst` | 4 |
| `secrets/combo/user-pass.lst` | 2,671 |
| `secrets/passwords.lst` | 1 |
| `secrets/tokens.lst` | 2,333 |
| `secrets/users.lst` | 45 |
| `users.lst` | 1,248,286 |

## Taxonomy

- `users.lst` — usernames only
- `passwords.lst` — plaintext passwords only
- `combo/user-pass.lst` — username:password
- `combo/hash-pass.lst` — hash:password
- `combo/hash-string.lst` — hash:string / bare hashes
- `default-creds.lst` / `default-creds.json` — manufacturer defaults
- `fuzzing.lst` — discovery paths
- `secrets/*` — client creds and tokens (chmod 700/600)

Provenance only in `SOURCES.tsv` (no source-named shard files).
