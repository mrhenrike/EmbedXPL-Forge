## Description

<!-- Briefly describe what this PR does and why. -->

## Type of change

- [ ] Bug fix
- [ ] New exploit module / engine
- [ ] Dependency update
- [ ] Refactor / code quality
- [ ] Documentation
- [ ] Other:

## Security checklist (required for all PRs)

> This project is a security tool used by real operators. Malicious code in
> non-exploit modules could harm end users. All items below must be checked
> before this PR can be reviewed.

- [ ] No reverse shells, bind shells, or C2 beacons in non-exploit modules
- [ ] No hard-coded attacker-controlled IPs/domains outside `modules/exploits/`
- [ ] No base64/obfuscated blobs that decode to shellcode in core/engine code
- [ ] No credential or key exfiltration to external hosts
- [ ] No unauthorized persistence (cron, registry Run keys, startup entries)
- [ ] No download-and-execute chains in non-exploit code
- [ ] All new network connections go to user-supplied targets only
- [ ] Dependencies added are well-known PyPI packages (not typosquats)

## Testing

- [ ] `python tools/run_scoped_tests.py` passes
- [ ] `ruff check .` passes (or explain exclusions)
- [ ] Manually tested on a lab target

## Authorship acknowledgement

> **Policy:** Only `@mrhenrike` authors commits that land in `main`.
> External contributors submit PRs; the maintainer reviews and squash-merges.
> The `author-gate` CI check enforces this automatically.

- [ ] I understand that @mrhenrike will squash-merge or cherry-pick this PR under their own authorship if accepted.

## Notes for reviewer

<!-- Anything the maintainer should pay special attention to. -->
