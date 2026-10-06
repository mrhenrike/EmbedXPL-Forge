# DRAFT — SecLists issue: manufacturer default-creds delta

> Local draft only. Copy/edit by hand before opening on GitHub.
> Do not paste AI-authored prose if submitting to SecLists.

## Title (suggestion)

Add / review manufacturer default credential delta (ICS, printers, network gear)

## Body (skeleton — rewrite in your own words)

### Summary

I maintain a structured manufacturer default-credentials database (IoT/ICS/printer/router) and a flat `user:pass` export. Before opening a PR, I want guidance on preferred file layout and whether a delta against existing `Passwords/Default-Credentials/` is welcome.

### What I can provide

- Flat `user:pass` list (deduped)
- Optional JSON with vendor metadata and public sources (CISA ICS advisories, routersploit-style defaults, printer defaults, SNMP communities, etc.)
- Attribution / source links per batch

### What I will not upload

- Full password corpora
- Client engagement secrets
- Anything with PII

### Questions for maintainers

1. Prefer one combined file, or split by vendor/product family (as in existing Default-Credentials tree)?
2. Should SNMP community strings live under Default-Credentials or elsewhere?
3. Any size cap for a first PR?

### Environment

- Compared locally against `/usr/share/seclists/Passwords/Default-Credentials/`
