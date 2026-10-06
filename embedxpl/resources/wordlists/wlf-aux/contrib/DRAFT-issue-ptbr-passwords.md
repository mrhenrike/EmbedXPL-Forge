# DRAFT — SecLists issue: curated PT-BR password subset

> Local draft only. Copy/edit by hand before opening on GitHub.
> Do not paste AI-authored prose if submitting to SecLists.
> Do not attach multi-million-line dumps.

## Title (suggestion)

Interest in a curated Brazilian Portuguese password subset (no breach dump)

## Body (skeleton — rewrite in your own words)

### Summary

I have a large offline PT-BR-oriented password corpus used for authorized lab work. I am **not** proposing to upload the full list. I would like feedback on whether a **small curated cultural/language subset** (after dedup and overlap checks) would be useful.

### Constraints I will follow

- No PII / no breach dumps with linkable identities
- Dedup + overlap check against existing PT-BR / language lists (including `Discovery/Web-Content/common_pt-br.txt` and password language lists)
- No AI-generated password content

### Questions

1. Is there appetite for an additional PT-BR password list beyond what already exists?
2. Preferred size band (e.g. &lt; 50k / &lt; 200k lines)?
3. Should probability ordering be preserved, or is alpha/`sort -u` fine?

### Note

Full corpus stays offline and will not be attached to the issue.
