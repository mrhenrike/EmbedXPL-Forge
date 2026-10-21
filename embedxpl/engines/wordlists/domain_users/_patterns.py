"""Corporate username/password pattern constants."""
from __future__ import annotations


# ── Corporate username patterns ────────────────────────────────────────────────

# Pattern tokens:
#   {fn}  = first name (normalized, no accents)
#   {ln}  = last name
#   {mn}  = first middle name (empty if none)
#   {fi}  = first initial
#   {li}  = last initial
#   {mi}  = middle initial
#   {ini} = all initials
#   {sep} = separator (iterated: ".", "_", "-", "")
#   {num} = numeric suffix (iterated: "01", "1", "02", "2", …)
#   {sub} = subdomain prefix (requires subdomain=True)
#
# Ordering follows common corporate AD username frequency.
# Username format patterns. Operator-supplied names drive generation.
CORPORATE_PATTERNS: list[dict] = [
    # ── Tier 1: Highest frequency (fn.ln in energy/utilities and similar) ──
    {"id": "fn_sep_ln",        "desc": "firstname.lastname",                  "fmt": "{fn}{sep}{ln}"},
    # ── Tier 2: No-separator variants (filn common in energy/utilities) ───
    {"id": "fi_ln",            "desc": "flastname (initial+last, no sep)",    "fmt": "{fi}{ln}"},
    {"id": "fn_li",            "desc": "firstnamel (name+last initial)",      "fmt": "{fn}{li}"},
    # ── Tier 3: With separator - initial+last, name+initial ──────────────────
    {"id": "fi_sep_ln",        "desc": "f.lastname",                          "fmt": "{fi}{sep}{ln}"},
    {"id": "fn_sep_li",        "desc": "firstname.l",                         "fmt": "{fn}{sep}{li}"},
    # ── Tier 4: First/last name alone (service accounts, single-name users) ───
    {"id": "fn_only",          "desc": "firstname only",                      "fmt": "{fn}"},
    {"id": "ln_only",          "desc": "lastname only",                       "fmt": "{ln}"},
    # ── Tier 5: No-separator compound (fnln, lnfn) ────────────────────────────
    {"id": "fn_ln",            "desc": "firstnamelastname (no sep)",          "fmt": "{fn}{ln}"},
    {"id": "ln_fn",            "desc": "lastnamefirstname (no sep)",          "fmt": "{ln}{fn}"},
    # ── Tier 6: Reversed (ln.fn, ln.f) - government/judicial pattern ─────────
    {"id": "ln_sep_fn",        "desc": "lastname.firstname",                  "fmt": "{ln}{sep}{fn}"},
    {"id": "ln_sep_fi",        "desc": "lastname.f (reversed initial)",       "fmt": "{ln}{sep}{fi}"},
    {"id": "ln_fi",            "desc": "lastnamef (no sep)",                  "fmt": "{ln}{fi}"},
    # ── Tier 7: Disambiguation with numeric suffix ────────────────────────────
    # Pattern fn.lnNUM (pessoax.corpx01) - when duplicate fn.ln exists
    {"id": "fn_sep_ln_num",    "desc": "fn.ln + numeric suffix (duplicate)",  "fmt": "{fn}{sep}{ln}{num}"},
    # Pattern fn.ln.NUM (pessoax.corpx.01) - dot-separated disambiguation
    {"id": "fn_sep_ln_sep_num","desc": "fn.ln.N (dot-separated, BR common)",  "fmt": "{fn}{sep}{ln}{sep}{num}"},
    # Pattern filn01 - initial+last with numeric suffix
    {"id": "fi_ln_num",        "desc": "filn + numeric suffix",               "fmt": "{fi}{ln}{num}"},
    # ── Tier 8: With middle name (when available) ──────────────────────────────
    {"id": "fn_sep_mn_sep_ln", "desc": "first.middle.last",                   "fmt": "{fn}{sep}{mn}{sep}{ln}", "needs_middle": True},
    {"id": "fi_mi_ln",         "desc": "fml initials (fimiln)",               "fmt": "{fi}{mi}{ln}",           "needs_middle": True},
    {"id": "fi_sep_mi_sep_li", "desc": "f.m.l (all initials with sep)",       "fmt": "{fi}{sep}{mi}{sep}{li}", "needs_middle": True},
    # ── Tier 9: Initials ──────────────────────────────────────────────────────
    {"id": "fi_li",            "desc": "initials fl (no sep)",                "fmt": "{fi}{li}"},
    {"id": "ini",              "desc": "all initials fml… (no sep)",          "fmt": "{ini}"},
    {"id": "fi_sep_li",        "desc": "f.l (initials with sep)",             "fmt": "{fi}{sep}{li}"},
    # ── Tier 10: BR institutional - name + middle/company part as alias ───────
    # Observed: firstname.middlename used when last name causes collision
    {"id": "fn_sep_mn",        "desc": "firstname.middlename (collision alt)","fmt": "{fn}{sep}{mn}",          "needs_middle": True},
    # ── Tier 10b: Particle-inclusive last name (dapessoay, decorpx, deacme) ───
    # Observed: pessoax.dapessoay, personay.decorpx, robotx.dacorpx
    # Some AD admins include the particle when the last name alone is ambiguous.
    {"id": "fn_sep_lf",        "desc": "firstname.dapessoay (particle+last)",  "fmt": "{fn}{sep}{lf}",          "needs_lf": True},
    {"id": "lf_sep_fn",        "desc": "dapessoay.firstname (reversed)",       "fmt": "{lf}{sep}{fn}",          "needs_lf": True},
    {"id": "fi_sep_lf",        "desc": "f.dapessoay (initial+full-last)",      "fmt": "{fi}{sep}{lf}",          "needs_lf": True},
    # ── Tier 11: Admin/role accounts ─────────────────────────────────────────
    {"id": "fn_sep_ln_adm",    "desc": "firstname.lastname.admin",            "fmt": "{fn}{sep}{ln}{sep}admin"},
    {"id": "adm_fn_sep_ln",    "desc": "admin.firstname.lastname",            "fmt": "admin{sep}{fn}{sep}{ln}"},
    # ── Tier 12: Subdomain-admin (e.g. corp-ad → corp-adadmin) ────────────
    {"id": "sub_admin",        "desc": "subdomainadmin (no sep)",             "fmt": "{sub}admin",              "subdomain": True},
    {"id": "sub_sep_admin",    "desc": "subdomain.admin (with sep)",          "fmt": "{sub}{sep}admin",         "subdomain": True},
    {"id": "admin_sep_sub",    "desc": "admin.subdomain",                     "fmt": "admin{sep}{sub}",         "subdomain": True},
    # ── Tier 13: Contractor pattern - fn.COMPANY_ABBR (validated BR pattern) ─
    # Observed: contractors from external companies use firstname.company_code
    # e.g. pessoax.acme, personay.xpto, robotx.corpx, pessoax.xptoinc
    # Requires company_abbr parameter to be set.
    {"id": "fn_sep_co",        "desc": "firstname.company_abbr (contractor)", "fmt": "{fn}{sep}{co}",           "needs_company": True},
    {"id": "fi_sep_co",        "desc": "f.company_abbr (contractor)",         "fmt": "{fi}{sep}{co}",           "needs_company": True},
    {"id": "fn_co",            "desc": "firstnamecompany (no sep, contractor)","fmt": "{fn}{co}",                "needs_company": True},
    # ── Tier 14: compound firstname (pessoaxpersonay, personay) ──────────────────
    # Observed: pessoaxpersonay.corpx, personay.acme (compound first names)
    {"id": "fn2_sep_ln",       "desc": "fn1fn2.lastname (compound first)",   "fmt": "{fn2}{sep}{ln}",          "needs_fn2": True},
    {"id": "fn2_sep_fi",       "desc": "fn1fn2.l (compound+initial)",        "fmt": "{fn2}{sep}{li}",          "needs_fn2": True},
]

# Generic sector templates. Real target names are never stored.
# At runtime, usernames/passwords are derived from the domain and company
# strings the operator supplies, not from a hardcoded org list.
KNOWN_BR_DOMAIN_PATTERNS: dict[str, dict] = {
    "acme.example": {"primary": "fn.ln", "secondary": "filn", "notes": "energy sector; contractors often use externo.acme.example"},
    "externo.acme.example": {"primary": "fn.ln", "secondary": "filn", "notes": "third-party/contractors"},
    "acme.local": {"primary": "fn.ln", "secondary": None, "notes": "AD local domain"},
    "xpto.example": {"primary": "numeric_padded", "secondary": "fn.ln", "notes": "padded numeric employee ID"},
    "corpx.example": {"primary": "numeric", "secondary": "prefix+num", "notes": "internal prefix+num; contractor prefix+num"},
    "brandx.example": {"primary": "numeric_padded", "secondary": "fn.ln", "notes": "employee ID plus fn.ln email slug"},
    "empresax.example": {"primary": "fn.ln", "secondary": "fn-ln", "notes": "public sector; hyphenated short names"},
    "xptoinc.example": {"primary": "numeric", "secondary": "prefix+num", "notes": "internal prefix+num; contractor prefix+num"},
    "companyxpto.example": {"primary": "fn.ln", "secondary": None, "notes": "agribusiness"},
    "corp.example": {"primary": "fn.ln", "secondary": "fn", "notes": "education / training"},
}

# Generic role prefixes for employee-id style usernames. Not tied to any org.
KNOWN_BR_EMPLOYEE_ID_PREFIXES: dict[str, str] = {
    "int": "internal employee",
    "uni": "internal employee prefix",
    "trc": "contractor / outsourced",
    "crm": "CRM system user",
    "est": "intern",
    "apr": "apprentice",
    "svc": "service account",
    "eng": "engineering",
    "log": "logistics",
    "ops": "operations",
}

# Separators used when generating with SEP token
# Default separator: dot only. User can override with --separators.
DOMAIN_SEPARATORS = ["."]

# All available separators (for --separators all or interactive "all")
ALL_DOMAIN_SEPARATORS = [".", "_", "-", ""]

# Numeric suffixes for generic/service accounts
NUMERIC_SUFFIXES = [
    "01", "02", "1", "2", "00", "10", "99",
    "03", "04", "05", "06", "07", "08", "09",
    "11", "12", "13", "20", "21", "100", "0",
]

