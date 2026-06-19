# Microsoft SSO domain scanner

Detects which domains in `domains.txt` (8,195 entries) offer **Microsoft SSO**
("Sign in with Microsoft" / Azure AD / Entra ID / Office 365) on their login pages.

## Run
```
pip install requests
python3 detect.py domains.txt . 64    # infile  outdir  workers
```

## Output
- `microsoft_sso_domains.txt` — domains confirmed to offer Microsoft SSO (the deliverable)
- `results.csv` — every domain with evidence: `domain,ms_sso,evidence_url,signal_type,signal`

## Detection logic
A domain is flagged **YES** only on a real signal, not a bare "Microsoft" mention:
- **Strong URL signal:** redirect/link to `login.microsoftonline.com`,
  `login.windows.net`, `sts.windows.net`, `aadcdn.msauth.net`, etc.
- **Explicit button text:** "Sign in with Microsoft", "Continue with Microsoft",
  "Sign in with Azure AD", "Microsoft Entra", "Sign in with your organizational
  account", "Office 365", etc.

It fetches each domain's homepage, follows login-ish links, and probes common
login paths (`/login`, `/signin`, `/sso`, ...).

## Note
Requires open outbound internet. It cannot run inside a Claude Code environment
whose network egress is restricted to an allowlist (third-party hosts return
`403 host_not_allowed`).
