# Dependency Confusion Recon

Tooling to assess a list of companies for **Dependency Confusion** exposure
(internal/private npm package names referenced in public code that are **not
claimed on the public npm registry**, and could therefore be hijacked).

> **Detection only.** No packages are ever published. Findings are intended for
> **responsible disclosure / bug bounty** reporting.

## Environment note

This environment runs under a restrictive network policy (host allowlist).
Company websites return `403 host_not_allowed`, so the JS-bundle approach is not
possible here. Reachable hosts include `registry.npmjs.org`, `github.com`,
`gitlab.com`, `raw.githubusercontent.com`. The scanner therefore works from
**public source repositories**.

## How it works (`repo-dep-scan.js`)

For each domain:
1. Derive a candidate org/user slug from the domain (its SLD).
2. List public repos on **GitHub** (and GitLab) for that slug.
3. Read `package.json` (root + a few common paths) and `.npmrc` per repo.
4. Collect every dependency name (scoped `@scope/name` and bare).
5. Query the public **npm registry**:
   - `CLAIMED` — exists on npm → safe
   - `SCOPE_OWNED` — scoped pkg missing but scope is registered → low risk
   - `VULNERABLE` — 404 + empty scope (or bare 404) → **hijackable**

```bash
node repo-dep-scan.js domains.txt repo-results.jsonl   # scan (resumable)
node report.js repo-results.jsonl report.md            # build report
```

The `dep-confusion-scan.js` fallback parses live JS bundles + source maps —
usable only when company domains are network-reachable.
