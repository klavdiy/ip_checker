# OWASP third-party notice

**FieldNet Kit (FNkit)** integrates **optional** OWASP-related workflows via `owasp_toolkit.py`.  
This repository remains **MIT** licensed. OWASP projects listed below are **not vendored** unless you install them separately.

## Components

| Component | Role in FieldNet Kit | Upstream license | How we use it |
|-----------|-------------------|------------------|---------------|
| [Amass](https://github.com/owasp-amass/amass) | Passive subdomain / asset discovery | Apache-2.0 | Subprocess `amass enum -passive` when binary is in `PATH` |
| [Nettacker](https://github.com/OWASP/Nettacker) | Optional port/service scan | **AGPL-3.0** | Subprocess only; user installs; default module `port_scan` |
| [WSTG](https://github.com/OWASP/wstg) | Testing methodology | CC-BY-SA-4.0 | Short checklist titles + links; **no substantial copy** of guide text |
| [Secure Headers](https://github.com/OWASP/www-project-secure-headers) | HTTP header guidance | Apache-2.0 (project site) | Built-in HEAD/GET checks: presence for common headers; minimal value checks for HSTS (`max-age` ≥ 1y), CSP (no `unsafe-inline`/`unsafe-eval`), `X-Frame-Options` (`DENY` vs `SAMEORIGIN`) |

## License compatibility with MIT (this repo)

- **Apache-2.0 (Amass, Secure Headers project):** Calling an external CLI or implementing checks against public header names does not require changing FieldNet Kit's license. Do not copy large chunks of upstream documentation into this repo without attribution and license compliance.
- **AGPL-3.0 (Nettacker):** Running Nettacker as a separate program via subprocess is the usual model for "user's tool on user's machine." If you **modify Nettacker** or **distribute** a combined product that includes Nettacker code, you must comply with AGPL (source offer, etc.). This project does **not** ship Nettacker source.
- **CC-BY-SA-4.0 (WSTG):** Linking and short summaries is fine; do not paste large sections of WSTG into this repo without CC-BY-SA attribution and ShareAlike considerations.

## Authorized use

Use menu **11** and CLI flags only on systems and targets you own or are explicitly authorized to test. Amass and Nettacker can generate significant third-party traffic.

## Attribution

When publishing results that cite OWASP methodology, link to:

- https://owasp.org/www-project-web-security-testing-guide/
- https://owasp.org/www-project-secure-headers/
