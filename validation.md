# Local validation evidence

Date: 2026-10-01. The reviewed changes were applied to public `main` at `27de0b13fc2daca78a46f861074654509da45e70` in an isolated clone. Checks below distinguish local editorial evidence from broader application and release validation.

| Check | Status | Scope |
|---|---|---|
| `python3 demo/check_portfolio_fixture.py` | Verified: exit 0 | Offline benign/synthetic or help check only |
| Broader capabilities | Not run | Backend/API, full stack, Docker, AI providers, external integrations and SIEM execution not run. Historical release statements and fixture statuses are not current-run results. |

## Retained output

```text
$ python3 demo/check_portfolio_fixture.py
PASS: 7 technique expectations, 6 IOC expectations, 9 graph edges
Scope: fixture consistency only; no application extraction, SIEM replay or AI accuracy claim
```
