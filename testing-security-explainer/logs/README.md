# Security Observability Evidence (Phase 2)

This folder contains learner-friendly, reproducible security evidence for the demo app.

## What To Read First
- `http-cases-summary.txt`: quick pass/fail status table for all security cases.
- `security-audit-events.txt`: extracted structured security audit lines.
- `redis-keys-after-tests.txt`: proof that refresh/session keys are stored in Redis.
- `cases/`: per-case HTTP status (`.code`) and response body (`.json`).

## Scenario Map
| Case | Endpoint | Expected | Evidence |
|---|---|---|---|
| `login-user-fail` | `POST /login` wrong password | `401` | `cases/login-user-fail.code` + `.json` |
| `login-user-ok` | `POST /login` valid user | `200` | `cases/login-user-ok.code` + `.json` |
| `login-admin-ok` | `POST /login` valid admin | `200` | `cases/login-admin-ok.code` + `.json` |
| `me-no-token` | `GET /me` without token | `401` | `cases/me-no-token.code` + `.json` |
| `admin-users-forbidden` | `GET /admin/users` as normal user | `403` | `cases/admin-users-forbidden.code` + `.json` |
| `admin-users-ok` | `GET /admin/users` as admin | `200` | `cases/admin-users-ok.code` + `.json` |
| `profile-owner-ok` | `GET /profile/{self}` | `200` | `cases/profile-owner-ok.code` + `.json` |
| `profile-owner-forbidden` | `GET /profile/{other}` | `403` | `cases/profile-owner-forbidden.code` + `.json` |
| `refresh-user-ok` | `POST /refresh` first use | `200` | `cases/refresh-user-ok.code` + `.json` |
| `refresh-user-replay` | `POST /refresh` replay old token | `401` | `cases/refresh-user-replay.code` + `.json` |
| `logout-user` | `POST /logout` with refresh token | `200` | `cases/logout-user.code` + `.json` |
| `refresh-after-logout` | `POST /refresh` after logout | `401` | `cases/refresh-after-logout.code` + `.json` |
| `refresh-invalid-token` | `POST /refresh` invalid token | `401` | `cases/refresh-invalid-token.code` + `.json` |

## Important For Learners
- Focus on `security-audit-events.txt` and `http-cases-summary.txt`.
- Ignore Spring auto-configuration condition logs for security learning; those are framework diagnostics.
- JWT values are dynamic; verify behavior using HTTP status + audit `type/outcome`.

## Reproduce
Run from project root:

```bash
bash testing-security-explainer/logs/reproduce.sh
```
