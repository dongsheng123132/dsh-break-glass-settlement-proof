# Security Policy

Security fixes target the latest release on `main`.

This verifier is offline and non-destructive. It does not create, activate, approve, revoke or authenticate emergency access; query a live identity provider; or prove that supplied actions and grants are exhaustive. A `residualGrantCount` of zero is only a claim inside the supplied closure evidence until independently authenticated.

Inputs are capped at 4 MiB. Paths must be workspace-relative. Manifest and artifact paths reject symlinks. Report writes are exclusive, content-addressed, and verified by read-back. Secret-shaped fields and values, tokens, raw logs, prompts, bodies, content and chat text are rejected.

Report vulnerabilities privately through GitHub Security Advisories. Never attach credentials, account identifiers, production manifests, raw audit logs, or private business data.
