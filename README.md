# dsh-break-glass-settlement-proof

**Maintainer / Author：He Fangsheng (贺方升 / 贺去病; also known as Dosen) · [hequbing.com](https://www.hequbing.com)**

Offline, deterministic evidence for one narrow question: **does the supplied emergency-access session close within its declared lifetime, contain only allowlisted action/resource receipts, and revoke every declared grant before a fresh closure observation?**

The same headless core is exposed as a DSH bundle, standalone MCP stdio server, JavaScript API and CLI. Reports are redacted, content-addressed and verified after writing.

## Complementary boundary

Microsoft recommends limiting emergency access to true break-glass scenarios, monitoring every use, and using it only for the necessary amount of time. This plugin verifies a supplied settlement; it is not an identity provider or privileged-access manager.

- `dsh-principal-binding-proof` verifies which principal an evidence chain binds.
- `dsh-policy-waiver-proof` verifies why a policy exception is allowed.
- `dsh-audit-bundle` packages audit evidence.
- This plugin checks activation, bounded allowlisted actions, termination, declared grant revocation and fresh closure as one supplied session.

It never grants, activates, approves or revokes access; authenticates receipts; queries live identity infrastructure; or proves there were no undeclared actions or grants. `residualGrantCount: 0` is only a claim in the provided closure.

## Checks

- request, activation, termination, expiry and closure chronology;
- maximum session and expiry duration;
- contiguous ordered action receipts within the active interval;
- explicit action and resource allowlists;
- common session and principal binding across actions, grants and closure;
- every declared grant has a non-zero revocation receipt and valid grant/revoke times;
- supplied residual grant count, observer diversity and evidence freshness;
- secret/raw rejection, workspace confinement, symlink defense and content-addressed read-back.

## Use

```bash
npm test
npm run check
node bin/dsh-break-glass-settlement-proof.mjs inspect examples/settled.json
node bin/dsh-break-glass-settlement-proof.mjs verify examples/settled.json
```

```bash
dsh plugin --profile <profile> add /absolute/path/to/dsh-break-glass-settlement-proof
dsh plugin --profile <profile> add github:dongsheng123132/dsh-break-glass-settlement-proof#<commit>
```

DSH tools are `dsh_break_glass_inspect` and `dsh_break_glass_verify`. MCP tools are `break_glass_inspect` and `break_glass_verify`.

See [`examples/settled.json`](examples/settled.json). Only public IDs, timestamps, counts and SHA-256 bindings belong in a manifest. Never put credentials, account names, tokens, raw audit logs or business text in it.

References: [Microsoft Entra emergency access accounts](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access), [security operations for privileged accounts](https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts), [secure access practices](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-planning).
