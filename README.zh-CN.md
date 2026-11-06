# dsh-break-glass-settlement-proof

作者 / 维护者：贺去病（贺方升 / Dosen）· [hequbing.com](https://www.hequbing.com)

这是一个离线、确定性的 DSH 证据层，只回答一个窄问题：**显式提供的紧急访问会话，是否在声明寿命内闭合，只包含 allowlist 中的动作/资源回执，并在新鲜的 closure 观察前撤销全部已声明授权？**

同一个无界面核心同时提供 DSH bundle、独立 MCP stdio、JavaScript API 和 CLI；报告脱敏、内容寻址，并在写后回读。

## 互补边界

Microsoft 建议 break-glass 只用于真正的紧急情况、每次使用都要监控，并把使用时间限制到绝对必要范围。本插件只核验 supplied settlement，不是身份系统或 PAM。

- `dsh-principal-binding-proof` 证明证据链绑定哪个主体；
- `dsh-policy-waiver-proof` 证明为何允许例外；
- `dsh-audit-bundle` 打包审计证据；
- 本插件把激活、限时 allowlisted 动作、终止、已声明授权撤销和新鲜 closure 合成一次会话结算。

它不会授予、激活、审批或撤销权限，不认证回执、不查询线上身份系统，也不证明没有未声明动作或授权。`residualGrantCount: 0` 只表示提供的 closure 声明。

## 核验项

- request、activation、termination、expiry、closure 时序；
- 会话与到期时长上限；
- 活跃区间内连续、有序的动作回执；
- 显式 action/resource allowlist；
- actions、grants、closure 的同一 session/principal binding；
- 每个已声明 grant 都有非零 revocation receipt 与合法撤销时序；
- 声明的残留授权数量、观察者多样性、证据新鲜度；
- 拒绝秘密/raw 字段、workspace 限界、symlink 防护、内容寻址回读。

```bash
npm test
npm run check
node bin/dsh-break-glass-settlement-proof.mjs verify examples/settled.json
dsh plugin --profile <profile> add github:dongsheng123132/dsh-break-glass-settlement-proof#<commit>
```

DSH 工具是 `dsh_break_glass_inspect`、`dsh_break_glass_verify`；MCP 工具是 `break_glass_inspect`、`break_glass_verify`。完整 manifest 见 [`examples/settled.json`](examples/settled.json)。禁止放账户名、密钥、token、原始审计日志或业务正文。

规范来源：[Microsoft Entra emergency access](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access)、[privileged account security operations](https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts)。
