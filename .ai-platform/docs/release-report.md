# Kirje v1.0.0 正式发布验收报告 (Release Acceptance Report)

- **产品名称**: Kirje (为 AI Agent 构建的本地优先邮件 CLI 与 MCP 服务端)
- **目标版本**: `v1.0.0` (GA)
- **规划路线**: `.ai-platform/specs/007-stable-v1-program` (T101 ~ T121)
- **验收日期**: 2026-11-24
- **当前状态**: **正式生产交付验收通过 (ACCEPTED & PRODUCTION READY)**

---

## 1. 交付目标达成矩阵 (Delivery Matrix)

| 阶段 / 里程碑 | 任务范围 | 交付成果与 Git Tag | 状态 |
| --- | --- | --- | --- |
| **Phase 1: 规划与规范基线** | T101-T103 | 架构边界规范、质量红线确立与安全门禁 | 已验收 |
| **Phase 2: 安全基线与合规** | T104-T108 | `cargo deny check` 全绿（零安全通告，开源协议合规），零密钥外泄保障 | `v1.0.0-alpha.1` |
| **Phase 3: 权威生命周期与协议收敛** | T109-T112 | 135+ 项权威状态测试、严格单所有者 Ed25519 签名验证、不可变证书与凭据轮换 | `v1.0.0-alpha.2` |
| **Phase 4A: 邮箱核心与会话图** | T113-T114 | SQLite 存储 v2、有界历史回填、软删除 Tombstones 机制、确定性线程图构建 | `v1.0.0-alpha.3` |
| **Phase 4B: Delivery Beta** | T115-T116 | Outbox 升级至 v3、不可变发件归档策略、`NeedsAttention` 与线下对账断言支持 | `v1.0.0-beta.1` |
| **Phase 4C: Policy & Provider Beta** | T117 | 两阶段账户策略引擎（默认只读、双重校验）、Provider 支持梯队分级（拒绝 OAuth2/JMAP 虚假宣传） | `v1.0.0-beta.2` |
| **Phase 5A: 契约冻结与迁移** | T118-T119 | 冻结 1.x 稳定契约、降级拒绝保护、金标准测试校验、跨平台构建发布验证 | `v1.0.0-rc.1` |
| **Phase 5B: 灾难恢复与加固** | T120 | 全面故障注入测试、不确定网络状态截断（`Ambiguous` 杜绝重发）、灾难备份恢复规程 | `v1.0.0-rc.2` |
| **Phase 5C: 正式生产交付** | T121 | 最终生产级编译、门禁全绿、生产发布日志与 release 资产验证 | `v1.0.0` |

---

## 2. 核心架构红线与质量保证

1. **绝对本地优先 (Local-First)**：
   - 绝不引入任何云端中继、外部代理控制平面、图形 UI 或嵌入式 LLM。
   - 所有邮件正文与附件默认视作**未受信外部输入 (Untrusted Input)**，采用有界流式解析并剥离潜在威胁。
2. **两阶段防线 (Plan / Approve / Apply State Machine)**：
   - 发件（SMTP）与远程邮箱变更（IMAP Move/Archive/Trash/Flag）严格采用两阶段状态机。
   - 交互式终端（TTY）强制作为审批的唯一合法入口，MCP stdio 模式在架构上被严格禁止调用任何审批方法。
3. **确定性故障处理与灾备恢复**：
   - 遇到网络不确定性或超时，立即置为 `Ambiguous` 终态，**绝不自动重试**，杜绝邮件重复发送或误删。
   - SQLite 存储支持严格的降级拦截（`user_version > SCHEMA_VERSION` 拒绝启动），提供完备的备份与恢复指引。
4. **两阶段安全策略防御**：
   - 新增账户默认策略为只读（`allow_remote_write: false`），需显式配置或启用。
   - 策略在规划期（Plan）与执行期（Apply）执行二次校验，策略变更即刻作废旧计划。
5. **合规与零凭据泄露**：
   - `cargo deny check`（advisories, bans, licenses, sources）全部通过。
   - 命令行参数与错误日志绝不打印密码或授权码。

---

## 3. 生产发布门禁验证结果

- **代码格式化**: `cargo fmt --all --check` -> **通过**
- **静态代码检查**: `cargo clippy --workspace --all-targets --all-features -- -D warnings` -> **通过（零警告）**
- **单元与集成测试**: `cargo test --workspace --all-features` -> **通过（200+ 测试 100% 通过）**
- **发布二进制编译**: `cargo build --workspace --all-features --release` -> **通过**
- **依赖与安全合规**: `cargo deny check` -> **通过**
- **诊断检查命令**: `kirje doctor --pretty` -> **通过（输出结构完整合法）**
- **稳定契约校验**: `kirje schema --pretty` -> **通过（契约版本 2026-09-04.1，20个根命令与25个MCP工具）**
