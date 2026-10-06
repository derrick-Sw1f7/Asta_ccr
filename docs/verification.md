# CCR 最终自验报告

交付版本：0.1.0。验证环境：Windows / PowerShell、Python 3.11.9，项目根目录 `C:\Users\Derrick Li\Desktop\asta`。客户端日期：2026-10-06，Asia/Hong_Kong。所有工作已自主完成，无待确认步骤。

## 设计自审结论

[架构设计](architecture.md) 包含模块划分、单向依赖表、备选方案及否决原因、最终目录树、全部接口定义、集中阈值依据、证明格式与判定算法。[证明 Schema](proof.schema.json) 为 Draft 2020-12；运行时不依赖 jsonschema，而做严格重建校验。

| 要求 | 结论 | 证据 |
| --- | --- | --- |
| 六项能力明确归属 | PASS | ingestion / segmentation / scoring / compression / proof / replay，CLI 提供 compress/replay/demo。 |
| 单向依赖、边界清晰、独立可测 | PASS | contracts 统一 dataclass/TypedDict/Protocol；AST 校验 DAG、公开依赖、无内部跨调；各能力有独立 pytest。 |
| 复杂度符合规模 | PASS | 单进程同步纯函数管线、JSON 审计归档、薄 I/O 适配器，无数据库／服务框架／必需网络。 |
| dropped 标签与 SHA-256、merged 来源列表 | PASS | Schema 必填；生成前完整复核，回放逐段、逐处置重算；完整唯一覆盖及来源顺序重建。 |
| 不可关闭底线 | PASS | 固定保护标签优先于配置；凭证原文保留；原始尝试、拒绝、后期重试全部 kept；权限和告警也 kept。极端阈值和恶意低分插件测试通过。 |
| 无 key／离线自动降级及日志 | PASS | missing_api_key / network_unavailable / invalid_plugin_response 独立测试；WARNING 包含 degraded=true 和原因，首次网络错误后本批停止网络调用。 |
| 完整回放与篡改失败 | PASS | 来源、规则最低风险、评分器、处置、所有指纹、JSONL context、统计、版本、时间重建；CLI 篡改失败退出 1；可信源和外部摘要检出完整重写。 |

纯核心未读取环境、文件、时钟或打印日志。可选模型只提升风险；保护内容不会发送到插件。结构化 arguments、role、kind、outcome 等字段完整保存在运行时 context JSONL，避免只保存正文导致的隐藏丢失。

## 阶段测试与自愈

每个阶段实际运行 pytest，记录来自执行输出：

| 阶段 | 实际结果 |
| --- | --- |
| 设计、公开契约、Schema 与自审 | `6 passed in 0.02s` |
| 配置／摄取／切分／摘要／评分／压缩核心 | `168 passed in 0.54s` |
| 证明、回放、CLI、插件、demo、架构集成 | `403 passed in 3.31s` |
| 最终全部文件与契约文档同步后的套件 | **`413 passed in 2.08s`** |

最终通过率：**413/413，100%**，无失败、跳过或 xfail。14 个测试文件覆盖全部核心与边缘模块；入口及版本由 CLI／架构测试覆盖。包括正常、空输入／边界、错误类型、篡改、配置极值、跨周期关联、插件故障与可信锚校验。

最终真实 pytest 摘要：

```text
........................................................................ [ 17%]
........................................................................ [ 34%]
........................................................................ [ 52%]
........................................................................ [ 69%]
........................................................................ [ 87%]
.....................................................                    [100%]
413 passed in 2.08s
```

修复过程：系统 Python 的现存旧 pyreadline 包与 3.11 不兼容，建立 `.venv` 隔离后运行成功。首次集成发现 demo 的任意计数断言与实际注入清单不一致，改为精确核对已知安全事件身份，并加强原始尝试／拒绝／重试完整保留；随后全绿。集成安全审查发现结构化字段输出和两侧 token 统计口径需要一致，已改为完整 JSONL；还补充工具 call_id 歧义、全角凭证赋值符、命名空间秘密字段、巨大非法模型分数和离线批次停止调用测试。未将任何失败状态留作交付。

## 50 轮端到端结果

种子 0、42、99、-1 各自生成 50 轮并在 pytest 中完成压缩 → 证明写入文件 → 读回 → replay，核对安全事件精确 ID、逐段原文与运行时元数据，全部通过。事件注入分散在早、中、晚周期，拒绝与重试相隔超过 50 个事件。

独立 CLI，种子 42 的真实结果：

```text
demo rounds=50 safety_segments=9 safety_events_lost=0 replay_valid=true seed=42
scorer=rule kept=59 merged=1 dropped=10
token_estimation=utf8_bytes_div_4_ceil_v1 original_tokens=7748 compressed_tokens=5138 ratio=1.5079797586609576
source_sha256=5048562507b884a6051bd6a8bccf70e2083728d7b263a021915bed111f8b373b
replay valid=true checked_segments=109
```

109 个来源事件／单元恰好覆盖：59 kept + 40 个重复来源合为 1 merged + 10 dropped。9 个安全事件全部无损 kept：3 个凭证、2 个权限变化、原始工具尝试／拒绝／晚期重试、1 个策略告警。额外保留普通独有消息。压缩比约 1.508，安全验证不以比率作为通过标准。

禁用 site-packages 的 `python -S` 加入 src 后运行同一 demo，退出 0、相同分区、零丢失且 replay 通过，验证核心没有第三方运行时依赖。

生成文件位于 artifacts/demo/events.jsonl、proof.json、context.txt。artifacts 被 .gitignore 忽略；仅虚构凭证用于样例。

## 初次交付的 README 命令逐条核对

从真实 README 提取全部 powershell 命令，按出现顺序逐条执行。**13/13 退出码为 0**，根目录与实际目录树一致。日志保存在本地 artifacts/readme-checks.json。

| README 命令（完整参数见 README） | 退出码 | 验证结果 |
| --- | --- | --- |
| python -m venv .venv | 0 | 独立环境存在。 |
| .venv\\Scripts\\python.exe -m pip install -e ".[dev]" | 0 | 成功安装可编辑 CCR、pytest，CLI entry point 存在。 |
| .venv\\Scripts\\python.exe -m pytest -q | 0 | 当次输出 413 passed in 2.46s。 |
| ccr.exe demo --output-dir artifacts/demo --seed 42 | 0 | 50 轮、9 个安全事件零丢失、回放成功。 |
| ccr.exe replay artifacts/demo/proof.json --events artifacts/demo/events.jsonl | 0 | 校验 109 单元。 |
| ccr.exe compress examples/session.jsonl --proof ... --context ... --config config.example.json --segment-id example-session | 0 | kept=6、merged=1、dropped=1；文件生成。 |
| ccr.exe replay artifacts/example/proof.json --events examples/session.jsonl | 0 | 校验 9 单元。 |
| python.exe -m ccr --help | 0 | 模块入口与三子命令可用。 |
| ccr.exe compress --help | 0 | 参数与 README 一致。 |
| ccr.exe replay --help | 0 | trusted events / 两个摘要参数可用。 |
| ccr.exe demo --help | 0 | output-dir / seed 参数可用。 |
| python.exe -c 无 key 子进程压缩示例 | 0 | rule；实际 stderr 为 WARNING degraded=true reason=missing_api_key segment_id=session。 |
| python.exe -c expected-source/proof 摘要参数示例 | 0 | 校验 9 单元。 |

摘要示例展示调用语法；正式信任锚必须来自独立可信存储，不能从待校验证明取值。README 清楚说明此边界。

## 实际篡改失败

对 demo 证明副本，将首个 dropped.content_sha256 改为全零，实际调用 replay：

```text
exit_code=1
replay valid=false checked_segments=109
difference path=$.dropped[0].content_sha256 detail=segment_id=s000011 fingerprint mismatch: expected_sha256=18405f18ee353416248c1c937dac5c5b65f4b08f62f87bfa800ea3db6dac9418 actual_sha256=0000000000000000000000000000000000000000000000000000000000000000
```

同时报告外层 proof_sha256 不符。日志未输出原始秘密或被丢弃正文。测试还验证攻击者重算外层摘要后改变标签、保留内容、来源清单、压缩比、评分器、版本或时间仍失败。

## 已核实的交付边界

当前真实运行测试环境是 Python 3.11.9；AST 验证全部源文件符合 Python 3.10 语法，未声称在未安装的 3.10 解释器实际跑过。核心不使用 tomllib 或其他 3.11 专属 API。

HTTP 插件通过 mock 覆盖正常响应、无 key、离线、超时、无效／过大响应和配置错误；没有使用真实 API key 或付费模型请求。自包含摘要提供一致性，来源真实性依赖可信原始事件或外部摘要。规则无法识别所有未标记未知凭证格式；已知安全信号与调用方声明标签的不可关闭保护已测试。证明包含原始丢弃内容及安全凭证，审计归档需按敏感数据管理。

README、MIT LICENSE、.gitignore、pyproject.toml（零运行时依赖、CLI entry point）、CONTRIBUTING.md、.env.example、配置示例、全部源代码、测试和设计／Schema 均已交付。

## README 入门改写后的验证

本次通读全部 src/ccr 源码、目录、安装配置、样例和相关测试，将 README 改为从项目用途、安装、完整演示到自定义事件的入门指南，补齐功能列表、技术栈、目录说明和常见问题。用工作笔记清单解释审计，用内容指纹解释 SHA-256；明确 JSONL 输出、证明体积、未知凭证、可选模型与可信来源校验的边界。

新增 examples/my-session.jsonl，包含两条相同角色的普通重复消息和一条显式临时消息，读者可以直接运行。docs/architecture.md 的目录树同步加入此样例。核心源文件、类型契约、阈值、CLI 参数和处理逻辑均未修改。

从新版 README 中提取全部 PowerShell 命令，在项目根目录按顺序执行，**16/16 命令退出码为 0**。覆盖版本检查、虚拟环境创建、可编辑安装、50 轮 demo 与回放、完整与最小样例压缩／回放、四个 help 命令、配置文件、无 key 的 --llm 降级与完整 pytest。核对过程中在当前进程临时清除模型 key，并在结束时恢复，未进行付费模型调用。完整命令与输出保存在本地 artifacts/readme-rewrite-checks.json。

真实结果：

```text
demo rounds=50 safety_segments=9 safety_events_lost=0 replay_valid=true seed=42
scorer=rule kept=59 merged=1 dropped=10
replay valid=true checked_segments=109

最小样例：scorer=rule kept=0 merged=1 dropped=1
replay valid=true checked_segments=3

413 passed in 1.26s
```

README 内 JSON / JSONL 代码示例均通过解析校验，引用的本地文件链接全部存在。Windows 命令已实际执行；Linux/macOS 的解释器路径换用方式仅作说明，未声称在这些平台运行过。初次交付部分的 13 条命令记录保留为历史，当前 README 的命令数以本节为准。
