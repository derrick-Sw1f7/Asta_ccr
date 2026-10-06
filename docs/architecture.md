# CCR 架构设计与设计自审

状态：设计自审全部 PASS，实现与最终自验已完成；真实测试结果见 verification.md。目标运行环境为 Python 3.10+；运行时仅用标准库，pytest 为唯一开发依赖。CCR 证明的是已声明规则下的处置与来源一致性，不声称能识别所有未知秘密或证明任意文本永远没有未来价值。

## 1. 决策与模块边界

采用小型管线和函数式安全核心，辅以薄应用层、文件 CLI 与可选评分适配器。单次批处理完整会话，允许工具重试相隔几十轮。没有数据库、消息总线、异步工作队列或框架依赖。

```text
JSON / JSONL / demo
        |
        v
  cli (文件、参数、退出码) -----> adapters (env / urllib，可选)
        |                              |
        v                              | RiskPlugin 注入
  app (编排、时钟、WARNING 日志) <-------+
        |
        +--> ingestion --> segmentation --> scoring --> compression --> proof
        |                                                        |
        +--> replay <------------------------------------- JSON attestation
                |
                +--> 重建 ingestion / segmentation / rule score / compression / proof

所有模块 --> contracts (dataclass / TypedDict / Protocol)
纯核心 --> config (唯一阈值与评分常量) / integrity (规范 JSON、SHA-256、估算)
```

图中水平箭头是数据流，不是相互导入。实际依赖方向如下，禁止反向依赖和任何跨模块 `_private` 调用：

| 模块 | 职责 | 可依赖的项目模块（公开接口） |
| --- | --- | --- |
| contracts | 全部边界数据类型及 RiskPlugin 协议 | 无 |
| config | 集中阈值、固定评分与不可关闭标签；JSON 配置校验 | contracts |
| integrity | UTF-8 指纹、规范 JSON、证明摘要、token 估算 | contracts, ingestion |
| ingestion | 严格校验 JSON 事件、ID 唯一、标准化序列化 | contracts |
| segmentation | 按空行段落切分，保留原始字符；工具／结构化安全事件原子化 | contracts |
| scoring | 内容与结构化字段规则、跨周期拒绝重试关联、可选增量风险及降级通知 | contracts, config |
| compression | 不可关闭底线，确定性三类处置，按来源顺序输出 | contracts, config, integrity, ingestion, scoring |
| proof | 复核来源、评分与处置，构造完整证明 | contracts, config, integrity, ingestion, segmentation, scoring, compression |
| replay | 严格重建证明并列出差异，支持可信来源／可信摘要 | contracts, config, integrity, ingestion, segmentation, scoring, compression, proof |
| adapters | 环境变量和标准库 HTTP 可选插件，不进入默认核心 | contracts, integrity |
| app | 编排与 UTC 时间注入，将降级通知记录为 WARNING | 上述公开接口 |
| demo | 固定随机种子的 50 轮模拟会话 | contracts |
| cli | argparse、文件读写、JSON/JSONL、状态码 | app, adapters, demo, ingestion, replay, integrity, config |

每个模块都可直接导入、独立实例化或调用纯函数；测试只通过公开接口构造输入，不启动 CLI、网络或其他服务。scoring 不读取环境变量、不写日志、不打开文件；可选调用通过 RiskPlugin 注入，失败只返回 Degradation。compression / proof 完全确定性，无外部 I/O。外层 app 负责显式日志。

选择原因：问题需要可追溯的有限转换步骤，函数管线可以复算并定位每一步。契约集中避免隐式字典约定，轻量公共工具防止多处实现 SHA-256 与 JSON 规范化。独立 proof/replay 保持生成和校验入口可测，但共享确定性安全策略，避免两个策略实现漂移。

否决方案：

* 单一巨型 CLI：评分与文件网络耦合，难以独立测试，难以审计丢弃分支。
* 微服务／事件总线／数据库：单个会话批次不足以支撑其运维复杂度；来源归档 JSON 已满足初版回放。
* LLM 生成摘要作为主要压缩：非确定性、依赖网络，难以证明敏感事实没有被遗漏；初版只去重相同普通文本并丢弃显式低风险状态。
* 句子级无上下文切分：秘密字段名和值可能分离；采用段落切分且始终携带完整父事件评分背景。
* 每条拒绝只在紧邻重试时保留：跨轮次重试易漏检；所有拒绝事件都保留，在全周期上额外标记同工具／资源或明确 retry_of 的重试。
* SHA-256 等于数字签名：没有可信锚时不能证明来源真实性；提供外部 source_sha256 / proof_sha256 与可信 events 文件校验。
* 强制 TOML 运行时配置：3.10 缺少 tomllib；采用标准库 JSON 配置，并在 config.py 集中默认值。

## 2. 最终目录树

```text
CCR/                         # 当前工作目录（名字可不同），命令均从该目录执行
  README.md
  LICENSE
  CONTRIBUTING.md
  .gitignore
  .env.example
  pyproject.toml
  config.example.json
  docs/
    architecture.md
    proof.schema.json
    verification.md
  examples/
    session.jsonl
    my-session.jsonl          # README 入门样例，不改变核心逻辑
  src/ccr/
    __init__.py
    __main__.py
    contracts.py
    config.py
    integrity.py
    ingestion.py
    segmentation.py
    scoring.py
    compression.py
    proof.py
    replay.py
    adapters.py
    app.py
    demo.py
    cli.py
  tests/
    test_contracts.py
    test_config.py
    test_integrity.py
    test_ingestion.py
    test_segmentation.py
    test_scoring.py
    test_compression.py
    test_proof.py
    test_replay.py
    test_adapters.py
    test_app.py
    test_demo.py
    test_cli.py
    test_architecture.py
```

开发环境 `.venv/`、生成的敏感审计文件 `artifacts/` 均被忽略。安装 `python -m pip install -e ".[dev]"` 后可用 `ccr` 或 `python -m ccr`；测试配置的 pythonpath 指向 src。

## 3. 集中安全阈值与不可关闭底线

所有可调与固定评分数值定义在 config.py，不在其他模块散布魔法数。配置只接受 keep_score / merge_score；未知键、布尔数值、非有限数、越界值与 merge_score > keep_score 均报错。不能配置保护集合。

| 常量 | 默认值 | 依据 |
| --- | --- | --- |
| keep_score | 0.8 | 高于普通持久信息的 0.5，低于已知策略风险的 0.9；将高风险普通信息直接保留，与普通去重带拉开距离。0.5 会取消普通去重空间。 |
| merge_score | 0.3 | 在显式临时状态的 0.1 与普通持久文本的 0.5 之间，保证普通文本不会默认被丢弃；0.5 边界太近，易随评分变化丢掉持久信息。 |
| credential score | 1.0 | 最高风险，且标签本身触发无损保留，不依赖数值。 |
| refusal / rejected_tool_retry score | 1.0 | 权限边界证据与绕过尝试；全部保留拒绝事件是对指定底线的保守实现。 |
| permission_change score | 0.95 | 改变后续操作权限，接近最高风险；无损保留仍由保护标签保证。 |
| policy_violation score | 0.9 | 已知策略告警必须保留，低于实际秘密／权限变化只是排序含义。 |
| ordinary score | 0.5 | 缺乏安全信号并不等于可删除；默认仅允许相同普通消息去重，否则原文保留。结构化事件即使文本为空或标记临时，也至少取此分，避免删除 arguments／outcome 等字段。 |
| transient / empty score | 0.1 / 0.0 | transient 是调用方明确声明的临时状态；空内容没有文字信息。两者仍先检查全父事件和结构化字段的安全信号。 |

保护标签集合：credential、permission_change、rejected_tool_retry、policy_violation、refusal。均在任何配置及任何插件下无损保留。调用方安全标签只会增加保护；未知标签输入拒绝；无标签序列化为 ["none"]。凭证识别覆盖命名秘密字段、Bearer、常见 token 前缀、PEM 私钥、URI 密码及结构化 arguments；输入标签可声明规则未知的凭证。规则存在未知格式的检测边界，README 明确说明。

## 4. 切分、评分与三类判定

摄取只接受有唯一 event_id / role / content 的结构化事件，保留空白、Unicode 和原始字段。无静默过滤、无隐式字符串转换。message 按空行段落切分，分隔符保留在前一段，拼接可重建全文。工具、拒绝、权限与告警等结构化事件保持原子；每个子段携带完整父 Event，因此秘密跨段分布时所有子段得到保护。

规则扫描全父事件文本、arguments 和结构化标签（包括 target 等字符串字段中的已知凭证）；工具拒绝先扫描全会话，再关联后续显式 retry_of 或相同 tool_name/target 的调用。关联后原始尝试、拒绝和重试均标记 rejected_tool_retry 并保留。相同工具但未知 target 采取保守关联；不只比较紧邻内容或 args 顺序。非空 tool_call.call_id 必须唯一，tool_result 可引用同一 ID，防止重写关联。

LLM 默认关闭。启用但无 CCR_LLM_API_KEY 时返回 missing_api_key，网络／返回格式失败返回稳定原因。首次网络失败后本批剩余单元直接走规则，避免对离线端点重复等待。app 必须以 WARNING 输出 `degraded=true reason=... segment_id=...`，不打印异常载荷。所有保护单元不发送给插件；输入模型返回仅 PluginAssessment.value，有效范围 [0,1]。有效 LLM 风险只可取 max(rule, model)，不能修改标签、不能降低风险。证明记录有效值、理由和评分器，不联网复算 LLM 输出；replay 重算规则底线并检查增量评分约束及基于记录值的处置。

确定性处置依次执行：

1. 保护标签、结构化工具／动作元数据或 value >= keep_score：kept，内容逐字符保留，元数据完整输出。
2. 无保护且 value < merge_score：dropped，必须附 ["none"]、精确 UTF-8 SHA-256 和固定理由。
3. 中间分数：只有没有 tool_name/call_id/retry_of/target/arguments/outcome 信号的普通消息，才对同 role/kind/topic/transient 且文本完全相同的单元去重。出现次数 >= 2 才进入 merged，保留全部有序 source_segment_ids；不对近似文本作摘要。
4. 中间分数但无相同伙伴：kept，保守保存原文。

来源单元必须恰好被一个处置覆盖。输出顺序按第一来源位置保留；context 是规范 JSONL，每行含完整标准化父事件字段、该段精确 content、segment_id 与 source_segment_ids。这样仅存在于 arguments 的凭证及仅存在于 outcome 的拒绝在运行时上下文中也保留。merged 用第一来源事件字段，并列出全部来源段 ID；原始 exact content 始终可从 kept/merged/source archive 恢复。保护事件总在 kept 内，不依赖去重可恢复性。结构化输出有额外字节开销，压缩比允许小于 1，安全优先于压缩率。

## 5. 证明与完整回放

JSON Schema 草案位于 docs/proof.schema.json，使用 Draft 2020-12，additionalProperties=false。Schema 只是格式说明；核心运行时用标准库进行更强的严格结构校验、重建和语义校验，不依赖 jsonschema。

证明含 batch segment_id、UTC generated_at、ccr_version、scorer、阈值快照、全部标准化事件和 source_sha256、全部切分单元与分数、kept / merged / dropped、output_order、context、token_estimation、proof_sha256。dropped 的内容位于源归档中，运行时压缩上下文不含它；审计归档体积不承诺压缩，也因包含凭证需要按敏感文件管理。

指纹：sha256(exact_content.encode("utf-8"))；不做换行或 Unicode 归一化。规范 JSON：ensure_ascii=false、sort_keys=true、separators=(",", ":")、allow_nan=false，UTF-8 编码。source_sha256 对完整标准化事件数组求值，proof_sha256 对除该字段外完整文档求值。

token 方法为 utf8_bytes_div_4_ceil_v1：原始输入先按完整标准化事件（包含 arguments、角色、状态等）渲染规范 JSONL，UTF-8 总字节数／4 向上取整；压缩后 context JSONL 字节数同法。输入与输出均包含结构化信息，避免参数中的凭证在原始 token 数中被漏算；压缩输出额外来源 ID 的开销如实计入。此方法是跨语言可重现的粗估而非厂商 tokenizer，中文／代码会存在偏差。ratio = original_tokens / compressed_tokens；分母为 0 时 ratio=null，避免 NaN/Infinity。

生成前重新校验事件、切分、规则最低评分、单元覆盖和确定性压缩；不允许调用方向证明生成器塞入一个已把安全事件删掉的 CompressionResult。时间从 app 注入，使 proof 本身没有时钟 I/O。

replay 不信任证明声明：严格校验字段类型和格式、拒绝重复 JSON key / 非有限数；重算每段内容、UTF-8 指纹、标签、规则最低风险、评分器来源；重建 kept/merged/dropped、来源覆盖与顺序、context、估算、source/proof 摘要。校验版本、时间格式和阈值。差异输出字段路径、segment_id 和哈希，避免泄露原始秘密；任一差异 CLI 退出 1；文件／参数格式失败退出 2。

可选 `--events` 对可信原始事件比较 source_sha256；`--expected-source-sha256` / `--expected-proof-sha256` 接受用户外部保存的可信摘要。证明内部的非密钥摘要不是签名；若攻击者同时改内容和所有摘要，自包含校验不能认证原始作者。外部可信锚可以发现完整重写。不可网络复算 LLM 的历史输出，其真实性同样依赖可信证明摘要。

## 6. 验证计划与阶段门

阶段一：写设计、全部公开契约、Schema、自审，实际运行 pytest 契约测试。
阶段二：实现 ingestion/segmentation/config/integrity/scoring/compression，每模块正常／边界／失败单测，实际 pytest。
阶段三：proof/replay/adapter/app/cli/demo、完整 pytest；恶意阈值／插件、破坏证明、可信锚与错误日志均独测。
阶段四：逐条执行 README 命令、50 轮 CLI demo 与测试、完整 pytest；任何失败自行修复重跑，记录真实输出。

端到端模拟 50 轮（每轮 user+assistant，且分散插入工具与安全事件），固定种子随机挑选注入轮次，含凭证、权限、早期拒绝／后期重试、策略告警。断言所有规则安全事件的全部来源段都在 kept 且内容完全相同；证明落盘读回并 replay；普通重复与临时状态同时验证 merged/dropped。

## 7. 设计自审

| 清单 | 结论 | 理由／已消除的问题 |
| --- | --- | --- |
| 六项能力明确归属 | PASS | ingestion、segmentation、scoring、compression、proof、replay 分别负责，cli 提供可执行回放。 |
| 单向依赖、无内部跨调、模块独立可测 | PASS | 上述依赖 DAG；contracts 统一边界，纯函数可构造输入；增加 AST 架构测试禁止私有跨调／反向依赖。 |
| 复杂度适当 | PASS | 单进程同步批处理，六核心能力加契约／配置／摘要与薄边缘；否决服务化、数据库、LLM 摘要。 |
| dropped 标签+指纹、merged 来源列表 | PASS | TypedDict / Schema 强制字段；生成和回放重建完整唯一覆盖。 |
| credential 无损、拒绝保留不可关闭 | PASS | 固定保护标签先于阈值／LLM；所有拒绝保留，额外保护权限、告警与重试。 |
| 无 key／离线自动降级可观测 | PASS | 注入可选插件；missing_api_key／调用失败形成 Degradation；app WARNING degraded=true；独立测试。 |
| 完整 replay，篡改失败 | PASS | 全文和处置重建，校验来源／证明摘要；CLI 非零；增加可信源／外部摘要以处理同时重写指纹。 |

自审改进：没有采用仅 dropped 指纹的弱回放；没有用可调阈值作为秘密保护底线；没有依赖 Python 3.11 的 TOML 模块；没有将自校验冒充来源认证。所有项目 PASS 后自主继续实现。

## 8. 全部公开接口定义

下面是 src/ccr/contracts.py 的完整公开契约，接口字段均有类型与说明；实现后通过文档同步测试保证此块与源文件一致。

<!-- CONTRACTS_START -->
```python
"""Public module boundaries. Field comments document serialized meaning.

Modules exchange only these dataclasses/TypedDicts and the plugin Protocol;
no module reaches into another module's private implementation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, TypedDict, Union

JSONValue = Union[None, bool, int, float, str, list["JSONValue"], dict[str, "JSONValue"]]
SafetyLabel = Literal["credential", "permission_change", "rejected_tool_retry", "policy_violation", "refusal", "none"]
Role = Literal["system", "user", "assistant", "tool"]
EventKind = Literal["message", "tool_call", "tool_result", "permission_change", "policy_warning"]


class RequiredEventInput(TypedDict):
    """Required input event fields; IDs are unique within one session."""
    event_id: str  # Stable caller-assigned event ID.
    role: Role  # Originating conversation role.
    content: str  # Exact original text, including whitespace.


class EventInput(RequiredEventInput, total=False):
    """Optional ingestion fields; unknown keys are rejected to expose typos."""
    kind: EventKind  # Default message; tool events remain atomic.
    tool_name: str | None  # Name used to correlate a later retry.
    call_id: str | None  # Tool invocation identity.
    retry_of: str | None  # Earlier call ID or event ID, when known.
    outcome: Literal["accepted", "rejected", "unknown"]  # Structured denial signal.
    target: str | None  # Tool resource identity, when known.
    topic: str | None  # Optional grouping hint for identical-text merges.
    transient: bool  # Explicit disposable status; safety floors override it.
    safety_tags: list[SafetyLabel]  # Caller labels can add protection, never subtract it.
    arguments: dict[str, JSONValue] | None  # Structured tool arguments, checked for secrets.


@dataclass(frozen=True)
class Event:
    """Validated session event; content is never normalized or redacted."""
    event_id: str  # Unique source identity.
    role: Role  # Origin role.
    content: str  # Original text.
    kind: EventKind = "message"  # Semantic event category.
    tool_name: str | None = None  # Tool identity.
    call_id: str | None = None  # Invocation identity.
    retry_of: str | None = None  # Explicit retry reference.
    outcome: Literal["accepted", "rejected", "unknown"] = "unknown"  # Result status.
    target: str | None = None  # Resource identity.
    topic: str | None = None  # Merge grouping hint.
    transient: bool = False  # Low-risk disposable hint.
    safety_tags: tuple[SafetyLabel, ...] = ()  # Additional protection labels.
    arguments: dict[str, JSONValue] | None = None  # JSON-compatible structured arguments.


@dataclass(frozen=True)
class Segment:
    """Independently judged paragraph or atomic tool/security event."""
    segment_id: str  # Deterministic ID: s000001, s000002, ... in stream order.
    event: Event  # Complete parent event, so split children inherit its safety context.
    index: int  # Zero-based paragraph position in the parent event.
    content: str  # Exact slice; concatenation reconstructs the event content.


@dataclass(frozen=True)
class Thresholds:
    """Configurable score cutoffs; protected labels always bypass cutoffs."""
    keep_score: float  # Score at/above this value is kept.
    merge_score: float  # Score below this value may be dropped when unprotected.


@dataclass(frozen=True)
class Score:
    """Recorded importance and deterministic safety classification."""
    segment_id: str  # Corresponding source segment ID.
    value: float  # Finite risk in [0, 1]; LLM may only raise rule risk.
    safety_tags: tuple[SafetyLabel, ...]  # Sorted labels, or singleton none.
    reasons: tuple[str, ...]  # Rule reasons plus optional llm_risk_raise.
    scorer: str = "rule"  # rule or llm:<model> for this unit.


@dataclass(frozen=True)
class Degradation:
    """Pure-core notice emitted as WARNING by the outer application."""
    reason: str  # Stable reason code; never raw exception text or secrets.
    segment_id: str | None = None  # Affected unit, or whole scorer setup.


@dataclass(frozen=True)
class ScoringResult:
    """Complete scoring result, including observable fallback information."""
    scores: tuple[Score, ...]  # One score per source segment, in order.
    scorer: str = "rule"  # rule if no plugin call succeeded, otherwise llm:<model>.
    degradations: tuple[Degradation, ...] = ()  # Notices for the I/O boundary.


@dataclass(frozen=True)
class PluginAssessment:
    """Untrusted optional model output; validated before use."""
    value: float  # Claimed risk in [0, 1].


class RiskPlugin(Protocol):
    """Injected plugin interface; network implementation lives in adapters."""
    model_id: str  # Public model identifier, without secrets.

    def assess(self, segment: Segment) -> PluginAssessment:
        """Assess an unprotected unit; failures trigger per-unit rule fallback."""
        ...


@dataclass(frozen=True)
class KeptUnit:
    """Losslessly retained source unit."""
    segment_id: str  # Original segment ID.
    content: str  # Exact source slice.


@dataclass(frozen=True)
class MergedUnit:
    """Identical unprotected text stored once with all source identities."""
    segment_id: str  # Deterministic merged ID: m000001, ...
    source_segment_ids: tuple[str, ...]  # Ordered provenance, at least two IDs.
    content: str  # Identical source text, preserved once.


@dataclass(frozen=True)
class DroppedUnit:
    """Explicit discarded unit; source archive enables fingerprint replay."""
    segment_id: str  # Original segment ID.
    safety_tags: tuple[SafetyLabel, ...]  # Required; only none may be dropped.
    content_sha256: str  # SHA-256 of exact UTF-8 content.
    reason: str  # Stable disposition reason: below_merge_threshold.


@dataclass(frozen=True)
class OutputRef:
    """Chronological compressed-context reference."""
    kind: Literal["kept", "merged"]  # Referenced collection.
    segment_id: str  # Kept or merged ID.


@dataclass(frozen=True)
class CompressionResult:
    """Complete deterministic partition, with compressed text rendering."""
    kept: tuple[KeptUnit, ...]  # No-loss units.
    merged: tuple[MergedUnit, ...]  # Deduplicated ordinary units.
    dropped: tuple[DroppedUnit, ...]  # Explicit, hashed disposals.
    output_order: tuple[OutputRef, ...]  # First-occurrence order of retained output.
    context: str  # Canonical JSONL render of exact slices and complete event metadata.


class ProofScore(TypedDict):
    """Serialized score and segment provenance."""
    segment_id: str  # Source segment identity.
    event_id: str  # Parent identity.
    index: int  # Paragraph index.
    content: str  # Exact source slice for independent replay.
    content_sha256: str  # SHA-256 UTF-8 fingerprint.
    value: float  # Recorded score.
    safety_tags: list[SafetyLabel]  # Rule-derived labels.
    reasons: list[str]  # Recorded rule/plugin explanation codes.
    scorer: str  # Per-unit scoring identity.


class ProofKept(TypedDict):
    """Serialized retained unit and integrity data."""
    segment_id: str  # Source identity.
    content: str  # Exact retained content.
    content_sha256: str  # UTF-8 fingerprint.


class ProofMerged(TypedDict):
    """Serialized merge with complete ordered source provenance."""
    segment_id: str  # Merge identity.
    source_segment_ids: list[str]  # All contributing source segment IDs.
    content: str  # Common source content.
    content_sha256: str  # UTF-8 fingerprint.


class ProofDropped(TypedDict):
    """Serialized discard; labels and content hash are mandatory."""
    segment_id: str  # Source identity.
    safety_tags: list[SafetyLabel]  # Only none is admissible.
    content_sha256: str  # Recomputed from the source during replay.
    reason: str  # Deterministic discard reason.


class ProofOutputRef(TypedDict):
    """Serialized compressed output order."""
    kind: Literal["kept", "merged"]  # Referenced collection.
    segment_id: str  # Referenced identity.


class ProofThresholds(TypedDict):
    """Serialized cutoff snapshot, preventing configuration drift."""
    keep_score: float  # Retention cutoff.
    merge_score: float  # Drop/merge cutoff.


class TokenEstimate(TypedDict):
    """Reproducible estimate, not an actual model tokenizer measurement."""
    method: str  # utf8_bytes_div_4_ceil_v1.
    original_tokens: int  # ceil(normalized complete source JSONL UTF-8 bytes / 4).
    compressed_tokens: int  # ceil(rendered context UTF-8 bytes / 4).
    ratio: float | None  # original/compressed; null when compressed is zero.


class ProofDocument(TypedDict):
    """Self-contained replayable attestation; digest is not a signature."""
    schema_version: str  # Format version: 1.
    segment_id: str  # Caller-provided compression batch/session identity.
    generated_at: str  # UTC ISO-8601 timestamp.
    ccr_version: str  # Generator version.
    scorer: str  # rule or llm:<model>.
    thresholds: ProofThresholds  # Exact cutoff snapshot.
    token_estimation: TokenEstimate  # Recomputed compression ratio.
    events: list[EventInput]  # Full normalized source archive.
    source_sha256: str  # Canonical normalized-events JSON SHA-256.
    segments: list[ProofScore]  # Full source units and scoring evidence.
    kept: list[ProofKept]  # Lossless units.
    merged: list[ProofMerged]  # Merged units and source IDs.
    dropped: list[ProofDropped]  # Discarded units, labels and hashes.
    output_order: list[ProofOutputRef]  # Deterministic chronology.
    context: str  # Exact rendered compressed context.
    proof_sha256: str  # Canonical document digest excluding this field.


@dataclass(frozen=True)
class ReplayDifference:
    """Safe audit diagnostic: paths/IDs/digests, never source contents."""
    path: str  # JSON field path of a mismatch.
    detail: str  # Sanitized mismatch description.


@dataclass(frozen=True)
class ReplayResult:
    """CLI-independent complete verification outcome."""
    valid: bool  # True only when every invariant passed.
    checked_segments: int  # Number of source units replayed.
    differences: tuple[ReplayDifference, ...] = ()  # All safe differences collected.


@dataclass(frozen=True)
class RunResult:
    """Application result without file I/O."""
    proof: ProofDocument  # Generated attestation.
    compression: CompressionResult  # Context and disposition partition.
    scoring: ScoringResult  # Scores and downgrade notices.
```
<!-- CONTRACTS_END -->
