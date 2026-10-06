# CCR：让长对话的整理过程有据可查

CCR 是一个用 Python 编写的**会话记录整理工具**。它帮助 AI Agent（能持续对话并调用工具的 AI 助手）减少需要携带的历史记录，同时留下可以核对的处理记录。

长对话像一本不断增厚的工作笔记。直接删页或写成摘要，可能丢掉“这里出现过密码”“这次操作被拒绝”“后来又重试了”等重要线索。CCR 的做法类似**整理笔记时同时开一张清单**：标明哪些原样保留、哪些重复内容合并、哪些临时内容移出，并保存原始记录供以后检查。

输入一份会话记录，CCR 会输出两份文件：供后续使用的整理后上下文，以及解释处理过程的审计证明。它目前提供本地命令行工具和 Python 接口，按整批记录处理；接入 Agent 时，需要由你的程序收集记录并调用它。

全名 **Context Compression with Replayable attestation**，意思是“压缩上下文，并留下能重新核对的证明”。项目优先保证已识别的安全记录不会丢失，每次移出内容都有记录。

## 核心功能

- **读取会话记录**：支持 JSON 数组或 JSONL 文件，检查格式、字段和重复编号。
- **拆分并判断重要性**：普通消息按空行分成段落；明确标记为工具调用、工具结果等类型的记录整条处理。用规则识别密码、密钥、权限变化、操作拒绝、后续重试和策略告警。
- **保护安全记录**：已识别或主动标记的安全内容原文保留，角色、工具参数、拒绝状态等字段也保留；修改阈值或使用模型评分都不能取消这种保护。
- **减少重复与临时内容**：完全相同且角色、主题等分组信息一致的普通文本可以合并；默认可移出无安全标签的临时状态或空消息。独有的普通消息默认保留。
- **生成处理清单**：每段内容都有去向，合并记录带全部来源编号，移出记录带安全标签和内容指纹。
- **离线重新核对**：`replay` 重算切分、规则、处置和指纹，校验失败时返回非零退出码。可额外对照独立保存的原始记录或摘要。
- **可选模型评分**：默认无需 API key；也可启用大语言模型（LLM）辅助提高重要性评分，无 key 或网络故障时自动退回规则并记录原因。

三类处理结果可以这样理解：

| 名称 | 通俗含义 | 默认处理例子 |
| --- | --- | --- |
| `kept` | 原样留下 | 密钥、权限变更、拒绝记录、独有普通信息 |
| `merged` | 重复内容只放一份，并列出所有出处 | 同一角色重复说同一段项目说明 |
| `dropped` | 从后续上下文中移出，原文仍在审计证明里 | 标记为临时的“正在等待”，且没有安全信号 |

## 技术栈

| 技术 | 在项目中的用途 |
| --- | --- |
| Python 3.10+ 标准库 | 全部核心逻辑；运行时没有第三方库依赖 |
| `dataclass` / `TypedDict` | 明确描述事件、评分和结果的字段，方便接入与测试 |
| `argparse`、JSON / JSONL | 命令行参数、输入记录和输出文件 |
| `hashlib` / SHA-256 | 为内容生成“指纹”，用于检查内容是否与记录一致 |
| `urllib`（可选） | 调用兼容的模型 HTTP 接口，无需安装模型 SDK |
| setuptools | 安装项目并提供 `ccr` 命令入口 |
| pytest（开发依赖） | 验证安全保护、压缩、回放、CLI 和插件降级 |

处理流程如下；文件读写、日志和可选网络请求位于外层，核心判断可独立测试：

```text
会话文件 JSON / JSONL
          |
          v
 读取检查 -> 分段 -> 规则评分 -> 保留 / 合并 / 移出
                       ^                   |
                  可选模型辅助             +--> context.jsonl：后续使用的上下文
                                           +--> proof.json：原始记录与处理清单
                                                      |
                                                      v
                                    replay：重新计算并逐项核对
```

## 环境要求与安装

需要 **Python 3.10 或更新版本**，并带有 `pip` 和 `venv`。默认运行、演示和回放不需要模型账户、API key、数据库或 GPU。首次安装通常需要联网获取构建工具和 pytest；安装完成后，默认规则模式可以离线运行。

以下完整示例使用 **Windows PowerShell**。先取得项目文件，在 IDE 中打开项目文件夹，并在包含 `pyproject.toml` 和 `README.md` 的**项目根目录**打开终端。所有相对路径都从这里计算。

先检查 Python 版本：

```powershell
python --version
```

创建独立环境并安装项目和测试工具：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

`.venv` 可以理解为项目专用的“工具箱”，避免和电脑上其他 Python 项目混用依赖。`-e` 表示直接使用当前源码，`[dev]` 额外安装测试工具。下文始终调用环境里的解释器，**无需运行激活脚本**。

Linux/macOS 的虚拟环境解释器通常位于 `.venv/bin/python`：创建环境时使用 `python3`，其余示例将 `.\.venv\Scripts\python.exe` 换成 `.venv/bin/python`，命令参数保持相同。本 README 的实际命令核对在 Windows 上完成。

## 快速上手

### 1. 先跑一个完整演示

安装完成后直接运行：

```powershell
.\.venv\Scripts\python.exe -m ccr demo --output-dir artifacts/demo --seed 42
```

程序会生成 **50 轮**对话，将虚构凭证、权限变化、早期拒绝与晚期重试等记录分散插入，再完成整理、写入证明、读回核对。`--seed 42` 固定演示数据，方便重复检查；证明中的生成时间会随运行变化。

输出中的关键两行如下：

```text
demo rounds=50 safety_segments=9 safety_events_lost=0 replay_valid=true seed=42
scorer=rule kept=59 merged=1 dropped=10
```

这表示 9 个安全单元全部保留，证明核对成功；59 个单元原样留下，普通重复内容形成 1 组，10 个临时单元移出。`merged=1` 统计的是合并组数，每组可能包含多条来源记录。

输出文件位于自动创建的目录中：

| 文件 | 用途 |
| --- | --- |
| `artifacts/demo/events.jsonl` | 演示的原始会话记录 |
| `artifacts/demo/context.txt` | 整理后的上下文，**内容格式是 JSONL** |
| `artifacts/demo/proof.json` | 原始内容、评分、处理清单和校验信息 |

### 2. 单独核对生成的证明

```powershell
.\.venv\Scripts\python.exe -m ccr replay artifacts/demo/proof.json --events artifacts/demo/events.jsonl
```

成功时输出：

```text
replay valid=true checked_segments=109
```

“回放”是依据原始记录重新计算整理过程并核对清单，**不会重新执行会话里的工具调用**。`--events` 再对照一份原始事件文件；实际使用时，应将这份文件独立、可信地保存。

### 3. 整理仓库自带的小样例

```powershell
.\.venv\Scripts\python.exe -m ccr compress examples/session.jsonl --proof artifacts/example/proof.json --context artifacts/example/context.jsonl --segment-id example-session
.\.venv\Scripts\python.exe -m ccr replay artifacts/example/proof.json --events examples/session.jsonl
```

样例包含 9 条事件，结果为 `kept=6 merged=1 dropped=1`。`--proof` 指定审计文件，`--context` 指定整理后的文件，`--segment-id` 是本次处理的名称，可自定义。输出目录会自动创建；同名输出文件会被覆盖，需要保留多次结果时请使用不同路径。

## 使用自己的会话记录

**事件**就是一条消息或一次工具动作。CCR 输入的是按发生顺序排列的事件。JSONL 指“每个物理行一个 JSON 对象”；也可以把对象放进一个 JSON 数组文件。

仓库提供了最小样例 [examples/my-session.jsonl](examples/my-session.jsonl)，内容如下（前两条使用相同角色，所以可以演示普通文本去重）。可以先直接运行，再复制到自己的文件中编辑；保存格式使用 **UTF-8、无 BOM**：

```jsonl
{"event_id":"e1","role":"assistant","content":"The project uses Python."}
{"event_id":"e2","role":"assistant","content":"The project uses Python."}
{"event_id":"e3","role":"assistant","content":"Waiting for the next step.","transient":true}
```

然后运行：

```powershell
.\.venv\Scripts\python.exe -m ccr compress examples/my-session.jsonl --proof artifacts/my-session/proof.json --context artifacts/my-session/context.jsonl
.\.venv\Scripts\python.exe -m ccr replay artifacts/my-session/proof.json --events examples/my-session.jsonl
```

默认结果为 `kept=0 merged=1 dropped=1`：前两条重复文本合并，第三条临时消息移出，但三条原文均保存在证明中。

三个必填字段：

| 字段 | 含义与要求 |
| --- | --- |
| `event_id` | 每条事件的唯一编号，不能重复或为空 |
| `role` | 来源：`system`（系统）、`user`（用户）、`assistant`（助手）、`tool`（工具） |
| `content` | 原始正文，必须是字符串；正文换行在 JSON 中写成 `\n` |

常用可选字段：

| 字段 | 用途 | 省略时 |
| --- | --- | --- |
| `kind` | `message`、`tool_call`、`tool_result`、`permission_change`、`policy_warning` | `message` |
| `tool_name` / `arguments` | 工具名称与参数；参数是 JSON 对象 | `null` |
| `call_id` / `retry_of` | 一次调用的编号／所重试的先前调用或事件编号 | `null` |
| `outcome` | `accepted`、`rejected`、`unknown`；明确表达接受或拒绝 | `unknown` |
| `target` / `topic` | 操作目标／消息主题；有助于关联重试或分组重复内容 | `null` |
| `transient` | `true` 表示明确可移出的临时消息；安全和结构化动作保护仍优先 | `false` |
| `safety_tags` | 主动声明安全内容，如 `["credential"]` | `[]` |

请使用 `safety_tags` 标记规则可能不认识的秘密。受保护的标签有 `credential`、`permission_change`、`rejected_tool_retry`、`policy_violation`、`refusal`；`none` 表示未声明保护，不能与保护标签并用。把已识别的秘密标成 `none` 不会取消规则保护。

非空 `tool_call.call_id` 必须唯一，`tool_result` 可引用同一编号。文件中的未知字段、重复 JSON 键、错误类型、非法标签或非有限数会报错；不要直接将第三方聊天导出文件传入，应先映射为上述格式。

## 常用命令与配置

### 查看帮助

```powershell
.\.venv\Scripts\python.exe -m ccr --help
.\.venv\Scripts\python.exe -m ccr compress --help
.\.venv\Scripts\python.exe -m ccr replay --help
.\.venv\Scripts\python.exe -m ccr demo --help
```

| 子命令 | 做什么 | 主要参数 |
| --- | --- | --- |
| `compress` | 整理输入记录，输出上下文和证明 | 输入文件、`--proof`、`--context`；可选 `--config`、`--segment-id`、`--llm` |
| `replay` | 重新计算并校验证明 | 证明文件；可选 `--events`、`--expected-source-sha256`、`--expected-proof-sha256` |
| `demo` | 生成并验证 50 轮演示 | 可选 `--output-dir`、`--seed` |

安装还会生成 `ccr` 入口，例如 Windows 中的 `.\.venv\Scripts\ccr.exe`。它与上面的 `python.exe -m ccr` 使用同一套命令。

### 调整普通内容的保留阈值

可以从 [config.example.json](config.example.json) 开始：

```json
{
  "keep_score": 0.8,
  "merge_score": 0.3
}
```

重要性分数从 0 到 1，越高越值得保留。没有保护标签和结构化动作字段的普通内容，按以下规则处理：

| 分数位置 | 处置 |
| --- | --- |
| 大于或等于 `keep_score` | 原样保留 |
| 小于 `merge_score` | 从上下文移出，写入清单 |
| 两个阈值之间 | 满足相同文本和分组条件则合并，否则保留 |

默认普通持久信息得分 0.5，明确临时状态得分 0.1，空正文得分 0。因此默认不会移出独有普通信息。**保护标签和结构化工具／动作字段在阈值之前检查**，这些记录保持原样。

指定配置文件运行：

```powershell
.\.venv\Scripts\python.exe -m ccr compress examples/session.jsonl --proof artifacts/configured/proof.json --context artifacts/configured/context.jsonl --config config.example.json
```

两个值须满足 `0 <= merge_score <= keep_score <= 1`。提高 `merge_score` 到 0.5 以上可能移出无保护的普通信息；新手建议保持默认值。合并只处理完全相同的普通文本，并要求角色、事件类型、主题和临时标记一致，不生成近似文本摘要。默认值与取值依据集中在 [config.py](src/ccr/config.py)。

### 可选：让模型辅助评分

只在 `compress` 加上 `--llm` 时启用模型。模型可以建议保留更多内容，不能降低规则评分或改变安全标签。

密钥只从环境变量 `CCR_LLM_API_KEY` 读取。请在 IDE 的终端／进程环境中配置；[.env.example](.env.example) 是变量说明模板，程序**不会自动读取 `.env` 文件**。

| 环境变量 | 用途 | 默认值 |
| --- | --- | --- |
| `CCR_LLM_API_KEY` | 可选评分接口的密钥 | 空；启用后降级到规则 |
| `CCR_LLM_MODEL` | 模型名称，会记录在证明里 | `gpt-4o-mini` |
| `CCR_LLM_BASE_URL` | 兼容 Chat Completions 的 API 根地址 | `https://api.openai.com/v1` |
| `CCR_LLM_TIMEOUT` | 每次请求的超时秒数，须为有限正数 | `5` |

调用方式：

```powershell
.\.venv\Scripts\python.exe -m ccr compress examples/session.jsonl --proof artifacts/llm/proof.json --context artifacts/llm/context.jsonl --llm
```

未设置 key 时仍能成功完成整理，日志中会有：

```text
WARNING degraded=true reason=missing_api_key segment_id=session
```

`degraded=true` 表示“此次使用规则代替模型”。网络故障的原因是 `network_unavailable`，无效模型响应是 `invalid_plugin_response`；首次网络失败后，本批剩余内容使用规则。已经成功评分的内容仍保留其记录。

已识别的受保护单元不会发给模型；其余文本会发送到配置的接口，未知格式的秘密可能需要你主动标记。回放可以离线检查历史模型分数满足规则底线，不重新调用模型。

## 读懂证明与校验结果

“压缩证明”是一张带原始附件的处理清单。它包括批次名称、生成时间、CCR 版本、评分器、阈值、原始事件、分段内容、评分和三类处置。

SHA-256 可以理解为**内容指纹**：根据原文计算出固定长度的摘要，再次计算即可检查是否与记录一致。每个 `dropped` 单元都带标签与指纹，每个 `merged` 单元都带 `source_segment_ids`，说明合并来自哪些段。

`replay` 检查来源是否完整、每段是否有且只有一种处置、安全标签是否正确、保留与合并内容是否匹配，并重新核对指纹、上下文和统计。命令的退出码含义：

| 退出码 | 含义 | 下一步 |
| --- | --- | --- |
| `0` | 命令执行成功；对于 replay 表示校验通过 | 可以使用结果 |
| `1` | 证明或可信来源／摘要不一致 | 根据差异路径核查来源和证明 |
| `2` | 输入格式、路径、参数或文件读写错误 | 检查命令和文件格式 |

校验的是**证明内保存的 `context`**；单独的上下文文件如被改动，不会通过读取证明自动发现。接入程序应使用已验证证明内的上下文，或再核对外部文件与它一致。

指纹能检查一致性，但不是作者签名。如果有人同时改写原始内容、处置和全部指纹，自包含校验不能独自证明来源真实。需要更强的来源保障时，独立保存可信事件文件，使用 `--events` 对照；或在生成时独立保存 CLI 输出的 `source_sha256` / `proof_sha256`，以后传给相应 `--expected-...` 参数。摘要必须是 64 个小写十六进制字符，不能从待验证的证明中临时提取作为信任依据。

## 目录结构

下面列出全部源码模块和主要资源。`.venv/` 与 `artifacts/` 是使用过程中生成的目录，已被 `.gitignore` 排除。

```text
项目根目录/
├── README.md                 # 入门与使用说明
├── pyproject.toml            # Python 版本、安装、CLI 与测试设置
├── config.example.json       # 默认阈值示例
├── .env.example              # 可选模型环境变量说明
├── .gitignore                # 排除环境、生成产物和本地密钥文件
├── LICENSE                   # MIT 许可证
├── CONTRIBUTING.md           # 贡献与测试约定
├── examples/
│   ├── session.jsonl         # 包含安全与普通事件的可运行样例
│   └── my-session.jsonl      # 三条事件的入门样例
├── docs/
│   ├── architecture.md       # 架构理由、全部接口与设计自审
│   ├── proof.schema.json     # 证明文件的格式定义
│   └── verification.md       # 交付与文档验证记录
├── src/ccr/
│   ├── __init__.py           # 包与版本
│   ├── __main__.py           # python -m ccr 入口
│   ├── cli.py                # 参数与文件读写
│   ├── app.py                # 串起处理步骤，记录时间和日志
│   ├── contracts.py          # 各步骤共用的数据类型
│   ├── config.py             # 阈值、评分常量与安全底线
│   ├── ingestion.py          # 读取并检查事件结构
│   ├── segmentation.py       # 将消息拆为可判断的段落
│   ├── scoring.py            # 安全规则、重试关联与可选增量评分
│   ├── compression.py        # 保留、合并、移出与上下文输出
│   ├── integrity.py          # 指纹、严格 JSON 与 token 粗估
│   ├── proof.py              # 生成完整处理证明
│   ├── replay.py             # 重新计算并核对证明
│   ├── adapters.py           # 可选模型的环境与 HTTP 接口
│   └── demo.py               # 50 轮模拟数据与安全保留检查
└── tests/                    # 各模块、CLI、架构与端到端测试
```

详细设计见 [架构文档](docs/architecture.md)，机器可读格式见 [证明 Schema](docs/proof.schema.json)，真实验证记录见 [自验报告](docs/verification.md)。

## 常见问题

### 需要 API key 才能用吗？

默认不用。演示、普通压缩和回放都能使用本地规则完成。只有加上 `--llm` 才会读取模型配置；缺少 key 时会自动退回规则。

### 为什么 PowerShell 找不到 `python`、`ccr`，或禁止激活脚本？

找不到 `python` 时，确认已安装 Python 3.10+ 并加入 PATH，再重新打开终端。找不到 `ccr` 时，通常是虚拟环境未激活；本指南直接使用 `.\.venv\Scripts\python.exe -m ccr`，无需配置命令路径或运行 `Activate.ps1`。若该解释器不存在，请先完成创建环境和安装步骤。

### 提示 `input_error=file_io` 或 `input_error=invalid_data` 怎么办？

先确认终端在项目根目录，输入文件存在且输出位置可写。输入、证明、上下文须使用不同路径。格式错误时，检查 UTF-8 无 BOM、每行合法 JSON、必填字段、编号唯一、布尔值写成 `true` / `false`，以及字段名没有拼写错误。CLI 为避免泄露正文，只显示简短错误类别。

### 为什么有些重复内容仍然保留？

安全内容和结构化工具记录始终保留，重复也不会合并。普通消息必须文本完全相同且角色、类型、主题、临时标记一致，并落在可合并的评分范围。不同角色说同样一句话，或多了空格，都会保持各自记录。

### 为什么证明比原文件大？压缩比又是什么意思？

证明保留全部原始内容，还增加处理清单和校验信息，体积可能更大。减少的是后续使用的上下文。

token 是模型计算输入长度的单位。CCR 使用可复算的粗估：将完整标准化原始事件（补齐默认字段后）的 JSONL 和输出上下文 JSONL 分别按 UTF-8 字节数除以 4，向上取整；方法标识是 `utf8_bytes_div_4_ceil_v1`。`ratio` 等于原始估算除以输出估算，例如 1.5 表示输出约为原来的三分之二。结构化来源信息有额外开销，小输入的比率可能低于 1；输出为空时是 `null`。这不是实际模型 tokenizer 的精确计数。

### `context.txt` 可以当作新的会话输入吗？

它采用 JSONL 格式，并带有额外的段编号和来源列表；直接交给 `compress` 会因未知字段被拒绝。接入 Agent 时应按需要读取或映射这些记录，并保留审计证明。当前项目不会自动替换任何 Agent 的会话历史。

### 凭证会被隐藏吗？能发现所有秘密吗？

CCR 会保留已识别的凭证原文，不负责脱敏或加密。规则覆盖常见命名秘密字段、Bearer、私钥、部分 token 格式等，不能保证识别所有未知格式；已知敏感内容请显式加安全标签。上下文和证明都可能含敏感数据，应限制访问并按会话数据管理。样例中的凭证均为虚构值。

### 修改阈值能删掉安全记录吗？

不能关闭已识别或主动标记的安全保护。权限变化、告警、拒绝以及已关联的原始尝试和重试都保留；结构化工具／动作字段也保持完整。阈值只影响其他普通内容，使用高 `merge_score` 时需要评估普通信息的保留需求。

### 回放失败或 pytest 启动失败怎么办？

回放退出 1 时，根据输出中的字段路径、单元编号和摘要差异，核查文件是否被改动、可信事件是否对应同一批次。格式或文件错误退出 2。当前回放接受 Schema 1 和 CCR 0.1.0，版本不同也会拒绝；不要靠手改版本或指纹让校验通过。

测试应使用项目虚拟环境，而不是全局 Python。全局环境里的旧插件可能干扰 pytest；独立环境可以避免混用依赖。运行全部测试：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

测试覆盖各模块的正常、边界和失败路径，以及多个固定随机种子的 50 轮安全演示、证明篡改和模型降级。参与开发前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。项目使用 [MIT 许可证](LICENSE)。
