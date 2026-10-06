# Contributing to CCR

要求 Python 3.10+。从仓库根目录建立独立虚拟环境，安装开发依赖：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest -q
```

如本机不允许激活脚本，可直接使用 `.\.venv\Scripts\python.exe` 代替 `python`。Linux/macOS 激活命令为 `source .venv/bin/activate`。

先阅读 [架构设计](docs/architecture.md)。新增模块应保持单向公开接口依赖，边界类型放在 contracts.py；不得调用其他模块私有函数。评分、丢弃判定与证明生成不得读取文件、环境变量、系统时间或打印日志。依赖改动必须保持运行时仅标准库，插件以协议注入。

安全规则变化需附正常、边界与失败测试，尤其是凭证无损保留、拒绝后重试、配置极值、插件降级、证明篡改与可信来源验证。不要为了提高压缩比减弱保护底线。公开契约或证明格式变化须同步架构文档中的契约块、Schema 与版本处理。

每个阶段实际运行 pytest；改动 CLI 或文档命令时逐条执行命令，提交说明记录真实验证结果。测试示例仅使用明显的虚构凭证，不提交真实会话、密钥或生成的审计文件。私下向仓库维护者报告真实秘密泄露，不在公开 issue 中粘贴凭证。
