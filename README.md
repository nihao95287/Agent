# 终端命令安全审计与自动修复 Agent

一个**完全由大模型(LLM)驱动**的命令行安全审计智能体：你输入一条 shell 命令，Agent 会
**自动审计风险 →（必要时）自主探测真实系统环境 → 综合上下文 → 给出"修复后的安全命令"**。

整个过程无需人工干预，模型自主、按顺序地调度两个工具。支持 **OpenAI** 与 **Anthropic** 双后端。

> 本项目为"全 AI 驱动 Vibe Coding"实验：代码、System Prompt、业务编排逻辑、测试与报告素材
> 均由 AI 独立闭环完成。

---

## ✨ 功能特性

- **两个截然不同的功能性工具**
  - 🅰️ `Command_Analyzer`：17 条规则/正则引擎，识别 `rm -rf`、`chmod 777`、`docker -p 0.0.0.0`、
    `curl | bash`、fork 炸弹、`dd` 覆写磁盘、关闭防火墙等高危操作，输出结构化风险报告。
  - 🅱️ `Environment_Prober`：用 `subprocess`/`os`/`socket` **真实探测**本地环境（OS 版本、
    root/admin 权限、端口占用、路径存在性、可执行文件是否安装），**跨平台**（Windows/Linux/macOS）。
- **标准化协议**：通过 Function Calling / Tool Use 连接模型与本地工具。
- **双后端可切换**：OpenAI Function Calling（兼容 DeepSeek/Kimi/Qwen/本地模型）或 Anthropic Tool Use。
- **自主编排循环**：模型自行决定何时调 A、何时调 B、何时收敛输出。
- **健壮性**：内置防死循环、工具参数容错解析、`shell=False` 防注入、依赖可降级。

## 📂 项目结构

```
.
├── main.py                 # 主程序：System Prompt + 工具A/B + 双后端适配器 + 编排循环
├── requirements.txt        # 依赖：openai / anthropic / pydantic / python-dotenv
├── test_orchestration.py   # 离线测试：编排循环(死循环防护/去重) + 双后端消息翻译
├── .env.example            # 配置模板（复制为 .env 使用）
├── reflection.md           # 实验反思（中英双语）：两个技术缺陷与修复
├── prompts_log.md          # 交付物：AI 扮演的角色 + 完整原始提示词
└── README.md               # 本文件
```

## 🧠 工作原理

```
用户输入命令
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│              Orchestration Loop (run_agent_turn)          │
│                                                           │
│  第1轮: 强制调用 ──► 🅰️ Command_Analyzer (规则审计)        │
│                          │ 返回 risk_level + suggested_probes
│                          ▼                                │
│  第N轮: 模型自主 ──► 🅱️ Environment_Prober (探测真实环境)  │
│   (auto)                 │ 端口占用? 是否root? docker装了吗?
│                          ▼                                │
│  证据充分 ──► 收敛，输出最终 Markdown 审计报告 + 安全命令  │
│                                                           │
│  防护: 最多 MAX_TOOL_ITERATIONS(6) 轮；超限强制 tool_choice=none 收尾
└─────────────────────────────────────────────────────────┘
```

System Prompt 强约束：①收到命令必先调工具A审计；②若有权限疑问/端口冲突/环境未知，
必须接着调工具B探测；③证据足够后必须停止调用、直接输出，杜绝反复确认。

## 🚀 安装

> 本机的 `python` 指向的是 Microsoft Store 占位符，请用 Windows 的 **`py`** 启动器
> （其它系统用 `python`/`python3`）。

```bash
py -m pip install -r requirements.txt
```

## ⚙️ 配置

复制 `.env.example` 为 `.env`，二选一填入后端。`LLM_PROVIDER` 留空时会按"哪个 Key 有值"自动选择。

| 变量 | 说明 | 默认 |
|---|---|---|
| `LLM_PROVIDER` | `openai` \| `anthropic`，留空自动判别 | 自动 |
| `OPENAI_API_KEY` | OpenAI/兼容端点密钥 | — |
| `OPENAI_BASE_URL` | 兼容端点地址（DeepSeek/Kimi/Qwen/本地…） | OpenAI 默认 |
| `OPENAI_MODEL` | 模型名 | `gpt-4o-mini` |
| `OPENAI_FORCE_TOOL_CHOICE` | 是否强制首轮指定 `Command_Analyzer`；`auto` 会避开已知不兼容的 DeepSeek thinking 模型 | `auto` |
| `ANTHROPIC_API_KEY` | Anthropic 密钥 | — |
| `ANTHROPIC_BASE_URL` | 自定义/中转端点（可选） | Anthropic 默认 |
| `ANTHROPIC_MODEL` | Claude 模型名 | `claude-sonnet-4-6` |
| `ANTHROPIC_MAX_TOKENS` | 单次最大输出 token | `2048` |

**Anthropic 后端示例 `.env`：**
```ini
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-你的密钥
ANTHROPIC_MODEL=claude-sonnet-4-6
# ANTHROPIC_BASE_URL=https://你的中转网关   # 如使用中转可填
```

**OpenAI / DeepSeek 后端示例 `.env`：**
```ini
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-你的密钥
OPENAI_BASE_URL=https://api.deepseek.com
OPENAI_MODEL=deepseek-chat
# OPENAI_FORCE_TOOL_CHOICE=auto  # thinking 模型不支持强制 tool_choice 时会自动降级
```

## ▶️ 运行

```bash
py main.py             # 启动交互式 Agent（需 API Key）
py main.py --check     # 查看依赖、后端解析与配置
py main.py --selftest  # 离线自检：直接跑通工具A/B，无需 Key（适合截图）
py test_orchestration.py   # 离线测试：编排循环 + 双后端消息翻译，无需 Key
```

## 🧪 测试用例（完美触发「工具A → 工具B」自动连续调用）

启动 `py main.py` 后，依次粘贴：

**用例 1 —— 触发"权限探测"链：**
```
sudo chmod -R 777 /var/www/html
```
工具A 命中 `过度授权(high)` + `提权执行(medium)` → 自动调用工具B `check_privilege`
探测当前是否 root/admin → 给出修复（如 `chmod -R 755` 并去掉多余 sudo）。

**用例 2 —— 触发"端口 + 安装"探测链：**
```
docker run -d -p 0.0.0.0:3306:3306 mysql:latest
```
工具A 命中 `端口对外暴露(high)` → 自动连续调用工具B `check_port 3306` + `which docker`
→ 给出修复（如绑定 `127.0.0.1:3306:3306`）。

终端会打印 `🛠️ 调用工具 ...` 行，可清晰看到 A、B 被自动、连续调度。

## 🐞 已修复的两个技术缺陷（详见 `reflection.md`）

1. **多轮工具调用死循环** —— 原 `while True` + 提示词只说"要调用"不说"何时停"。
   修复：`MAX_TOOL_ITERATIONS=6` 硬上限 + 超限 `tool_choice=none` 强制收尾 + 同轮去重 +
   提示词"收敛纪律"。（`test_orchestration.py` 已断言 6 轮后必然收尾）
2. **复杂 Shell 字符串经协议传递的解析/注入** —— 含 `\;`、反引号、`$` 等会让 `json.loads`
   崩溃、`shell=True` 会注入。修复：`parse_tool_arguments` 三级容错解析（OpenAI 路径）+
   工具B 一律 `subprocess.run([...], shell=False)` 固定参数绝不拼接 + 提示词要求命令"原样不透明传递"。
   （注：Anthropic 的 `tool_use.input` 本身就是结构化 dict，天然规避了 JSON 字符串解析问题。）

## 🖥️ 跨平台说明

题面描述的是 Ubuntu，但工具B 实现为**跨平台只读探测**：自动区分 Windows / POSIX
（如权限检测在 Windows 用 `IsUserAnAdmin()`、在 Linux 用 `os.geteuid()`），在 Ubuntu 上同样真实可用。

## 🔒 安全声明

- Agent **绝不执行**用户提交的命令；工具B 只做**只读探测**，且所有真实探测都用
  `subprocess.run([...], shell=False)` 固定参数、不拼接任何用户输入。
- 本工具用于**防御性安全审计与教学**，请勿用于真实破坏性操作。
