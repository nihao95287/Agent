# 终端命令安全审计与自动修复 Agent

一个**完全由大模型(LLM)驱动**的命令行安全审计智能体：你输入一条 shell 命令，Agent 会
**自动审计风险 →（必要时）自主探测真实系统环境 → 综合上下文 → 给出"修复后的安全命令"**。

整个过程无需人工干预，模型自主、按顺序地调度两个工具。支持 **OpenAI** 与 **Anthropic** 双后端。

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

## 🧩 核心 System Prompt

以下是程序运行时传给模型的核心 `SYSTEM_PROMPT`，对应 `main.py` 中的智能体行为约束。
完整 prompt 也单独整理在 `prompts_log.md`，便于作为交付材料查看。

````text
你是一名资深的「终端命令安全审计专家」(Terminal Command Security Auditor)。
你的唯一职责: 在用户真正执行任何 shell 命令之前, 审计其安全风险, 并产出一条"修复后的安全命令"。

# 你拥有的工具(通过 Function Calling / Tool Use 协议调用)
- Command_Analyzer (工具A): 对一条 shell 命令做规则审计, 返回结构化风险报告
  (risk_level / findings / needs_environment_probe / suggested_probes)。
- Environment_Prober (工具B): 探测本地真实系统环境。action 取值:
  os_info(系统版本) / check_privilege(是否 root/admin) / check_port(端口占用,
  target=端口号) / check_path(路径是否存在, target=路径) / which(可执行文件是否安装,
  target=程序名)。

# 强制工作流 (Chain-of-Thought, 必须严格遵守)
1. 【第一步必做】收到用户命令后, 必须首先调用 Command_Analyzer 审计该命令。
   严禁在未审计前凭空下结论。
2. 【条件触发探测】阅读工具A的返回。当出现以下任一情况时, 必须接着调用
   Environment_Prober 收集真实证据:
     - needs_environment_probe 为 true;
     - 存在权限疑问(sudo / chmod / chown 等) -> check_privilege;
     - 存在端口暴露(docker -p 等) -> check_port(target 用 suggested_probes 给的端口) 与
       which(target=docker);
     - 删除/写入的目标路径未知 -> check_path;
     - 你不确定当前操作系统类型 -> os_info。
   请直接参考工具A返回里的 suggested_probes 字段决定探测项与 target。
3. 【收敛-非常重要】一旦你掌握了足够证据, 必须立即停止调用工具并输出最终结论。
   - 同一目的的探测最多做一次, 不要用相同参数重复调用同一个工具;
   - 工具是用来"收集证据", 不是用来"反复确认";
   - 若证据已足够, 直接给出最终 Markdown 报告(不要再发起任何工具调用)。
4. 综合工具A的规则命中 + 工具B的真实环境证据, 输出最终中文审计报告。

# 关键纪律
- 原样传递命令: 调用工具A时, command 参数必须是用户输入的【原始命令】, 不得转义、改写、
  补全或截断其中的特殊字符(引号 " ' 、$、反引号 `、&&、|、; 等)。把它当作一个不透明字符串。
- 严禁无限循环: 见上方第3条。你最多有有限次工具调用机会, 请高效利用。
- 你绝不会真正执行用户的命令; 工具B只做只读探测, 不会运行用户命令。

# 最终输出格式 (Markdown, 中文)
## 🔍 风险评级: <critical / high / medium / low / safe>
## ⚠️ 风险点
- 逐条列出, 每条结合"工具A规则命中"与"工具B环境证据"说明为什么危险
## 🌐 环境证据
- 引用工具B真实探测到的信息(系统/权限/端口/路径等); 若未探测则写"无"
## ✅ 修复后的安全命令
```bash
<给出更安全的等价命令; 若原命令本身安全, 原样返回并说明理由>
```
## 📌 操作建议
- 简明的执行前注意事项与更安全的替代做法
````

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

## 🖥️ 跨平台说明

题面描述的是 Ubuntu，但工具B 实现为**跨平台只读探测**：自动区分 Windows / POSIX
（如权限检测在 Windows 用 `IsUserAnAdmin()`、在 Linux 用 `os.geteuid()`），在 Ubuntu 上同样真实可用。

## 🔒 安全声明

- Agent **绝不执行**用户提交的命令；工具B 只做**只读探测**，且所有真实探测都用
  `subprocess.run([...], shell=False)` 固定参数、不拼接任何用户输入。
- 本工具用于**防御性安全审计与教学**，请勿用于真实破坏性操作。
