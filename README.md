[English](#english) | [中文](#中文)

# AgentGate

**Runtime security for autonomous AI agents. / 自主 AI 智能体的运行时安全框架。**

[![PyPI version](https://img.shields.io/pypi/v/agentgate.svg)](https://pypi.org/project/agentgate/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/agentgate/agentgate/ci.yml?branch=main)](https://github.com/agentgate/agentgate/actions)
[![Python](https://img.shields.io/pypi/pyversions/agentgate.svg)](https://pypi.org/project/agentgate/)

---

## The Problem / 问题背景 {#english}

AI agents are growing explosively. Frameworks like LangChain, CrewAI, and AutoGen make it trivial to build agents that call tools, browse the web, execute code, and modify files -- often with minimal human oversight.

Security tooling has not kept up. The [OWASP Top 10 for Agentic AI (2025)](https://owasp.org/www-project-agentic-ai-top-10/) highlights critical risks including unbounded tool access, insufficient sandboxing, missing audit trails, and privilege escalation between agents.

Existing solutions focus on **LLM-level** guardrails -- prompt injection detection, content filtering, hallucination checks. Almost none address **agent-level** security: controlling *what tools an agent can call*, *with what arguments*, *how often*, and *what happens when it misbehaves*.

---

{#中文}

AI 智能体正在爆发式增长。LangChain、CrewAI、AutoGen 等框架使得构建能够调用工具、浏览网页、执行代码和修改文件的智能体变得极其简单——而这些操作往往缺乏充分的人工监督。

安全工具远未跟上这一发展速度。[OWASP Agentic AI Top 10 (2025)](https://owasp.org/www-project-agentic-ai-top-10/) 指出了若干关键风险，包括不受限的工具访问、不充分的沙箱隔离、缺失的审计追踪，以及智能体之间的权限提升问题。

现有方案大多关注 **LLM 层面**的防护——提示注入检测、内容过滤、幻觉检查。几乎没有方案专门解决**智能体层面**的安全问题：控制*智能体能调用哪些工具*、*使用什么参数*、*调用频率如何*，以及*出现异常行为时如何处置*。

---

## What AgentGate Does / AgentGate 做了什么

AgentGate is an open-source security framework purpose-built for the agent layer. It sits between your AI agents and the tools they invoke, providing:

- **Fine-grained permissions** -- declarative YAML policies that control which tools each agent can call, with argument-level constraints (regex patterns, enum values, numeric bounds).
- **Deny-first evaluation** -- deny rules are always checked before allow rules, ensuring explicit blocks cannot be bypassed.
- **Rate limiting** -- sliding-window rate limits per agent and tool to prevent runaway execution.
- **Session controls** -- hard limits on total tool calls and session duration.
- **Comprehensive audit trail** -- every tool call is logged with arguments, decision, result summary, timing, and anomaly scores. Stored in SQLite with optional Ed25519 cryptographic signatures.
- **Anomaly detection** -- built-in heuristic detector flags burst activity, unusual tool diversity, and suspiciously fast execution.
- **Framework integrations** -- drop-in support for LangChain, CrewAI, AutoGen, and any Python function via a simple decorator.
- **No code changes required** -- wrap existing tools with a decorator or plug in framework middleware. Your agent code stays untouched.

---

AgentGate 是一个专为智能体层打造的开源安全框架。它位于 AI 智能体和其调用的工具之间，提供以下能力：

- **细粒度权限控制** -- 声明式 YAML 策略，控制每个智能体可以调用哪些工具，并支持参数级别的约束（正则表达式、枚举值、数值范围）。
- **拒绝优先评估** -- 拒绝规则始终先于允许规则执行，确保显式阻断不会被绕过。
- **速率限制** -- 基于滑动窗口的速率限制，按智能体和工具分别生效，防止失控执行。
- **会话控制** -- 对工具调用总次数和会话时长施加硬性上限。
- **全面审计追踪** -- 记录每次工具调用的参数、决策结果、返回摘要、耗时及异常评分。数据存储在 SQLite 中，支持可选的 Ed25519 加密签名。
- **异常检测** -- 内置启发式检测器，可标记突发活动、异常工具多样性和可疑的极短执行时间。
- **多框架集成** -- 开箱即用地支持 LangChain、CrewAI、AutoGen，以及通过简单装饰器集成任意 Python 函数。
- **无需修改代码** -- 通过装饰器或框架中间件即可包装已有工具，原有智能体代码无需改动。

---

## Quick Start / 快速上手

### Installation / 安装

```bash
pip install agentgate
```

### Protect any function with the `@protect` decorator / 使用 `@protect` 装饰器保护任意函数

```python
from agentgate import protect

@protect(policy="policy.yaml", agent_id="code-assistant")
def read_file(path: str) -> str:
    return open(path).read()

# This call is checked against the policy before executing.
# If denied, raises agentgate.ToolCallDenied.
# 调用前会依据策略进行检查。若被拒绝，将抛出 agentgate.ToolCallDenied。
content = read_file(path="/tmp/data.txt")
```

### Use the `AgentGate` class directly / 直接使用 `AgentGate` 类

```python
from agentgate import AgentGate

gate = AgentGate(policy="policy.yaml")

result = await gate.intercept_tool_call(
    agent_id="code-assistant",
    session_id="sess-001",
    tool_name="read_file",
    tool_args={"path": "/tmp/data.txt"},
    execute_fn=actual_read_file,
)

gate.close()
```

### Scan a policy file from the CLI / 通过命令行扫描策略文件

```bash
agentgate scan policy.yaml
```

---

## Key Features / 核心功能

### Declarative YAML Policies / 声明式 YAML 策略

Define security rules in version-controlled YAML files. No code changes, no runtime configuration drift.

在版本管理的 YAML 文件中定义安全规则。无需修改代码，杜绝运行时配置漂移。

```yaml
version: "1"
agents:
  code-assistant:
    tools:
      denied:
        - name: "execute_shell"
          reason: "Shell execution is not permitted"
      allowed:
        - name: "read_file"
          args:
            path:
              pattern: "^/tmp/.*"
              max_length: 256
        - name: "write_file"
          rate_limit:
            max_calls: 10
            window_seconds: 60
```

### Framework Integrations / 框架集成

Works with LangChain, CrewAI, AutoGen, and any Python callable -- see [Integration Examples](#integration-examples--集成示例) below.

支持 LangChain、CrewAI、AutoGen 以及任意 Python 可调用对象——参见下方[集成示例](#integration-examples--集成示例)。

### Comprehensive Audit Trail / 全面审计追踪

Every tool call is recorded with full context: agent ID, session ID, tool name, arguments, policy decision, result summary, execution duration, anomaly score, and optional Ed25519 signature.

每次工具调用均被完整记录，包括：智能体 ID、会话 ID、工具名称、调用参数、策略决策、结果摘要、执行耗时、异常评分，以及可选的 Ed25519 签名。

### Anomaly Detection / 异常检测

Built-in heuristic detector with configurable sensitivity (low / medium / high). Flags burst activity, high tool diversity, and suspiciously fast execution. Supports alert delivery via log, webhook, or email.

内置启发式检测器，灵敏度可配置（low / medium / high）。能够标记突发活动、异常工具多样性和可疑的极短执行时间。支持通过日志、webhook 或邮件发送告警。

### CLI Tools / 命令行工具

| Command | Description / 说明 |
|---------|-------------|
| `agentgate init` | Generate a starter `policy.yaml` / 在当前目录生成初始 `policy.yaml` |
| `agentgate check <policy>` | Validate a policy file / 校验策略文件并报告错误或警告 |
| `agentgate scan <policy>` | Deep-scan for security issues / 深度扫描策略的安全问题和最佳实践 |
| `agentgate audit` | Query the audit trail / 查询并展示审计追踪记录 |
| `agentgate report` | Generate an HTML or JSON report / 生成 HTML 或 JSON 安全报告 |

---

## Integration Examples / 集成示例

### Generic `@protect` Decorator / 通用 `@protect` 装饰器

```python
from agentgate import protect

@protect(policy="policy.yaml", agent_id="data-pipeline")
async def fetch_url(url: str) -> str:
    async with aiohttp.ClientSession() as session:
        resp = await session.get(url)
        return await resp.text()
```

### LangChain Middleware / LangChain 中间件

```python
from agentgate.integrations.langchain import AgentGateMiddleware

middleware = AgentGateMiddleware(policy="policy.yaml")
agent = initialize_agent(tools, llm, agent_type=...)
agent.middleware = [middleware]
```

### CrewAI Callback / CrewAI 回调

```python
from agentgate.integrations.crewai import AgentGateCallback

callback = AgentGateCallback(policy="policy.yaml")
crew = Crew(agents=[...], tasks=[...], callbacks=[callback])
crew.kickoff()
```

### AutoGen Adapter / AutoGen 适配器

```python
from agentgate.integrations.autogen import AgentGateAdapter

adapter = AgentGateAdapter(policy="policy.yaml")
assistant = AssistantAgent("assistant", llm_config=llm_config)
adapter.wrap(assistant)
```

---

## Policy File Reference / 策略文件参考

The following example shows a full-featured policy file. See inline comments for explanations.

以下示例展示了一个功能完整的策略文件，请参阅行内注释了解各字段含义。

```yaml
version: "1"
description: "Production security policy"

agents:
  # Named agent with specific permissions
  # 具名智能体及其专属权限
  code-assistant:
    role: "Code analysis and generation"
    tools:
      denied:
        - name: "execute_shell"
          reason: "Shell execution prohibited in production"
        - name: "delete_*"
          reason: "Deletion tools are not permitted"
      allowed:
        - name: "read_file"
          args:
            path:
              pattern: "^/app/workspace/.*"
              max_length: 512
        - name: "write_file"
          args:
            path:
              pattern: "^/app/workspace/.*"
            content:
              max_length: 100000
          rate_limit:
            max_calls: 20
            window_seconds: 60
        - name: "search_code"
    resources:
      filesystem:
        read: ["/app/workspace/**"]
        write: ["/app/workspace/output/**"]
      network:
        allowed_domains: ["api.openai.com", "*.githubusercontent.com"]
        denied_domains: ["*.internal.corp"]
    limits:
      max_tool_calls_per_session: 500
      max_session_duration_seconds: 3600

  # Fallback policy for unrecognised agents
  # 未识别智能体的兜底策略
  __default__:
    tools:
      denied:
        - name: "*"
          reason: "Unknown agents are denied all tool access"
      allowed: []

audit:
  enabled: true
  storage: sqlite
  sign_records: false
  retention_days: 90

anomaly:
  enabled: true
  sensitivity: medium
  alerts:
    - type: log
    - type: webhook
      url: "https://hooks.example.com/agentgate"
```

---

## CLI Usage / 命令行用法

### Initialize a new policy / 初始化新策略

```bash
# Create a starter policy.yaml in the current directory
# 在当前目录创建初始 policy.yaml
agentgate init

# Specify a custom output path
# 指定自定义输出路径
agentgate init --output my-policy.yaml
```

### Validate a policy file / 校验策略文件

```bash
agentgate check policy.yaml
```

### Deep-scan for security issues / 深度安全扫描

```bash
agentgate scan policy.yaml
```

### Query the audit trail / 查询审计追踪

```bash
# Show recent events / 显示最近的事件
agentgate audit

# Filter by agent and decision / 按智能体和决策结果筛选
agentgate audit --agent-id code-assistant --decision denied

# Filter by time range / 按时间范围筛选
agentgate audit --since 2h --limit 50
```

### Generate a security report / 生成安全报告

```bash
# HTML report / HTML 报告
agentgate report --format html --output report.html

# JSON report / JSON 报告
agentgate report --format json --output report.json
```

---

## Architecture / 架构

AgentGate is a hybrid Python + Rust project.

AgentGate 是一个 Python + Rust 混合项目。

```
agentgate/
  python/
    agentgate/
      core.py              # Central orchestration engine / 核心编排引擎
      policy/
        schema.py          # Pydantic v2 policy models / 策略模型
        loader.py          # YAML loading and validation / YAML 加载与校验
        engine.py          # Policy evaluation (Python fallback) / 策略评估（Python 回退）
        defaults.py        # Built-in default policy / 内置默认策略
      audit/
        models.py          # AuditEvent and AuditQuery models / 审计事件与查询模型
        collector.py       # Event collection pipeline / 事件采集管道
        store.py           # SQLite persistence / SQLite 持久化
      integrations/
        generic.py         # @protect decorator / @protect 装饰器
        langchain.py       # LangChain middleware / LangChain 中间件
        crewai.py          # CrewAI callback / CrewAI 回调
        autogen.py         # AutoGen adapter / AutoGen 适配器
      anomaly/             # Anomaly detection subsystem / 异常检测子系统
      cli/                 # CLI entry points / 命令行入口
  src/                     # Rust native extension (optional) / Rust 原生扩展（可选）
    policy/
      types.rs             # Policy data types / 策略数据类型
      matcher.rs           # Compiled glob matching engine / 编译型 glob 匹配引擎
    audit/
      writer.rs            # High-throughput audit writer / 高吞吐审计写入器
      signer.rs            # Ed25519 cryptographic signing / Ed25519 加密签名
    lib.rs                 # PyO3 bindings / PyO3 绑定
```

The **Python layer** handles all orchestration, framework integration, and user-facing APIs. The optional **Rust extension** (`agentgate._core`) provides compiled policy matching and cryptographic audit signing for production workloads. When the Rust extension is not installed, AgentGate falls back transparently to a pure-Python implementation.

---

**Python 层**负责全部编排逻辑、框架集成和面向用户的 API。可选的 **Rust 扩展**（`agentgate._core`）为生产环境提供编译型策略匹配和加密审计签名。未安装 Rust 扩展时，AgentGate 将自动回退至纯 Python 实现，功能完全一致。

---

## OWASP Agentic AI Top 10 Coverage / OWASP Agentic AI Top 10 覆盖情况

The table below maps each item from the [OWASP Top 10 for Agentic AI (2025)](https://owasp.org/www-project-agentic-ai-top-10/) to the AgentGate features that address it.

下表将 [OWASP Agentic AI Top 10 (2025)](https://owasp.org/www-project-agentic-ai-top-10/) 的每一项风险映射到 AgentGate 的对应缓解措施。

| # | OWASP Risk | AgentGate Mitigation / 缓解措施 |
|---|-----------|---------------------|
| 1 | Agentic Identity and Access Mismanagement | Per-agent policies with named identifiers and role-based tool permissions / 基于命名标识和角色的逐智能体策略与工具权限 |
| 2 | Tool and Function Misuse | Deny-first evaluation, glob allow/deny lists, argument constraints / 拒绝优先评估、glob 允许/拒绝列表、参数约束 |
| 3 | Privilege Escalation Across Agents | Isolated per-agent policies, `__default__` deny-all fallback / 逐智能体隔离策略，`__default__` 全拒绝兜底 |
| 4 | Uncontrolled Agentic Resource Consumption | Sliding-window rate limits, session call/duration limits / 滑动窗口速率限制、会话调用次数/时长上限 |
| 5 | Insecure Agentic Memory | Audit trail captures memory events; resource policies restrict access / 审计追踪记录内存变更事件；资源策略限制访问 |
| 6 | Insufficient Agentic Monitoring and Logging | Full audit trail with SQLite, anomaly scoring, configurable retention / SQLite 全量审计、异常评分、可配置留存周期 |
| 7 | Unsafe Code Generation and Execution | Deny rules for shell/code tools, argument pattern validation / 针对 shell/代码工具的拒绝规则、参数模式验证 |
| 8 | Agentic Supply Chain Vulnerabilities | Policy-as-code in version control, CLI validation (`check`, `scan`) / 策略即代码纳入版本管理，CLI 校验工具 |
| 9 | Insufficient Agentic Sandboxing | Filesystem path restrictions, network domain allow/deny lists / 文件系统路径限制、网络域名允许/拒绝列表 |
| 10 | Inadequate Agentic Multi-Agent Orchestration | Per-agent identity, cross-agent isolation, session limits / 逐智能体身份标识、跨智能体隔离、会话级限制 |

---

## Comparison / 方案对比

| Feature | AgentGate | Lakera | NeMo Guardrails | Promptfoo | Daytona | Langfuse |
|---------|-----------|--------|-----------------|-----------|---------|----------|
| **Focus / 定位** | Agent-level security / 智能体层安全 | LLM input/output | LLM conversation rails | LLM red-teaming | Dev environment | LLM observability |
| Tool-level permissions / 工具级权限 | Yes | No | No | No | No | No |
| Argument constraints / 参数约束 | Yes | No | No | No | No | No |
| Rate limiting / 速率限制 | Yes | Yes | No | No | No | No |
| Audit trail / 审计追踪 | Yes (signed) | Partial | No | No | No | Yes |
| Anomaly detection / 异常检测 | Yes | Yes | No | No | No | No |
| Policy-as-code (YAML) | Yes | No | Yes | Yes | No | No |
| Framework integrations / 框架集成 | LangChain, CrewAI, AutoGen | API | LangChain | CLI | API | LangChain |
| Open source / 开源 | Yes (Apache 2.0) | No | Yes | Yes | Yes | Yes |
| Rust acceleration / Rust 加速 | Yes | N/A | No | No | N/A | No |

---

## Development / 开发指南

### Prerequisites / 环境要求

- Python 3.10+
- Rust toolchain (for optional native extension / 用于可选的原生扩展)

### Setup / 项目搭建

```bash
# Clone the repository / 克隆仓库
git clone https://github.com/agentgate/agentgate.git
cd agentgate

# Create a virtual environment / 创建虚拟环境
python -m venv .venv
source .venv/bin/activate

# Install in development mode / 以开发模式安装
pip install -e ".[dev]"

# Build the Rust extension (optional) / 构建 Rust 扩展（可选）
cd src && cargo build --release && cd ..

# Run tests / 运行测试
pytest tests/
```

### Running the linter / 运行代码检查

```bash
ruff check python/
mypy python/agentgate/
```

---

## License / 许可协议

AgentGate is licensed under the [Apache License 2.0](LICENSE).

AgentGate 基于 [Apache License 2.0](LICENSE) 许可协议发布。

---

## Links / 相关链接

- Documentation / 文档: *coming soon / 即将推出*
- PyPI: https://pypi.org/project/agentgate/
- GitHub: https://github.com/agentgate/agentgate
- OWASP Agentic AI Top 10: https://owasp.org/www-project-agentic-ai-top-10/
