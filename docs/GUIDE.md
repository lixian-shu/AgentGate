[English](#english) | [中文](#中文)

# AgentGate Detailed Feature Guide / AgentGate 详细功能介绍与使用指南

---

## Table of Contents / 目录

- [Project Overview / 项目概览](#project-overview--项目概览)
- [Core Concepts / 核心概念](#core-concepts--核心概念)
- [Installation / 安装](#installation--安装)
- [Quick Start / 快速上手](#quick-start--快速上手)
- [Policy System / 策略系统](#policy-system--策略系统)
- [Four Integration Modes / 四种集成模式](#four-integration-modes--四种集成模式)
- [Audit System / 审计系统](#audit-system--审计系统)
- [Anomaly Detection / 异常检测](#anomaly-detection--异常检测)
- [CLI Tool / CLI 命令行工具](#cli-tool--cli-命令行工具)
- [Rust Acceleration Layer / Rust 加速层](#rust-acceleration-layer--rust-加速层)
- [End-to-End Walkthrough / 完整使用流程](#end-to-end-walkthrough--完整使用流程)
- [API Reference / API 参考](#api-reference--api-参考)

---

## Project Overview / 项目概览

AgentGate is a runtime security framework designed for AI Agents. It establishes a policy-driven security boundary between Agents and their tools/resources, providing three core capabilities:

| Capability | Description |
|---|---|
| **Policy Enforcement** | Declarative YAML policy files that control which Agents can invoke which tools, with what arguments, and at what frequency |
| **Behavior Auditing** | Every tool call and every decision is recorded to a SQLite database, with support for querying, exporting, and reporting |
| **Anomaly Detection** | Statistics-based behavioral analysis that automatically flags suspicious activity (new tool usage, frequency anomalies, behavioral drift, etc.) |

### Architecture

```
Python Layer (agentgate/)                  Rust Layer (agentgate._core)
+----------------------------+             +------------------------------+
| Policy Engine (policy/)    |             | PolicyMatcher                |
| Audit System (audit/)      |  -- PyO3 -> |  Sub-microsecond matching    |
| Anomaly Detection (anomaly/)|             | AuditWriter                  |
| Integrations (integrations/)|             |  100K+ events/sec writes     |
| CLI (cli/)                 |             | AuditSigner                  |
| Core Engine (core.py)      |             |  Ed25519 sign & verify       |
+----------------------------+             +------------------------------+
```

The Rust layer is **optional** -- if not compiled, the Python layer automatically falls back to a pure Python implementation with identical functionality.

---

AgentGate 是一个面向 AI Agent（智能体）的运行时安全框架。它在 Agent 与其工具/资源之间设置策略驱动的安全边界，提供三大核心能力：

| 能力 | 说明 |
|---|---|
| **策略管控** | 声明式 YAML 策略文件，控制哪些 Agent 可以调用哪些工具、传入什么参数、频率多高 |
| **行为审计** | 每一次工具调用、每一个决策都被记录到 SQLite 数据库，支持查询、导出、报告 |
| **异常检测** | 基于统计的行为分析，自动标记可疑活动（新工具使用、频率异常、行为偏移等） |

### 架构

```
Python 层 (agentgate/)                    Rust 层 (agentgate._core)
┌────────────────────────┐               ┌──────────────────────────┐
│ 策略引擎 (policy/)     │               │ PolicyMatcher            │
│ 审计系统 (audit/)      │  ── PyO3 ──>  │  亚微秒级模式匹配        │
│ 异常检测 (anomaly/)    │               │ AuditWriter              │
│ 框架集成 (integrations/)│               │  100K+ events/sec 写入   │
│ CLI (cli/)             │               │ AuditSigner              │
│ 核心引擎 (core.py)     │               │  Ed25519 签名验签        │
└────────────────────────┘               └──────────────────────────┘
```

Rust 层是**可选的**——如果未编译，Python 层自动回退到纯 Python 实现，功能完全一致。

---

## Core Concepts / 核心概念

### Deny-First

AgentGate's policy evaluation follows a deny-first principle:

1. Check the deny list first -- if any deny rule matches, reject immediately
2. Then check the allow list -- if an allow rule matches, proceed with argument validation
3. No match -- default deny

### Intercept, Not Replace

AgentGate does not require modification of your Agent code. It wraps tool calls through decorators, callbacks, and middleware, inserting security checks before and after execution.

### Execution Pipeline

Every tool call passes through the following pipeline:

```
Tool Call Request
  |
  +- 1. Policy Check    -> Is this tool allowed? Are arguments compliant?
  +- 2. Rate Check      -> Does it exceed the call frequency limit?
  +- 3. Session Check   -> Does it exceed session-level limits?
  +- 4. Execute Tool    -> Actually execute the tool function
  +- 5. Audit Record    -> Log call details, result, duration
  +- 6. Anomaly Detect  -> Does behavior deviate from baseline?
```

---

### 拒绝优先（Deny-First）

AgentGate 的策略评估遵循 deny-first 原则：

1. 先检查拒绝列表 -- 如果匹配任何拒绝规则，立即拒绝
2. 再检查允许列表 -- 如果匹配允许规则，进行参数验证
3. 都不匹配 -- 默认拒绝

### 拦截而非替换

AgentGate 不需要修改你的 Agent 代码。它通过装饰器、回调、中间件等方式"包裹"工具调用，在执行前后插入安全检查。

### 执行管线

每次工具调用都经过以下管线：

```
工具调用请求
  │
  ├─ 1. 策略检查   → 此工具是否被允许？参数是否合规？
  ├─ 2. 速率检查   → 是否超过调用频率限制？
  ├─ 3. 会话检查   → 是否超过会话级别限制？
  ├─ 4. 执行工具   → 实际执行工具函数
  ├─ 5. 审计记录   → 记录调用详情、结果、耗时
  └─ 6. 异常检测   → 行为是否偏离基线？
```

---

## Installation / 安装

### Basic Installation (Pure Python)

```bash
cd agentgate
pip install -e .
```

### Full Installation (with Rust Acceleration)

```bash
# Requires Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Requires maturin
pip install maturin

# Create virtual environment and build
python3.11 -m venv .venv
source .venv/bin/activate
maturin develop --release
```

### Framework Integrations (Optional Dependencies)

```bash
pip install agentgate[langchain]    # LangChain integration
pip install agentgate[crewai]       # CrewAI integration
pip install agentgate[autogen]      # AutoGen integration
pip install agentgate[all]          # All frameworks
pip install agentgate[dev]          # Dev tools (pytest, ruff, mypy)
```

---

### 基础安装（纯 Python）

```bash
cd agentgate
pip install -e .
```

### 完整安装（含 Rust 加速）

```bash
# 需要 Rust 工具链
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# 需要 maturin
pip install maturin

# 创建虚拟环境并构建
python3.11 -m venv .venv
source .venv/bin/activate
maturin develop --release
```

### 框架集成（可选依赖）

```bash
pip install agentgate[langchain]    # LangChain 集成
pip install agentgate[crewai]       # CrewAI 集成
pip install agentgate[autogen]      # AutoGen 集成
pip install agentgate[all]          # 全部框架
pip install agentgate[dev]          # 开发工具 (pytest, ruff, mypy)
```

---

## Quick Start / 快速上手

### 30-Second Demo

```python
from agentgate import protect

@protect(policy="agentgate.yaml", agent_id="my-agent")
def search_docs(query: str) -> str:
    return f"Results for: {query}"

# If the policy allows it, executes normally; if denied, raises ToolCallDenied
result = search_docs(query="AI safety")
```

### 5-Minute Tutorial

```python
from agentgate import AgentGate, ToolCallDenied

# 1. Define policy (can also be loaded from a YAML file)
policy = {
    "version": "1",
    "agents": {
        "my-agent": {
            "tools": {
                "allowed": [
                    {"name": "search_*"},                    # Allow all tools starting with search_
                    {"name": "read_file", "args": {          # Allow read_file, but restrict path
                        "path": {"pattern": "^/data/"}
                    }},
                ],
                "denied": [
                    {"name": "delete_*", "reason": "Delete operations are forbidden"},
                    {"name": "exec_shell"},
                ],
            },
            "limits": {
                "max_tool_calls_per_session": 100,
            },
        },
    },
    "audit": {"enabled": True, "storage": "sqlite"},
}

# 2. Create an AgentGate instance
with AgentGate(policy=policy, audit_db="my_audit.db") as gate:

    # 3. Allowed call -- executes normally
    result = gate.intercept_tool_call_sync(
        agent_id="my-agent",
        session_id="session-001",
        tool_name="search_docs",
        tool_args={"query": "AI safety"},
        execute_fn=lambda query="": f"Found results for: {query}",
    )
    print(result)  # "Found results for: AI safety"

    # 4. Denied call -- raises exception
    try:
        gate.intercept_tool_call_sync(
            agent_id="my-agent",
            session_id="session-001",
            tool_name="delete_user",
            tool_args={"user_id": "123"},
            execute_fn=lambda user_id="": f"Deleted {user_id}",
        )
    except ToolCallDenied as e:
        print(f"Denied: {e}")
        # "Denied: Tool 'delete_user' denied: Delete operations are forbidden"

    # 5. View audit summary
    summary = gate.get_audit_summary()
    print(f"Total events: {summary['total_events']}")
    print(f"Decision distribution: {summary['by_decision']}")
```

---

### 30 秒体验

```python
from agentgate import protect

@protect(policy="agentgate.yaml", agent_id="my-agent")
def search_docs(query: str) -> str:
    return f"Results for: {query}"

# 如果策略允许，正常执行；如果被拒绝，抛出 ToolCallDenied
result = search_docs(query="AI safety")
```

### 5 分钟入门

```python
from agentgate import AgentGate, ToolCallDenied

# 1. 定义策略（也可以从 YAML 文件加载）
policy = {
    "version": "1",
    "agents": {
        "my-agent": {
            "tools": {
                "allowed": [
                    {"name": "search_*"},                    # 允许所有 search_ 开头的工具
                    {"name": "read_file", "args": {          # 允许 read_file，但限制路径
                        "path": {"pattern": "^/data/"}
                    }},
                ],
                "denied": [
                    {"name": "delete_*", "reason": "禁止删除操作"},
                    {"name": "exec_shell"},
                ],
            },
            "limits": {
                "max_tool_calls_per_session": 100,
            },
        },
    },
    "audit": {"enabled": True, "storage": "sqlite"},
}

# 2. 创建 AgentGate 实例
with AgentGate(policy=policy, audit_db="my_audit.db") as gate:

    # 3. 允许的调用 — 正常执行
    result = gate.intercept_tool_call_sync(
        agent_id="my-agent",
        session_id="session-001",
        tool_name="search_docs",
        tool_args={"query": "AI safety"},
        execute_fn=lambda query="": f"Found results for: {query}",
    )
    print(result)  # "Found results for: AI safety"

    # 4. 被拒绝的调用 — 抛出异常
    try:
        gate.intercept_tool_call_sync(
            agent_id="my-agent",
            session_id="session-001",
            tool_name="delete_user",
            tool_args={"user_id": "123"},
            execute_fn=lambda user_id="": f"Deleted {user_id}",
        )
    except ToolCallDenied as e:
        print(f"被拒绝: {e}")
        # "被拒绝: Tool 'delete_user' denied: 禁止删除操作"

    # 5. 查看审计摘要
    summary = gate.get_audit_summary()
    print(f"总事件数: {summary['total_events']}")
    print(f"决策分布: {summary['by_decision']}")
```

---

## Policy System / 策略系统

### Policy File Structure

Policies use YAML format. The full structure is as follows:

```yaml
version: "1"
description: "Policy description"

agents:
  # Policy for each Agent
  agent_name:
    role: "Agent role description"

    tools:
      # Allowed tool list
      allowed:
        - name: "tool_name"           # Exact match
        - name: "search_*"            # Glob wildcard
        - name: "write_file"
          args:                       # Argument constraints
            path:
              pattern: "^/tmp/"       # Regex match
              max_length: 256         # Max length
            content:
              max_length: 10000
          rate_limit:                 # Rate limiting
            max_calls: 10
            window_seconds: 60

        - name: "calculate"
          args:
            value:
              min: 0                  # Minimum value
              max: 1000               # Maximum value
            mode:
              enum: ["add", "sub"]    # Enum whitelist

      # Denied tool list (takes priority over allowed list)
      denied:
        - name: "delete_*"
          reason: "Delete operations are forbidden"
        - name: "exec_shell"

    # Resource access control
    resources:
      filesystem:
        read: ["/data/**", "/config/*.yaml"]   # Readable paths (glob)
        write: ["/tmp/**"]                      # Writable paths (glob)
      network:
        allowed_domains: ["api.example.com"]    # Allowed domains
        denied_domains: ["*.evil.com", "*"]     # Denied domains

    # Session-level limits
    limits:
      max_tool_calls_per_session: 100       # Max calls per session
      max_session_duration_seconds: 3600    # Max session duration (seconds)

  # Default Agent policy (fallback for unregistered Agents)
  __default__:
    tools:
      denied:
        - name: "*"
          reason: "Unregistered Agents are not allowed any operations"

# Audit configuration
audit:
  enabled: true
  storage: "sqlite"        # "sqlite" or "file"
  sign_records: true       # Sign audit records with Ed25519
  retention_days: 90

# Anomaly detection configuration
anomaly:
  enabled: true
  sensitivity: "medium"    # "low" / "medium" / "high"
  alerts:
    - type: "log"          # Output to logs
    - type: "webhook"      # Send to webhook
      url: "https://hooks.slack.com/services/..."
```

### Argument Constraint Types

| Constraint | Description | Example |
|---|---|---|
| `pattern` | Regex match on argument value | `"^/tmp/"` -- path must start with /tmp/ |
| `max_length` | Maximum string length | `256` -- path must not exceed 256 characters |
| `min` / `max` | Numeric range limits | `min: 0, max: 1000` |
| `enum` | Enum whitelist | `["read", "write", "append"]` |

### Built-in Policy Templates

```python
from agentgate.policy.defaults import DEFAULT_POLICY, PERMISSIVE_POLICY, DEVELOPMENT_POLICY
```

| Template | Use Case | Behavior |
|---|---|---|
| `DEFAULT_POLICY` | Production | Deny all unregistered Agents, audit + signing, 1 call per session |
| `PERMISSIVE_POLICY` | Permissive monitoring | Allow all tools, full auditing, up to 10,000 calls per session |
| `DEVELOPMENT_POLICY` | Development & debugging | Allow all tools, high-sensitivity anomaly detection, 7-day audit retention |

### Policy Loading API

```python
from agentgate import load_policy, load_policy_from_string, load_policy_from_dict
from agentgate.policy.loader import merge_policies, validate_policy_file

# Load from file
policy = load_policy("agentgate.yaml")

# Load from YAML string
policy = load_policy_from_string("""
version: "1"
agents:
  my-agent:
    tools:
      allowed:
        - name: "search_*"
""")

# Load from dict
policy = load_policy_from_dict({"version": "1", "agents": {}})

# Merge multiple policies (latter overrides former)
merged = merge_policies(base_policy, override_policy)

# Validate a policy file (returns a list of errors/warnings instead of raising)
issues = validate_policy_file("agentgate.yaml")
for issue in issues:
    print(issue)  # "error: ..." or "warning: ..."
```

---

### 策略文件结构

策略使用 YAML 格式，完整结构如下：

```yaml
version: "1"
description: "策略描述"

agents:
  # 每个 Agent 的策略
  agent_name:
    role: "agent 角色描述"

    tools:
      # 允许的工具列表
      allowed:
        - name: "tool_name"           # 精确匹配
        - name: "search_*"            # glob 通配符
        - name: "write_file"
          args:                       # 参数约束
            path:
              pattern: "^/tmp/"       # 正则匹配
              max_length: 256         # 最大长度
            content:
              max_length: 10000
          rate_limit:                 # 速率限制
            max_calls: 10
            window_seconds: 60

        - name: "calculate"
          args:
            value:
              min: 0                  # 最小值
              max: 1000               # 最大值
            mode:
              enum: ["add", "sub"]    # 枚举值

      # 拒绝的工具列表（优先于允许列表）
      denied:
        - name: "delete_*"
          reason: "禁止删除操作"
        - name: "exec_shell"

    # 资源访问控制
    resources:
      filesystem:
        read: ["/data/**", "/config/*.yaml"]   # 可读路径 (glob)
        write: ["/tmp/**"]                      # 可写路径 (glob)
      network:
        allowed_domains: ["api.example.com"]    # 允许的域名
        denied_domains: ["*.evil.com", "*"]     # 拒绝的域名

    # 会话级限制
    limits:
      max_tool_calls_per_session: 100       # 单次会话最大调用数
      max_session_duration_seconds: 3600    # 单次会话最大时长（秒）

  # 默认 Agent 策略（其他未注册 Agent 的兜底）
  __default__:
    tools:
      denied:
        - name: "*"
          reason: "未注册的 Agent 不允许任何操作"

# 审计配置
audit:
  enabled: true
  storage: "sqlite"        # "sqlite" 或 "file"
  sign_records: true       # 使用 Ed25519 签名审计记录
  retention_days: 90

# 异常检测配置
anomaly:
  enabled: true
  sensitivity: "medium"    # "low" / "medium" / "high"
  alerts:
    - type: "log"          # 输出到日志
    - type: "webhook"      # 发送到 webhook
      url: "https://hooks.slack.com/services/..."
```

### 参数约束类型

| 约束 | 说明 | 示例 |
|---|---|---|
| `pattern` | 正则表达式匹配参数值 | `"^/tmp/"` -- 路径必须以 /tmp/ 开头 |
| `max_length` | 字符串最大长度 | `256` -- 路径不超过 256 字符 |
| `min` / `max` | 数值范围限制 | `min: 0, max: 1000` |
| `enum` | 枚举白名单 | `["read", "write", "append"]` |

### 内置策略模板

```python
from agentgate.policy.defaults import DEFAULT_POLICY, PERMISSIVE_POLICY, DEVELOPMENT_POLICY
```

| 模板 | 用途 | 行为 |
|---|---|---|
| `DEFAULT_POLICY` | 生产环境 | 拒绝所有未注册 Agent，审计+签名，每会话仅 1 次调用 |
| `PERMISSIVE_POLICY` | 宽松监控 | 允许所有工具，全量审计，每会话最多 10,000 次调用 |
| `DEVELOPMENT_POLICY` | 开发调试 | 允许所有工具，高灵敏度异常检测，7 天审计保留 |

### 策略加载 API

```python
from agentgate import load_policy, load_policy_from_string, load_policy_from_dict
from agentgate.policy.loader import merge_policies, validate_policy_file

# 从文件加载
policy = load_policy("agentgate.yaml")

# 从 YAML 字符串加载
policy = load_policy_from_string("""
version: "1"
agents:
  my-agent:
    tools:
      allowed:
        - name: "search_*"
""")

# 从字典加载
policy = load_policy_from_dict({"version": "1", "agents": {}})

# 合并多个策略（后者覆盖前者）
merged = merge_policies(base_policy, override_policy)

# 验证策略文件（不抛异常，返回错误/警告列表）
issues = validate_policy_file("agentgate.yaml")
for issue in issues:
    print(issue)  # "error: ..." 或 "warning: ..."
```

---

## Four Integration Modes / 四种集成模式

### Mode 1: @protect Decorator (Any Framework)

The simplest approach, applicable to any Python function:

```python
from agentgate import protect, AgentGate

# Approach A: Specify a policy file
@protect(policy="agentgate.yaml", agent_id="my-agent")
def search_docs(query: str) -> str:
    return db.search(query)

# Approach B: Share an AgentGate instance
gate = AgentGate(policy="agentgate.yaml")

@protect(gate=gate, agent_id="my-agent")
def read_file(path: str) -> str:
    return open(path).read()

@protect(gate=gate, agent_id="my-agent")
def write_file(path: str, content: str) -> None:
    open(path, "w").write(content)

# Approach C: Protect async functions (auto-detected)
@protect(policy="agentgate.yaml", agent_id="my-agent")
async def fetch_url(url: str) -> str:
    async with aiohttp.ClientSession() as s:
        return await (await s.get(url)).text()

# Usage remains the same -- security checks happen automatically
result = search_docs(query="hello")       # Arguments passed via kwargs are validated
content = read_file(path="/data/file.txt")
```

**Parameter Reference:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `policy` | `str \| Path \| AgentGatePolicy \| dict \| None` | `None` | Policy source; `None` uses built-in default |
| `agent_id` | `str` | `"default"` | Agent identifier for policy lookup and audit records |
| `session_id` | `str \| None` | `None` | Session identifier; `None` auto-generates a UUID |
| `gate` | `AgentGate \| None` | `None` | Reuse an existing instance; when provided, `policy` is ignored |

**Note:** Only arguments passed via `kwargs` are validated by the policy engine. Positional arguments are not introspected.

### Mode 2: LangChain Middleware

```python
from agentgate.integrations.langchain import AgentGateMiddleware

# Create middleware
middleware = AgentGateMiddleware(
    policy="production.yaml",
    agent_id="langchain-agent",
)

# Pass as a callback handler to LangChain
from langchain.agents import create_react_agent

agent = create_react_agent(
    model=llm,
    tools=tools,
    callbacks=[middleware],  # AgentGate automatically intercepts all tool calls
)

# Clean up when done
middleware.close()
```

**How it works:**
- `on_tool_start`: Checks policy and rate limits before tool execution; raises `ToolCallDenied` on denial
- `on_tool_end`: Records successful tool calls and their duration
- `on_tool_error`: Records errors (automatically skips `ToolCallDenied` to avoid duplicate auditing)

### Mode 3: CrewAI Callback

```python
from agentgate.integrations.crewai import AgentGateCrewCallback

callback = AgentGateCrewCallback(
    policy="production.yaml",
    agent_id="crewai-agent",
)

# Use with CrewAI
from crewai import Crew, Agent, Task

crew = Crew(
    agents=[...],
    tasks=[...],
    step_callback=callback.step_callback,     # Intercept each tool call step
    task_callback=callback.task_callback,     # Record task completion events
)
crew.kickoff()
callback.close()
```

### Mode 4: AutoGen Adapter

```python
from agentgate.integrations.autogen import AgentGateAutoGenAdapter

adapter = AgentGateAutoGenAdapter(
    policy="production.yaml",
    agent_id="autogen-agent",
)

# Install onto an AutoGen Agent (monkey-patches execute_function)
from autogen import ConversableAgent

agent = ConversableAgent(name="assistant", ...)
adapter.install(agent)

# During execution, all function calls go through AgentGate
# Denied calls return error responses instead of raising exceptions (AutoGen-friendly)

# Uninstall and clean up
adapter.uninstall()
adapter.close()
```

---

### 模式 1: @protect 装饰器（任何框架）

最简单的方式，适用于任何 Python 函数：

```python
from agentgate import protect, AgentGate

# 方式 A: 指定策略文件
@protect(policy="agentgate.yaml", agent_id="my-agent")
def search_docs(query: str) -> str:
    return db.search(query)

# 方式 B: 共享 AgentGate 实例
gate = AgentGate(policy="agentgate.yaml")

@protect(gate=gate, agent_id="my-agent")
def read_file(path: str) -> str:
    return open(path).read()

@protect(gate=gate, agent_id="my-agent")
def write_file(path: str, content: str) -> None:
    open(path, "w").write(content)

# 方式 C: 保护异步函数（自动检测）
@protect(policy="agentgate.yaml", agent_id="my-agent")
async def fetch_url(url: str) -> str:
    async with aiohttp.ClientSession() as s:
        return await (await s.get(url)).text()

# 调用方式不变，安全检查自动进行
result = search_docs(query="hello")       # 通过 kwargs 传递的参数会被校验
content = read_file(path="/data/file.txt")
```

**参数说明：**

| 参数 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `policy` | `str \| Path \| AgentGatePolicy \| dict \| None` | `None` | 策略来源，`None` 使用内置默认 |
| `agent_id` | `str` | `"default"` | 用于策略查找和审计记录的 Agent 标识 |
| `session_id` | `str \| None` | `None` | 会话标识，`None` 自动生成 UUID |
| `gate` | `AgentGate \| None` | `None` | 复用已有实例，提供时忽略 `policy` |

**注意：** 只有通过 `kwargs` 传递的参数才会被策略引擎校验。位置参数不会被内省。

### 模式 2: LangChain 中间件

```python
from agentgate.integrations.langchain import AgentGateMiddleware

# 创建中间件
middleware = AgentGateMiddleware(
    policy="production.yaml",
    agent_id="langchain-agent",
)

# 作为回调处理器传入 LangChain
from langchain.agents import create_react_agent

agent = create_react_agent(
    model=llm,
    tools=tools,
    callbacks=[middleware],  # AgentGate 自动拦截所有工具调用
)

# 使用完毕后清理
middleware.close()
```

**工作原理：**
- `on_tool_start`: 在工具执行前检查策略和速率限制，拒绝时抛出 `ToolCallDenied`
- `on_tool_end`: 记录成功的工具调用及耗时
- `on_tool_error`: 记录错误（自动跳过 `ToolCallDenied` 避免重复审计）

### 模式 3: CrewAI 回调

```python
from agentgate.integrations.crewai import AgentGateCrewCallback

callback = AgentGateCrewCallback(
    policy="production.yaml",
    agent_id="crewai-agent",
)

# 在 CrewAI 中使用
from crewai import Crew, Agent, Task

crew = Crew(
    agents=[...],
    tasks=[...],
    step_callback=callback.step_callback,     # 拦截每一步工具调用
    task_callback=callback.task_callback,     # 记录任务完成事件
)
crew.kickoff()
callback.close()
```

### 模式 4: AutoGen 适配器

```python
from agentgate.integrations.autogen import AgentGateAutoGenAdapter

adapter = AgentGateAutoGenAdapter(
    policy="production.yaml",
    agent_id="autogen-agent",
)

# 安装到 AutoGen Agent 上（monkey-patch execute_function）
from autogen import ConversableAgent

agent = ConversableAgent(name="assistant", ...)
adapter.install(agent)

# Agent 执行时，所有函数调用都会经过 AgentGate
# 被拒绝的调用会返回错误响应而不是抛异常（AutoGen 友好）

# 卸载并清理
adapter.uninstall()
adapter.close()
```

---

## Audit System / 审计系统

### Audit Event Model

Every tool call (whether allowed or denied) generates an immutable `AuditEvent`:

```python
from agentgate import AuditEvent

# AuditEvent fields:
event = AuditEvent(
    # Auto-generated
    event_id="550e8400-...",              # UUID-4, auto-generated
    timestamp="2025-01-15T10:30:00+00:00", # UTC time, auto-generated

    # Required
    agent_id="my-agent",
    session_id="session-001",
    action_type="tool_call",              # "tool_call" | "file_access" | "network_request" | "memory_change"
    decision="allowed",                    # "allowed" | "denied" | "rate_limited"

    # Optional
    tool_name="search_docs",
    tool_args={"query": "hello"},
    deny_reason=None,                     # Reason for denial
    result_summary="Found 3 results",     # Execution result summary
    duration_ms=12.5,                     # Execution duration (ms)
    anomaly_score=0.15,                   # Anomaly score 0.0-1.0
    anomaly_flags=["new_tool:search_docs"], # Anomaly flag list
    signature="a1b2c3...",                # Ed25519 signature (if enabled)
    metadata={},                          # Custom metadata
)
```

### Using the Audit Store Directly

```python
from agentgate.audit.store import AuditStore
from agentgate.audit.models import AuditEvent, AuditQuery

# Open audit database
store = AuditStore("agentgate_audit.db")

# Query events
events = store.query(AuditQuery(
    agent_id="my-agent",             # Filter by Agent
    decision="denied",               # Only denied events
    tool_name="delete_*",            # Glob pattern match on tool name
    min_anomaly_score=0.5,           # Anomaly score >= 0.5
    limit=50,                        # Return at most 50 records
    offset=0,                        # Pagination offset
))

for event in events:
    print(f"{event.timestamp} | {event.tool_name} | {event.decision} | score={event.anomaly_score}")

# Count events
count = store.count(AuditQuery(agent_id="my-agent"))

# Get aggregate summary
summary = store.get_summary(agent_id="my-agent", hours=24)
# Returns:
# {
#     "total_events": 150,
#     "by_decision": {"allowed": 130, "denied": 18, "rate_limited": 2},
#     "by_action_type": {"tool_call": 145, "file_access": 5},
#     "by_tool": {"search_docs": 80, "read_file": 50, ...},
#     "top_denied_tools": [{"tool_name": "delete_user", "count": 10}, ...],
#     "avg_anomaly_score": 0.12,
# }

store.close()
```

### Exporting Audit Data

```python
from agentgate.audit.query import export_events_json, export_events_csv, format_events_table

# Export as JSON
export_events_json(events, "audit_export.json")

# Export as CSV
export_events_csv(events, "audit_export.csv")

# Format as a Rich table string
table_str = format_events_table(events)
print(table_str)
```

---

### 审计事件模型

每次工具调用（无论允许还是拒绝）都会生成一个不可变的 `AuditEvent`：

```python
from agentgate import AuditEvent

# AuditEvent 的字段：
event = AuditEvent(
    # 自动生成
    event_id="550e8400-...",              # UUID-4，自动生成
    timestamp="2025-01-15T10:30:00+00:00", # UTC 时间，自动生成

    # 必填
    agent_id="my-agent",
    session_id="session-001",
    action_type="tool_call",              # "tool_call" | "file_access" | "network_request" | "memory_change"
    decision="allowed",                    # "allowed" | "denied" | "rate_limited"

    # 可选
    tool_name="search_docs",
    tool_args={"query": "hello"},
    deny_reason=None,                     # 拒绝时的原因
    result_summary="Found 3 results",     # 执行结果摘要
    duration_ms=12.5,                     # 执行耗时（毫秒）
    anomaly_score=0.15,                   # 异常分数 0.0-1.0
    anomaly_flags=["new_tool:search_docs"], # 异常标记列表
    signature="a1b2c3...",                # Ed25519 签名（如启用）
    metadata={},                          # 自定义元数据
)
```

### 直接使用审计存储

```python
from agentgate.audit.store import AuditStore
from agentgate.audit.models import AuditEvent, AuditQuery

# 打开审计数据库
store = AuditStore("agentgate_audit.db")

# 查询事件
events = store.query(AuditQuery(
    agent_id="my-agent",             # 按 Agent 过滤
    decision="denied",               # 只看被拒绝的
    tool_name="delete_*",            # glob 模式匹配工具名
    min_anomaly_score=0.5,           # 异常分数 >= 0.5
    limit=50,                        # 最多返回 50 条
    offset=0,                        # 分页偏移
))

for event in events:
    print(f"{event.timestamp} | {event.tool_name} | {event.decision} | score={event.anomaly_score}")

# 统计事件数量
count = store.count(AuditQuery(agent_id="my-agent"))

# 获取聚合摘要
summary = store.get_summary(agent_id="my-agent", hours=24)
# 返回:
# {
#     "total_events": 150,
#     "by_decision": {"allowed": 130, "denied": 18, "rate_limited": 2},
#     "by_action_type": {"tool_call": 145, "file_access": 5},
#     "by_tool": {"search_docs": 80, "read_file": 50, ...},
#     "top_denied_tools": [{"tool_name": "delete_user", "count": 10}, ...],
#     "avg_anomaly_score": 0.12,
# }

store.close()
```

### 导出审计数据

```python
from agentgate.audit.query import export_events_json, export_events_csv, format_events_table

# 导出为 JSON
export_events_json(events, "audit_export.json")

# 导出为 CSV
export_events_csv(events, "audit_export.csv")

# 格式化为 Rich 表格字符串
table_str = format_events_table(events)
print(table_str)
```

---

## Anomaly Detection / 异常检测

### Six Detection Dimensions

AgentGate's anomaly detector maintains behavioral baselines for each Agent and detects anomalies across the following dimensions:

| Detection | Flag Format | Base Score Weight | Description |
|---|---|---|---|
| New tool usage | `new_tool:<name>` | 0.35 | Agent uses a tool for the first time |
| Call frequency anomaly | `frequency_spike:z=...` | 0.30 | Call interval deviates from mean by >2 standard deviations |
| Unusual argument values | `unusual_arg:<tool>.<arg>` | 0.15 | Argument value never seen in historical data |
| Session duration anomaly | `session_duration_anomaly:...` | 0.20 | Session duration deviates from historical mean |
| Denial rate spike | `denied_rate_spike:...` | 0.25 | Denial rate suddenly increases |
| Behavioral sequence anomaly | `sequence_break:<a>-><b>` | 0.20 | Tool call sequence never observed before |

### Sensitivity Thresholds

| Sensitivity | Threshold | Effect |
|---|---|---|
| `low` | 0.8 | Only flags highly suspicious behavior; fewer alerts |
| `medium` | 0.6 | Balanced mode (default) |
| `high` | 0.4 | Aggressive flagging; suitable for high-security scenarios |

Anomaly scores below the threshold are attenuated by 50% and flags are cleared.

### Alert Dispatching

```yaml
anomaly:
  enabled: true
  sensitivity: "medium"
  alerts:
    - type: "log"                    # Output to Python logging (WARNING level)
    - type: "webhook"                # Non-blocking POST to webhook
      url: "https://hooks.slack.com/services/T.../B.../xxx"
```

Alerts are only triggered when the anomaly score exceeds the sensitivity threshold. Webhooks are sent via background threads and do not block Agent execution.

---

### 六种检测维度

AgentGate 的异常检测器对每个 Agent 维护行为基线，通过以下维度检测异常：

| 检测项 | 标记格式 | 基础分数权重 | 说明 |
|---|---|---|---|
| 新工具使用 | `new_tool:<name>` | 0.35 | Agent 首次使用某个工具 |
| 调用频率异常 | `frequency_spike:z=...` | 0.30 | 调用间隔偏离均值 >2 个标准差 |
| 异常参数值 | `unusual_arg:<tool>.<arg>` | 0.15 | 参数值从未在历史中出现过 |
| 会话时长异常 | `session_duration_anomaly:...` | 0.20 | 会话时长偏离历史均值 |
| 拒绝率飙升 | `denied_rate_spike:...` | 0.25 | 拒绝率突然升高 |
| 行为序列异常 | `sequence_break:<a>-><b>` | 0.20 | 工具调用顺序从未出现过 |

### 灵敏度阈值

| 灵敏度 | 阈值 | 效果 |
|---|---|---|
| `low` | 0.8 | 只标记高度可疑行为，较少告警 |
| `medium` | 0.6 | 平衡模式（默认） |
| `high` | 0.4 | 激进标记，适用于高安全场景 |

低于阈值的异常分数会被衰减 50% 并清除标记。

### 告警分发

```yaml
anomaly:
  enabled: true
  sensitivity: "medium"
  alerts:
    - type: "log"                    # 输出到 Python logging (WARNING 级别)
    - type: "webhook"                # 非阻塞 POST 到 webhook
      url: "https://hooks.slack.com/services/T.../B.../xxx"
```

只有当异常分数超过灵敏度阈值时才会触发告警。Webhook 使用后台线程发送，不阻塞 Agent 执行。

---

## CLI Tool / CLI 命令行工具

Available via the `agentgate` command after installation.

安装后通过 `agentgate` 命令使用。

### `agentgate init` -- Initialize Policy File / 初始化策略文件

```bash
# Use default template
agentgate init

# Specify template and output path
agentgate init --template development --output my-policy.yaml
```

Available templates: `default` (strict), `permissive` (lenient), `development` (dev)

可用模板: `default`（严格）、`permissive`（宽松）、`development`（开发）

### `agentgate check` -- Validate Policy File / 验证策略文件

```bash
agentgate check agentgate.yaml
```

**Output / 输出：**
- List of errors and warnings / 错误和警告列表
- Policy summary table (Agent count, tool rule count, rate limits, audit config, etc.) / 策略摘要表格（Agent 数、工具规则数、速率限制、审计配置等）
- Exit code 0 (valid) / 1 (invalid) / 退出码 0（有效）/ 1（无效）

### `agentgate audit` -- Query Audit Logs / 查询审计日志

```bash
# View all events from the last hour
agentgate audit --last 1h

# Filter denied events for a specific Agent
agentgate audit --agent my-agent --decision denied --last 24h

# Filter by tool, output as JSON
agentgate audit --tool "delete_*" --format json --output denied.json

# Paginated view
agentgate audit --limit 20 --last 7d

# Specify database path
agentgate audit --db /path/to/audit.db --last 1h
```

**Options / 选项：**

| Option | Description / 说明 | Default / 默认值 |
|---|---|---|
| `--db` | SQLite database path / SQLite 数据库路径 | `agentgate_audit.db` |
| `--agent, -a` | Filter by Agent ID / 按 Agent ID 过滤 | - |
| `--session, -s` | Filter by Session ID / 按 Session ID 过滤 | - |
| `--last, -l` | Time window / 时间窗口 (`30m`, `1h`, `24h`, `7d`, `2w`) | - |
| `--decision, -d` | Filter by decision / 按决策过滤 (`allowed`/`denied`/`rate_limited`) | - |
| `--tool` | Filter by tool name (glob) / 按工具名过滤（支持 glob） | - |
| `--limit, -n` | Max results / 最大返回数 | 50 |
| `--format, -f` | Output format / 输出格式 (`table`/`json`/`csv`) | `table` |
| `--output, -o` | Output file path / 输出文件路径 | - |

### `agentgate report` -- Generate Security Report / 生成安全报告

```bash
# Security report for the last 24 hours
agentgate report

# Report for a specific Agent over the last 7 days
agentgate report --agent my-agent --last 7d

# Output as JSON
agentgate report --format json
```

The report includes: total events, decision distribution (allowed/denied/rate-limited), top tools, top denied tools, anomaly statistics, and actionable recommendations.

报告包含：事件总数、决策分布（允许/拒绝/限流）、Top 工具、Top 被拒绝工具、异常统计、针对性建议。

### `agentgate scan` -- Security Scan / 安全扫描

```bash
agentgate scan ./my-agent-project/
```

Scans an Agent project directory and detects the following issues:

扫描 Agent 项目目录，检测以下问题：

| Severity | Issue / 检测项 | Deduction / 扣分 |
|---|---|---|
| CRITICAL | Missing policy file (`agentgate.yaml`) / 缺少策略文件 | -25 |
| HIGH | Tool definitions not protected by AgentGate / 工具定义未受 AgentGate 保护 | -10 |
| HIGH | Network requests without domain restrictions / 未限制域名的网络请求 | -10 |
| MEDIUM | Unrestricted filesystem write/delete / 不受限的文件系统写入/删除 | -5 |
| MEDIUM | Unthrottled tool calls in loops / 循环内未限速的工具调用 | -5 |

**Example output / 输出示例：**

```
+-------------------- AgentGate Security Scan --------------------+
|                                                                  |
|  Security Report Card                                            |
|                                                                  |
|  Project: /path/to/my-agent                                      |
|  Files scanned: 15                                               |
|  Frameworks detected: LangChain, CrewAI                          |
|  Policy file: missing                                            |
|                                                                  |
|  Score: 38/100  Grade: D+                                        |
|                                                                  |
+------------------------------------------------------------------+

| Severity   | Issue                         | OWASP          |
|------------|-------------------------------|----------------|
| CRITICAL   | No policy file found          | OWASP-AGENT-01 |
| HIGH       | 3 unprotected tool defs       | OWASP-AGENT-02 |
| MEDIUM     | Unrestricted file access      | OWASP-AGENT-03 |
```

**Auto-detected frameworks / 框架自动检测：** LangChain, CrewAI, AutoGen, LlamaIndex, OpenAI, Anthropic, SmolAgents

### `agentgate proxy` -- HTTP Proxy (Phase 2) / HTTP 代理（Phase 2）

```bash
agentgate proxy --policy production.yaml --upstream http://localhost:8080
```

Provides an HTTP proxy mode for non-Python Agents. The current version displays "Coming Soon"; the command structure is already in place.

为非 Python Agent 提供 HTTP 代理模式。当前版本显示 "Coming Soon"，命令结构已就绪。

### `agentgate version` -- Show Version / 显示版本

```bash
agentgate version
# agentgate 0.1.0
```

---

## Rust Acceleration Layer / Rust 加速层

Three high-performance modules are exposed via PyO3:

通过 PyO3 暴露三个高性能模块：

```python
from agentgate._core import PolicyMatcher, AuditWriter, AuditSigner
```

### PolicyMatcher -- Policy Matching Engine / 策略匹配引擎

```python
pm = PolicyMatcher()

# Compile policy rules (JSON format)
import json
deny_rules = json.dumps([
    {"tool_pattern": "delete_*", "deny_reason": "No deletes", "is_deny": True}
])
allow_rules = json.dumps([
    {"tool_pattern": "search_*"},
    {"tool_pattern": "read_*", "arg_constraints": [
        {"key": "path", "pattern": "^/data/", "max_length": 256}
    ]}
])
pm.compile_policy("agent-1", deny_rules, allow_rules)

# Check a tool call (~238 ns/call, ~4.2M calls/sec)
result = pm.check_tool_call("agent-1", "search_docs", '{"query": "hello"}')
# {"decision": "allowed", "reason": None}

result = pm.check_tool_call("agent-1", "delete_file", '{}')
# {"decision": "denied", "reason": "No deletes"}
```

### AuditWriter -- High-Throughput Audit Writer / 高吞吐审计写入器

```python
writer = AuditWriter("audit.db", batch_size=100, flush_interval_ms=1000)

# Non-blocking write (background thread batches writes to SQLite)
writer.write_event('{"event_id": "...", "agent_id": "...", ...}')

# Force flush
writer.flush()

# Close (auto-flushes)
writer.close()
```

### AuditSigner -- Ed25519 Signing / Ed25519 签名

```python
signer = AuditSigner()

# Sign data
signature = signer.sign("audit event payload")  # 128-char hex string

# Verify signature
is_valid = signer.verify("audit event payload", signature)  # True

# Get public key (64-char hex, distributable to verifiers)
public_key = signer.public_key_hex()

# Restore from existing key
signer2 = AuditSigner.from_bytes(secret_key_bytes)  # 32 bytes
```

---

## End-to-End Walkthrough / 完整使用流程

### Scenario: Protecting a Customer Support AI Agent

### 场景：保护一个客服 AI Agent

#### Step 1: Initialize Policy / 初始化策略

```bash
cd my-agent-project
agentgate init --template default
```

#### Step 2: Edit the Policy File / 编辑策略文件

Edit `agentgate.yaml`:

编辑 `agentgate.yaml`：

**English version with English comments:**

```yaml
version: "1"
description: "Customer Support Agent Security Policy"

agents:
  customer_support:
    role: "customer support bot"
    tools:
      allowed:
        - name: "search_knowledge_base"
          args:
            query: { max_length: 500 }

        - name: "send_email"
          args:
            to: { pattern: ".*@company\\.com$" }    # Can only send to company emails
          rate_limit:
            max_calls: 10
            window_seconds: 60                       # Max 10 emails per minute

        - name: "lookup_order"
          args:
            order_id: { pattern: "^ORD-[0-9]+$" }   # Order ID format validation

      denied:
        - name: "delete_*"
          reason: "Support agents are not allowed to delete any data"
        - name: "modify_account"
          reason: "Requires admin privileges"
        - name: "exec_*"
          reason: "System command execution is forbidden"

    resources:
      filesystem:
        read: ["/data/knowledge_base/**"]
        write: []                                     # No file writing allowed
      network:
        allowed_domains: ["api.company.com", "crm.company.com"]
        denied_domains: ["*"]                         # Block all other domains

    limits:
      max_tool_calls_per_session: 50
      max_session_duration_seconds: 1800              # 30 minutes

  __default__:
    tools:
      denied:
        - name: "*"
          reason: "Unregistered Agents are not allowed any operations"

audit:
  enabled: true
  storage: "sqlite"
  sign_records: true
  retention_days: 90

anomaly:
  enabled: true
  sensitivity: "medium"
  alerts:
    - type: "log"
    - type: "webhook"
      url: "https://hooks.slack.com/services/xxx"
```

**中文版本（含中文注释）：**

```yaml
version: "1"
description: "客服 Agent 安全策略"

agents:
  customer_support:
    role: "customer support bot"
    tools:
      allowed:
        - name: "search_knowledge_base"
          args:
            query: { max_length: 500 }

        - name: "send_email"
          args:
            to: { pattern: ".*@company\\.com$" }    # 只能发给公司邮箱
          rate_limit:
            max_calls: 10
            window_seconds: 60                       # 每分钟最多 10 封

        - name: "lookup_order"
          args:
            order_id: { pattern: "^ORD-[0-9]+$" }   # 订单号格式校验

      denied:
        - name: "delete_*"
          reason: "客服不允许删除任何数据"
        - name: "modify_account"
          reason: "需要管理员权限"
        - name: "exec_*"
          reason: "禁止执行系统命令"

    resources:
      filesystem:
        read: ["/data/knowledge_base/**"]
        write: []                                     # 不允许写入文件
      network:
        allowed_domains: ["api.company.com", "crm.company.com"]
        denied_domains: ["*"]                         # 禁止访问其他域名

    limits:
      max_tool_calls_per_session: 50
      max_session_duration_seconds: 1800              # 30 分钟

  __default__:
    tools:
      denied:
        - name: "*"
          reason: "未注册的 Agent 不允许任何操作"

audit:
  enabled: true
  storage: "sqlite"
  sign_records: true
  retention_days: 90

anomaly:
  enabled: true
  sensitivity: "medium"
  alerts:
    - type: "log"
    - type: "webhook"
      url: "https://hooks.slack.com/services/xxx"
```

#### Step 3: Validate the Policy / 验证策略

```bash
agentgate check agentgate.yaml
```

#### Step 4: Integrate into Agent Code / 集成到 Agent 代码

**Using the core API / 使用核心 API：**

```python
from agentgate import AgentGate, ToolCallDenied

gate = AgentGate(policy="agentgate.yaml")

# Wrap your Agent's tool calls
# 在你的 Agent 工具调用处包裹
def handle_user_request(user_message: str):
    # ... Agent decides which tool to call ...
    tool_name = agent.decide_tool(user_message)
    tool_args = agent.extract_args(user_message)

    try:
        result = gate.intercept_tool_call_sync(
            agent_id="customer_support",
            session_id=current_session_id,
            tool_name=tool_name,
            tool_args=tool_args,
            execute_fn=lambda **kwargs: tools[tool_name](**kwargs),
        )
        return result
    except ToolCallDenied as e:
        return f"Sorry, this operation is not allowed: {e.reason}"
```

**Using the decorator / 使用装饰器方式：**

```python
from agentgate import protect

@protect(policy="agentgate.yaml", agent_id="customer_support")
def search_knowledge_base(query: str) -> str:
    return kb.search(query)

@protect(policy="agentgate.yaml", agent_id="customer_support")
def send_email(to: str, subject: str, body: str) -> str:
    return email_service.send(to, subject, body)
```

#### Step 5: Run and Monitor / 运行并监控

```bash
# Scan project security status / 扫描项目安全状态
agentgate scan .

# View real-time audit logs / 查看实时审计日志
agentgate audit --last 1h

# View denied calls / 查看被拒绝的调用
agentgate audit --decision denied --last 24h

# Generate security report / 生成安全报告
agentgate report --last 7d

# Export audit data for further analysis / 导出审计数据供进一步分析
agentgate audit --last 30d --format csv --output monthly_audit.csv
```

---

## API Reference / API 参考

### Core Classes / 核心类

#### `AgentGate`

```python
class AgentGate:
    def __init__(
        self,
        policy: AgentGatePolicy | str | Path | dict | None = None,
        audit_db: str | Path = "agentgate_audit.db",
        enable_anomaly: bool = True,
    ) -> None

    async def intercept_tool_call(
        self,
        agent_id: str,
        session_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
        execute_fn: Callable[..., Any],
    ) -> Any

    def intercept_tool_call_sync(
        self,
        agent_id: str,
        session_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
        execute_fn: Callable[..., Any],
    ) -> Any

    def get_audit_summary(
        self,
        agent_id: str | None = None,
        session_id: str | None = None,
        hours: int = 24,
    ) -> dict[str, Any]

    def close(self) -> None

    @property
    def policy(self) -> AgentGatePolicy
```

#### `ToolCallDenied`

```python
class ToolCallDenied(Exception):
    decision: str       # "denied" or "rate_limited" / "denied" 或 "rate_limited"
    tool_name: str
    reason: str
```

#### `AgentContext`

```python
@dataclass
class AgentContext:
    agent_id: str
    session_id: str
    role: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
```

### Policy Models / 策略模型

| Class / 类 | Key Fields / 关键字段 |
|---|---|
| `AgentGatePolicy` | `version`, `description`, `agents: dict[str, AgentPolicy]`, `audit`, `anomaly` |
| `AgentPolicy` | `role`, `tools: ToolsPolicy`, `resources`, `limits` |
| `ToolsPolicy` | `allowed: list[ToolPermission]`, `denied: list[ToolPermission]` |
| `ToolPermission` | `name` (glob), `args: dict[str, ArgConstraint]`, `rate_limit`, `reason` |
| `ArgConstraint` | `max_length`, `pattern`, `min`, `max`, `enum` |
| `RateLimit` | `max_calls`, `window_seconds` |
| `AgentLimits` | `max_tool_calls_per_session`, `max_session_duration_seconds` |
| `AuditConfig` | `enabled`, `storage`, `sign_records`, `retention_days` |
| `AnomalyConfig` | `enabled`, `sensitivity`, `alerts` |

### Decorator / 装饰器

```python
def protect(
    policy: str | Path | AgentGatePolicy | dict | None = None,
    agent_id: str = "default",
    session_id: str | None = None,
    gate: AgentGate | None = None,
) -> Callable
```

### Framework Integrations / 框架集成

| Class / 类 | Framework / 框架 | Install / 安装依赖 |
|---|---|---|
| `AgentGateMiddleware` | LangChain | `pip install agentgate[langchain]` |
| `AgentGateCrewCallback` | CrewAI | `pip install agentgate[crewai]` |
| `AgentGateAutoGenAdapter` | AutoGen | `pip install agentgate[autogen]` |

All integration classes accept the same constructor parameters: `policy`, `gate`, `agent_id`, `session_id`. If the corresponding framework is not installed, the class can still be imported, but instantiation will raise an `ImportError` with installation instructions.

所有集成类都接受相同的构造参数: `policy`, `gate`, `agent_id`, `session_id`。未安装对应框架时仍可导入，但实例化时会抛出 `ImportError` 并提示安装命令。
