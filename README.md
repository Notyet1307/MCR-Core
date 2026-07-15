# MCR Core

MCR Core 是一个与运行时、业务场景无关的 Go 库，用于记录、查询、回放和验证不可变的 Task Fact。它以单一追加式 JSONL 账本作为事实来源，并提供一个只负责 JSON 输入输出的轻量 CLI。

当前版本：[`v0.1.0`](https://github.com/Notyet1307/MCR-Core/releases/tag/v0.1.0)

## 核心能力

- **单一事实来源**：每个 Workspace 只使用 `.mcr/events.jsonl`，不维护第二份权威状态。
- **不可变、可验证**：原生记录使用 SHA-256 哈希链，Fact ID、时间戳和哈希由 Core 生成。
- **严格领域约束**：原生账本只接受 12 种内置 Kind；跨 Fact 关系必须引用同一 Workspace、同一 Task 中更早的精确记录。
- **确定性读取**：`Query` 按账本顺序返回 Fact；`Replay` 只从已验证历史构建有序投影。
- **安全持久化**：非阻塞文件锁、同目录临时文件、`sync`、原子替换和目录同步共同保证提交完整性。
- **只读兼容旧历史**：兼容的 Agent-lab 历史可以查询、回放和验证，但不会被修改、补链或转换。
- **有界流式处理**：读取和提交不会保留整份历史的 payload 副本；内存主要由结果、最大记录和紧凑引用索引决定。

## 安装

要求 Go 1.25 或更高版本。当前 v0.1.0 使用 `syscall.Flock`，支持提供该接口的类 Unix 平台（如 Linux 和 macOS），不支持 Windows。

将库加入项目：

```bash
go get github.com/Notyet1307/MCR-Core@v0.1.0
```

安装 CLI：

```bash
go install github.com/Notyet1307/MCR-Core/cmd/mcr@v0.1.0
```

## Go 库快速开始

Workspace 根目录必须已经存在；`Create` 会在其中创建私有的 `.mcr` 目录和原生账本。

```go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	mcr "github.com/Notyet1307/MCR-Core"
)

func main() {
	const workspacePath = "./demo-workspace"
	if err := os.MkdirAll(workspacePath, 0o700); err != nil {
		log.Fatal(err)
	}

	workspace, err := mcr.Create(workspacePath, "workspace-demo")
	if err != nil {
		log.Fatal(err)
	}

	fact, err := workspace.Submit(mcr.Submission{
		TaskID: "task-demo",
		Actor:  mcr.Actor{Type: "human", ID: "alice"},
		Kind:   mcr.KindTaskCreated,
		Payload: json.RawMessage(`{
			"definition": {
				"namespace": "example",
				"id": "demo-task",
				"version": "v1",
				"locator": "https://example.invalid/tasks/demo-v1.json",
				"sha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
			}
		}`),
	})
	if err != nil {
		log.Fatal(err)
	}

	verification, err := workspace.Verify()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("fact=%s integrity=%s\n", fact.FactID, verification.Integrity)
}
```

重新打开已有 Workspace：

```go
workspace, err := mcr.Open("./demo-workspace")
```

查询和回放：

```go
facts, err := workspace.Query(mcr.FactQuery{
	TaskID: "task-demo",
	Kind:   mcr.KindTaskCreated,
})

projection, err := workspace.Replay()
```

`FactQuery` 的非空字段使用精确匹配，并以 AND 组合；空查询返回全部 Task Fact。

## CLI

CLI 只有四个命令，并且每个命令都要求显式传入 `--workspace`。CLI 不负责创建 Workspace；请先通过 Go 库调用 `mcr.Create`。

### 验证

```bash
mcr verify --workspace ./demo-workspace
```

`verify` 在 stdout 输出 `Verification` JSON；诊断信息同时写入 stderr。

- 退出码 `0`：完整性为 `sealed_valid`
- 退出码 `1`：历史未形成有效密封链
- 退出码 `2`：参数、I/O 或其他操作错误

### 查询

```bash
# 返回全部 Fact
mcr query --workspace ./demo-workspace

# 精确过滤；多个条件以 AND 组合
mcr query \
  --workspace ./demo-workspace \
  --task-id task-demo \
  --kind task.created
```

可用过滤参数：`--fact-id`、`--task-id`、`--kind`。

### 回放

```bash
mcr replay --workspace ./demo-workspace
```

输出确定性的 Core Projection，不执行外部系统，也不生成可变产品状态。

### 提交

`submit` 从 stdin 读取且只读取一个 `Submission` JSON 值：

```bash
cat <<'JSON' | mcr submit --workspace ./demo-workspace
{
  "task_id": "task-demo",
  "actor": {"type": "human", "id": "alice"},
  "kind": "opaque.recorded",
  "payload": {
    "kind": "example.note.recorded",
    "data": {"text": "这是一条外部扩展事实"}
  }
}
JSON
```

成功时，CLI 在 stdout 输出由 Core 补全身份、时间戳和哈希链字段后的 Fact JSON。

## 原生 Fact Kind

| Kind | 用途 |
| --- | --- |
| `task.created` | 用不可变 Definition Reference 创建 Task |
| `run.recorded` | 记录一次有开始、结束和结果的运行观察 |
| `input.registered` | 登记输入内容的位置与 SHA-256 |
| `artifact.recorded` | 登记产物内容，可精确引用一个 Run |
| `claim.recorded` | 记录陈述，可精确引用来源 Artifact |
| `source_reference.recorded` | 记录内容绑定和精确锚点 |
| `evidence.linked` | 精确关联 Claim 与 Source Reference |
| `review.recorded` | 记录对更早 Fact 的审查结果 |
| `approval.recorded` | 记录对更早 Fact 的范围化审批 |
| `policy_decision.recorded` | 记录外部策略对更早 Fact 的决定 |
| `delivery.recorded` | 记录一组 Artifact 的交付描述 |
| `opaque.recorded` | 保存不属于原生词汇的外部 JSON 对象事实 |

未知的原生 Kind 会被拒绝。扩展事实必须显式封装为 `opaque.recorded`，且其外部 `kind` 不能冒充上述原生 Kind。

## 完整性与旧历史

`Verify` 可能报告以下完整性状态：

| 状态 | 含义 |
| --- | --- |
| `sealed_valid` | 完整密封链有效 |
| `unsealed` | 兼容旧历史结构有效，但没有密码学完整性声明 |
| `partial_invalid` | 哈希字段只出现在部分记录中 |
| `sealed_invalid` | 完整密封链格式存在，但链或哈希无效 |

原生 Workspace 始终使用密封账本。兼容的旧 Workspace 是只读的：`Query`、`Replay` 和 `Verify` 可用，`Submit` 返回 `ErrReadOnly`。可选的旧 `state.json` 只用于诊断，不参与事实回放，也不会变成权威状态。

## 错误分类

公共操作保留以下可通过 `errors.Is` 判断的错误：

- `mcr.ErrNotFound`
- `mcr.ErrConflict`
- `mcr.ErrBusy`
- `mcr.ErrInvalidSubmission`
- `mcr.ErrInvalidHistory`
- `mcr.ErrReadOnly`

底层操作系统错误会尽量保留在错误链中，便于继续使用 `errors.Is` 或 `errors.As` 诊断。

## 明确边界

MCR Core 只治理不可变 Task Fact，不负责：

- 执行或调度 agent
- 解释 Pack、提示词或业务场景
- 身份认证、授权或策略执行
- HTTP/gRPC 服务
- 可变产品投影或工作流状态机
- 修改、转换、修复或续写旧历史
- Agent-lab 的依赖接入、迁移或双写

## 开发与验证

仓库不依赖 Agent-lab、外部服务或客户 Workspace。运行：

```bash
go test ./... -count=1
go vet ./...
go build -o /tmp/mcr-core ./cmd/mcr
```

领域词汇与边界以 [`CONTEXT.md`](CONTEXT.md) 为准。
