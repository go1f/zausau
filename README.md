# Sensitive Info Scan

一个参考 `gitleaks`/`detect-secrets` 思路、但更偏向“可持续迭代规则”的 Go 敏感信息扫描工具原型。

## 架构

- `cmd/senscan`: CLI 入口，提供 `scan`、`validate`、`learn`
- `configs/default-rules.json`: 外置规则与误判过滤配置
- `internal/scan`: 并发文件扫描
- `internal/rules`: 规则编译、字段提取、校验与打分
- `internal/filter`: 浅显常见误判过滤
- `internal/learn`: 调用本地 `copilot-api` 生成候选规则
- `internal/learn`: 生成候选规则、静态审查、模型 reviewer
- `skills/sensitive-rule-evolver`: 规则迭代 SKILL

## 当前能力

- 并发扫描文本文件，自动跳过常见二进制/构建目录
- 支持两类规则：
  - `regex`: 适合 PEM 私钥、JWT、手机号、身份证等强格式
  - `field`: 适合 `password/token/location/face_embedding/...` 这类字段名驱动的敏感值
- 内置浅显误判过滤：
  - 占位符、示例值、测试值
  - 掩码值
  - UUID
  - 常见哈希
  - 环境变量引用
- 支持本地 `copilot-api` 反馈闭环：
  - 先扫描和验证
  - 再把验证报告送给模型
  - 输出候选规则 JSON
  - 对候选规则做静态审查、模型 reviewer、模拟合并后验证

## 使用

```bash
go run ./cmd/senscan scan .
go run ./cmd/senscan validate
go run ./cmd/senscan learn
```

```bash
go run ./cmd/senscan scan -format json .
go run ./cmd/senscan validate -format json
go run ./cmd/senscan learn -model gpt-5.4 -out artifacts/rule-suggestions.json
```

`learn` 对 `gpt-5.x` 会优先尝试 `/v1/responses`，再尝试 `/v1/messages`。如果两者都不可用，再改用兼容的 chat 模型，优先 `-model gpt-4.1`，其次 `-model gpt-4o`。

默认 `learn` 会基于 `testdata/datasets/regression-manifest.json` 跑提案和审查，并额外输出：

- `artifacts/rule-suggestions.json`
- `artifacts/rule-review.json`

## 公开测试集回归

仓库内已经固化了一组从公开项目抽取的 fixture：

- `trufflesecurity/test_keys`
- `Yelp/detect-secrets`
- `zricethezav/gitleaks`

刷新 fixture：

```bash
./scripts/refresh_public_fixtures.sh
```

跑公开 fixture 验证：

```bash
go run ./cmd/senscan validate -manifest testdata/datasets/public-manifest.json
```

跑完整回归集：

```bash
go run ./cmd/senscan validate -manifest testdata/datasets/regression-manifest.json
```

跑负样本集：

```bash
go run ./cmd/senscan validate -manifest testdata/datasets/negative-manifest.json
```

扩充近似误报负样本：

```bash
./scripts/expand_negative_corpus.sh
```

刷新公开负样本：

```bash
./scripts/refresh_negative_public_fixtures.sh
```

## 跨平台构建

构建常用发行产物到 `dist/`：

```bash
./scripts/build_release.sh
```

默认会生成：

- `dist/senscan-windows-amd64.exe`
- `dist/senscan-linux-arm64`
- `dist/senscan-darwin-arm64`
- `dist/configs/default-rules.json`
- `dist/checksums.txt`

扫描命令默认会先找当前工作目录下的 `configs/default-rules.json`；如果不存在，再回退到可执行文件同级目录下的 `configs/default-rules.json`。因此直接分发 `dist/` 目录即可运行。

## 迭代建议

1. 先补更多公开测试集到 `testdata/datasets/`
2. 为不同类别增加更强的 validator
3. 将字段提取从单行扩展到 JSON/INI/YAML 多行上下文
4. 引入基准测试，观察大仓库扫描性能
