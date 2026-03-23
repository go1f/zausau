# zausau

`zausau` 是一个用 Go 编写的敏感信息扫描工具，设计目标不是“一次性堆规则”，而是把扫描、回归、规则审查、模型辅助迭代串成一个可持续演进的工程闭环。

项目当前重点：

- 高性能本地扫描
- 可外置、可审查、可回归的规则体系
- 先压误报，再逐步补召回
- 支持本地 `copilot-api` 辅助生成规则提案，但模型建议不会直接生效

## 适用场景

当前规则覆盖的敏感信息主要包括：

- 敏感个人信息
- 登录凭证与各类 token、cookie、session、secret、api key
- 用户密码、个人账户系统账号与密码
- 私钥、密钥、随机种子、加密因子
- 中国大陆手机号、身份证号
- 生物特征相关字段
- 虚拟财产、资产、信用、风评类字段
- 通讯录、好友列表、群组列表
- 浏览记录、通信记录、轨迹、定位、经纬度
- 音频、视频、图像等个人媒体数据

这不是合规法条清单的完整实现，而是偏工程化的“检测优先级”定义。

## 项目特点

- Go 实现，适合做本地仓库和目录扫描
- 并发扫描文件，默认跳过明显二进制和常见无关路径
- 支持两类规则：
  - `regex`：适合 PEM、手机号、身份证、JWT、云厂商 key 等强格式
  - `field`：适合 `password/token/mobile/location/...` 这类字段名驱动的值检测
- 内置误判过滤：
  - 占位符和示例值
  - 掩码值
  - UUID
  - 常见 hash
  - 环境变量引用
- 扫描时实时输出命中项
- 默认在扫描目标目录生成聚合 CSV 报表
- 支持 `learn` 命令调用本地模型产出规则 proposal，并做静态审查与模拟回归

## 快速开始

### 1. 安装与构建

要求：

- Go 1.22 及以上

本地运行：

```bash
go run ./cmd/senscan scan .
```

构建发行包：

```bash
./scripts/build_release.sh
```

默认会输出：

- `dist/senscan-windows-amd64.exe`
- `dist/senscan-linux-arm64`
- `dist/senscan-darwin-arm64`
- `dist/configs/default-rules.json`
- `dist/checksums.txt`

注意：

- 程序默认先读当前工作目录下的 `configs/default-rules.json`
- 如果当前目录没有，再回退到可执行文件同级目录下的 `configs/default-rules.json`
- 实际分发时应携带整个 `dist/` 目录，而不是只拷贝一个可执行文件

### 2. 扫描目录

扫描当前目录：

```bash
go run ./cmd/senscan scan .
```

扫描指定目录：

```bash
go run ./cmd/senscan scan /path/to/repo
```

Windows 示例：

```powershell
.\senscan-windows-amd64.exe scan "D:\Downloads\Ali"
```

扫描时默认行为：

- `text` 模式实时打印命中项
- 扫描结束后打印汇总信息
- 默认生成 CSV 汇总报表
- CSV 默认写入被扫描目标所在目录，文件名为 `senscan-report-YYYYMMDD-HHMMSS.csv`

指定输出格式：

```bash
go run ./cmd/senscan scan -format text .
go run ./cmd/senscan scan -format json .
go run ./cmd/senscan scan -format csv .
```

常用参数：

- `-config`: 指定规则文件
- `-format`: `text`、`json`、`csv`
- `-out`: 显式指定 CSV 输出路径
- `-csv`: 是否额外生成 CSV，默认 `true`
- `-progress`: 是否显示实时进度，默认 `true`
- `-workers`: 覆盖并发数
- `-max-file-size`: 覆盖单文件大小限制
- `-min-score`: 覆盖最低命中分数

## 输出说明

### 终端输出

`text` 模式下，命中项会边扫边打印。当前版本不再对命中值做脱敏，直接显示原文，并在 excerpt 里用 `<<< >>>` 高亮。

示例：

```text
[generic-credential-field][0.78] demo.env:4 credential field=api_key -> sk_live_abc123456789XYZ
  api_key = " <<<sk_live_abc123456789XYZ>>> "
```

字段含义：

- 第一段方括号：命中的规则 ID
- 第二段方括号：命中分数
- 文件与行号：命中位置
- `category`：敏感信息类别
- `reason`：命中的原因，比如 `pattern-match` 或 `field=password`
- `->` 后面的值：实际命中的原文
- 下一行 excerpt：带高亮的上下文片段

### CSV 报表

CSV 不是逐条平铺结果，而是按“同类问题”聚合。聚合维度：

- `rule_id`
- `category`
- `severity`
- `reason`

CSV 列包括：

- `rule_id`
- `category`
- `severity`
- `reason`
- `count`
- `file_count`
- `max_score`
- `sample_file`
- `sample_line`
- `sample_match`
- `sample_excerpt`

这样做的目的，是减少一大堆重复 finding，方便先处理同类问题。

## 架构概览

主要目录：

- `cmd/senscan`: CLI 入口
- `configs/default-rules.json`: 默认规则和过滤配置
- `internal/app`: 命令调度、参数解析、回归与 learn 入口
- `internal/scan`: 文件遍历、并发扫描、进度事件
- `internal/rules`: 规则编译、字段提取、打分、excerpt 构造
- `internal/filter`: 浅层误报过滤器
- `internal/report`: 终端、JSON、CSV 报表输出
- `internal/learn`: 模型调用、proposal 合并、静态审查、review report
- `skills/sensitive-rule-evolver`: 规则迭代 SKILL
- `testdata/datasets`: 回归集、负样本集、公开 fixture
- `scripts`: 构建和数据集刷新脚本

核心流程：

```text
scan
  -> 遍历文件
  -> 跳过 ignore path / ignore ext / binary / oversized file
  -> 单行提取 assignment 与 regex match
  -> 过滤浅显误判
  -> 规则打分
  -> 实时输出命中
  -> 汇总结果与 CSV
```

## 规则系统

规则在 `configs/default-rules.json` 中维护。

每条规则通常包含：

- `id`
- `kind`
- `category`
- `severity`
- `field_patterns` 或 `patterns`
- `value_patterns`
- `exclude_values`
- `exclude_value_patterns`
- `validation`
- `score`

两类规则的使用建议：

- 优先写强格式的 `regex` 规则，误报通常更低
- 对 `field` 规则要尽量加上 `value_patterns` 和 `exclude_*` 限制，避免字段名过宽导致误报

不建议直接加这种规则：

- 只看 `id|name|number|value` 这种宽泛字段名
- 没有值约束的 `password|secret|token`
- 通过扩大 ignore path 来“消灭误报”

## 回归与验证

### 快速回归

运行默认验证：

```bash
go run ./cmd/senscan validate
```

运行完整回归：

```bash
go run ./cmd/senscan validate -manifest testdata/datasets/regression-manifest.json
```

运行负样本集：

```bash
go run ./cmd/senscan validate -manifest testdata/datasets/negative-manifest.json
```

运行公开正样本：

```bash
go run ./cmd/senscan validate -manifest testdata/datasets/public-manifest.json
```

当前协作约定：

- 规则或扫描逻辑改动后，至少跑 `go test ./...`
- 提交前应跑完整回归清单
- 回归通过后再 push

## 测试数据来源

仓库里固化了一部分公开 fixture，来源包括：

- `trufflesecurity/test_keys`
- `Yelp/detect-secrets`
- `zricethezav/gitleaks`

还有一批真实负样本与生成式近似误报样本，用来压误报。

更新脚本：

```bash
./scripts/refresh_public_fixtures.sh
./scripts/refresh_negative_public_fixtures.sh
./scripts/refresh_real_world_negative_fixtures.sh
./scripts/expand_negative_corpus.sh
```

## 模型辅助规则迭代

`learn` 命令负责调用本地模型，生成规则 proposal，再做审查。

基础用法：

```bash
go run ./cmd/senscan learn
```

指定模型与输出：

```bash
go run ./cmd/senscan learn -model gpt-5.4 -out artifacts/rule-suggestions.json -review-out artifacts/rule-review.json
```

默认流程：

1. 基于 `testdata/datasets/regression-manifest.json` 跑基线验证
2. 把当前规则摘要和验证报告发给本地 `copilot-api`
3. 生成 proposal
4. 对 proposal 做静态审查
5. 将 proposal 模拟合并到规则库
6. 跑模拟验证
7. 产出 review report

默认产物：

- `artifacts/rule-suggestions.json`
- `artifacts/rule-review.json`

重要约束：

- 模型 proposal 不是自动生效
- proposal 必须经过静态审查和回归门禁
- 审查关注点包括过宽字段规则、危险 ignore path、Go 不兼容正则、Precision/Recall/FDR 门槛

关于模型接口：

- `gpt-5.x` 优先走 `/v1/responses`
- 不可用时回退 `/v1/messages`
- 再不行再考虑兼容 chat 模型

## 性能说明

当前实现是“目录遍历 + 并发文件扫描 + 单行规则匹配”的模型，适合源码仓库、配置目录、文本导出文件的本地扫描。

已做的性能优化：

- 并发 worker 扫描文件
- 二进制文件快速跳过
- 大文件大小门槛控制
- 单行 assignment 提取只做一次，避免 field rule 重复解析

已知限制：

- 当前按行扫描，不支持跨行上下文命中
- 对超大纯文本文件，扫描速度仍然主要受正则数量和单行长度影响
- 字段规则多了之后，误报和性能都可能变差，所以新增规则前先补负样本

## 协作者开发流程

推荐流程：

1. 拉取代码并先跑 `go test ./...`
2. 跑一次 `validate -manifest testdata/datasets/regression-manifest.json`
3. 再修改规则或代码
4. 修改后重新跑回归
5. 必要时用 `scan` 对真实目录手工验证输出是否可读
6. 回归通过后再提交

如果你在改规则，建议同时做三件事：

- 增加一个正样本或漏报样本
- 增加一个负样本或近似误报样本
- 说明这条规则为什么不会把误报面放大

## 常见问题

### 为什么只拷贝 exe 会报找不到 `configs/default-rules.json`

因为规则文件默认不是内嵌的。请携带整个 `dist/` 目录，或者用 `-config` 显式指定规则文件路径。

### 为什么扫描时没看到进度条

实时进度输出默认写到 `stderr`，且只有在终端设备上才渲染。重定向到文件时，finding 仍会实时输出，但进度条不会渲染。

### 为什么命中值现在不打码

当前版本按协作需求改成了“直接展示原文，高亮 excerpt”。这样处理问题更直接，但也意味着：

- 不要把包含真实敏感数据的扫描结果随意上传
- 公开仓库和 issue 中只应使用测试样本

### 为什么 CSV 不是一条 finding 一行

因为这个工具更偏向“排查和处置同类问题”。同类问题聚合后，更适合大目录初筛。

## 后续方向

- 多行上下文解析，覆盖 JSON/YAML/INI block
- 更细的 provider-specific 规则和测试集
- 更系统的性能基准
- 更清晰的 TUI 扫描面板
- 更严格的 proposal reviewer 和规则 lint
