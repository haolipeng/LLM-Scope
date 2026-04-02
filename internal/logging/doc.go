// Package logging 提供全项目统一的 zap 接入与初始化。
//
// # 使用约定（全项目）
//
//  1. 不要在包级变量里写 `var x = logging.Named("pkg")` 或 `NamedZap(...)`：
//     包 init 早于 main 里的 logging.Init，会永远绑在默认（stderr）logger 上，Init 替换全局后也不会更新。
//
//  2. 推荐做法：
//     - 在函数/方法内调用 logging.Named / logging.NamedZap（每次从当前全局 Sugar/Zap 派生，成本低）；
//     - 或在 `New(...)` / 构造函数里把 logger 存进字段（前提是构造发生在 logging.Init 之后，本项目的 runner 均满足）。
//
//  3. 风格选择：
//     - 简单拼接：logging.Named("ssl").Infof(...)
//     - 结构化、热路径：logging.NamedZap("ssl").Info("msg", zap.String("k", v))
//
//  4. 应用日志文件与事件 JSONL（--log-file）不是同一个文件；见 Config 与 deriveAppLogPath。

package logging
