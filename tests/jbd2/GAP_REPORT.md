# JBD2 离线兼容性缺口报告

本报告记录围绕 `dissect/extfs/journal.py` 现有日志读取器建立的离线兼容性测试
（`tests/jbd2/`）所发现的差距。所有样本均由 `tests/jbd2/journal_builder.py` 以明确字节
布局手工构造，预期 fs 块号、journal 块位置、payload、UUID 编排与校验值独立于待测代码生成，
因此读取器无法通过反算“自证正确”。

运行方式（离线）：

```sh
TZ=UTC .venv/bin/python -m pytest -o addopts= tests/jbd2 -v
```

缺口测试以严格 `xfail` 形式存在：当前保持绿色，一旦读取器后续实现了拒绝或正确解析，
对应测试会以 `XPASS` 失败，提醒移除标记并转为常规断言。pytest 终端摘要按两类分别列出。

## 分类口径

- `parse_misalignment`（解析错位）：读取器接受输入、不报错，但把 tag/数据块映射到错误位置，
  取证结论可能指向错误的数据块。这是风险最高的一类，因为它静默产生错误结果。
- `unsupported_format`（不支持格式）：磁盘布局本身合法，但读取器未实现该布局或未做校验。
  表现为静默忽略校验、或用更宽的结构体误读，同样可能造成错位（具体见各项说明）。

## 已正确覆盖（常规通过断言，非 xfail）

- 64 位块号：`t_blocknr_high << 32 | t_blocknr` 组合，覆盖跨 32 位边界的块号，v2 与 v3 均验证。
- 共享 UUID：`JBD2_FLAG_SAME_UUID` 标签省略 16 字节 UUID，显式/省略交替时块号与 payload 仍对齐。
- checksum v2（12 字节 `journal_block_tag`，截断 16 位校验）与 v3（16 字节 `journal_block_tag3`，
  32 位校验）两种标签布局的选择与基础解析。
- 同一事务的多个 descriptor block 正确归并到同一个 commit。
- `commits()` 对非连续 sequence 间隙的过滤；commit 时间戳解码。
- 拒绝边界：超级块 magic 不匹配抛 `Error`；镜像在标签中途截断时遍历抛 `EOFError`（不会产出伪造块）。

## 缺口 1：缺失 LAST_TAG 结束标志 — parse_misalignment

- 测试：`test_missing_last_tag_flag_must_be_rejected`
- 现象：`DescriptorBlock.tags()` 的循环只以 `JBD2_FLAG_LAST_TAG` 为终止条件，且没有任何
  边界检查。当描述块尾部的标签缺少 LAST_TAG（损坏/被篡改）时，读取器把后续零字节当作更多
  标签持续解析，直到流末尾抛 `EOFError`，期间产出若干 `block=0` 的伪造 `DescriptorBlockTag`。
- 取证影响：调用方若未遍历到抛异常即取用早期标签，可能把块号 0 等伪造映射当作真实数据块。
- 复现：清除唯一标签 flags 中的 LAST_TAG 位，并在镜像后补零块使 EOF 路径确定可复现。
- 期望：应在标签超出描述块边界或缺少 LAST_TAG 时显式拒绝（抛 `Error`），而非静默产出伪造标签。

## 缺口 2：JBD2_FLAG_ESCAPE 转义块未跳过 — parse_misalignment

- 测试：`test_escaped_block_must_point_at_real_payload`
- 现象：当数据块首 4 字节与 journal magic 冲突时，内核在其前面插入一个 `JBD2_ESCAPE_HDR`
  （值 9）块，并在标签置 `JBD2_FLAG_ESCAPE`。读取器完全不检查该标志，`block_count` 不预留
  转义头块，于是 `open()` 指向转义头（读到 `c03b3998...`）而非真实 payload；其后同一描述块
  的每个标签 journal 块位置整体后移一块。
- 取证影响：这是直接的“指向错误数据块”——转义标签及其后续标签全部错位且不报错。
- 复现：构造一个 `escaped=True` 标签（转义头块 + 真实数据块）后接一个普通标签，断言读取器
  返回的 payload 与预期字节不符。
- 期望：遇到 `JBD2_FLAG_ESCAPE` 时为转义头额外消耗一个 journal 块，使 `open()` 指向真实数据。

## 缺口 3：标签校验字段从不验证（v3 与 v2）— unsupported_format

- 测试：`test_corrupt_v3_tag_checksum_must_be_rejected`、
  `test_corrupt_v2_tag_checksum_must_be_rejected`
- 现象：读取器从不计算/比对 `t_checksum`。v3 的 32 位 `crc32c(uuid + seq_be32 + data_block)`
  与 v2 的截断 16 位 `crc32c(uuid + descriptor_header + data_block)` 即使被篡改，标签仍被照常
  接受并映射。
- 取证影响：被篡改的日志无法被识别，损坏的块号/payload 会被当作可信证据。
- 复现：构造 `corrupt_checksum=True` 的标签（对正确 CRC 异或固定掩码），读取器无任何异常。
- 期望：在校验特性启用时校验标签校验值，不匹配则拒绝该标签/事务。
- 备注：`commit_header.h_chksum` 事务级校验同样未验证，属同一类未实现，本套件以标签级为主，
  事务级可在实现该特性时一并补齐。

## 缺口 4：legacy 无校验标签布局（10 字节 / 6 字节）— unsupported_format

- 测试：`test_legacy_non_checksum_tags_must_resolve`（`legacy64` 与 `legacy32` 两组参数）
- 现象：读取器仅根据是否有 CSUM_V3 在 12 字节与 16 字节两种标签间二选一，未考虑
  无 checksum 特性的 legacy 布局：64BIT 但无校验时为 10 字节
  （`blocknr(4) + flags(2) + blocknr_high(4)`），无 64BIT 无校验时为 6 字节
  （`blocknr(4) + flags(2)`）。用更宽的结构体会把 UUID 字节或下一标签误读成块号。
- 取证影响：对老格式日志直接产生错误块号（错位），且无任何提示。
- 复现：以 `JBD2_FEATURE_INCOMPAT_64BIT`（无 CSUM）构造 10 字节标签、无特性构造 6 字节标签，
  读取器解析出的块号与构造侧明确写入的块号不符。
- 期望：依据 `s_feature_incompat` 中 CSUM_V2/CSUM_V3/64BIT 的组合选择 6/10/12/16 字节标签布局。

## 建议优先级

1. 缺口 2（ESCAPE 错位）与缺口 1（LAST_TAG 越界）属静默错位，取证风险最高，应优先让读取器
   fail-closed 或正确计块。
2. 缺口 3（校验验证）决定能否识别被篡改日志，是取证可信度的关键。
3. 缺口 4（legacy 布局）影响面取决于样本是否来自无校验特性的老旧文件系统。
