# dissect.extfs ext4 inline_data 提取诊断

本目录是只读诊断，不修改 `dissect/extfs` 产品代码，也不接入 pytest。

## 复现

```sh
# 用仓库自带 venv（含 dissect.cstruct / dissect.util）
PYTHON=../../.venv/bin/python sh run_all.sh
```

脚本用 `build_image.py` 手工生成 4 个最小 ext4 镜像（1024B 块、256B inode、
单块组、开启 inline_data 特性），再由 `summary.py`（当前实现行为）与
`reference_fix.py`（内核语义参考实现）分别读取。

## 样本布局（参见 Linux fs/ext4/inline.c）

- 字节 [0, min(size,60)) 始终存放在 inode 的 i_block[60]（IFIRST）。
- size > 60 时，超出部分存放在 system.data xattr（e_name_index=7, name="data"），
  位于 inode 内 xattr 区（ibody，cstruct 的 i_extra）或外部 xattr 块。
- 短符号链接（S_IFLNK 且目标 <=60 字节）没有 EXT4_INLINE_DATA_FL，仅靠
  size < 60 走 i_block 内联路径，与 inline_data 是两套触发条件。

载荷为确定性序列 byte(i) = (i % 251) + 1，便于逐字节核对。

| 文件 | i_size | 布局 |
|------|-------:|------|
| fill60 | 60 | 恰好装满 i_block，无 xattr |
| spill61 | 61 | i_block 60B + system.data 1B（跨属性边界） |
| spill100 | 100 | i_block 60B + system.data 40B |
| shortlink | 20 | 短符号链接，无 inline 标志，仅 i_block |
| corrupt | 100 | 同 spill100，按变体施加损坏 |

三种损坏变体（只作用于 corrupt）：
- bad_magic：ibody xattr 魔数改坏。
- bad_value_offs：e_value_offs 指到区域末端，值只能读到 4/40 字节。
- entry_erased：system.data 表项清零（值字节仍残留在 ibody 末端）。

## 诊断中确认的两个独立 cstruct 布局事实（构建器据此适配）

1. ext4_super_block 三个特性字段声明顺序为 compat, incompat, ro_compat，
   与磁盘真实顺序 compat, ro_compat, incompat 不同；cstruct 按声明顺序排布，
   使解析出的 s_feature_incompat 与 s_feature_ro_compat 互换。
2. 本构建下 cstruct 把 i_extra 映射到 inode 偏移 160（不随 i_extra_isize 移动），
   ibody xattr 魔数与表项因此放在该偏移。
