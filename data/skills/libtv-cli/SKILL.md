---
name: libtv-cli
category: asset
description: LibTV official CLI operation guide for managing LibTV canvas projects, nodes, groups, models, assets, and command-line workflows.
---
# LibTV CLI（`libtv`）

`**libtv`** 的文档地图。子命令与选项权威文案以 `**libtv --help**`与`**libtv <子命令> --help\*\*`为准；当文档与`--help` 不一致时，以 CLI 实际输出为准并修订本 skill。

**项目 / 分组范围**：在画布所在工作目录执行 `**libtv project use <项目UUID>`**，写入 `**.libtv/project.json**`的`**projectUuid**`；之后大多数子命令（`libtv node`/`libtv upload`/`libtv group`）在省略 `**-p`/`--project**`时即使用该项目。需要限定到某个普通分组时，再执行`**libtv group use <分组>**`写入`**groupNodeKey\*\*`。详见 [commands/project.md](./commands/project.md)、[commands/group.md](./commands/group.md)。

## 文档地图

| 主题                                                                 | 文件                                                             |
| -------------------------------------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------- |
| 一键安装 / 指定版本安装                                              | [scripts/install.md](./scripts/install.md)（脚本与本文件同目录） |
| 管道（NDJSON）、stdout/stderr、嵌套 case                             | [examples/pipes/README.md](./examples/pipes/README.md)           |
| 常见案例（场景化可复制命令集，**每个 case 一文件**）                 | [examples/README.md](./examples/README.md)                       |
| `libtv login web` / `libtv login phone`                              | [commands/login.md](./commands/login.md)                         |
| `libtv logout`                                                       | [commands/logout.md](./commands/logout.md)                       |
| `libtv project`（含 `create` / `list` / `use` / `unuse` / 默认摘要） | [commands/project.md](./commands/project.md)                     |
| `libtv node`（含 `create` / `list` / `delete` / 默认用法）           | [commands/node.md](./commands/node.md)                           |
| `libtv group`（含 `list` / `create` / `use` / `unuse` / 默认用法）   | [commands/group.md](./commands/group.md)                         |
| `libtv upload`                                                       | [commands/upload.md](./commands/upload.md)                       |
| `libtv image`（`shortcut list` / `shortcut <scene                    | label> -n <node>`）                                              | [commands/image.md](./commands/image.md) |
| `libtv script`（含 `storyboard`：从脚本节点生成分镜图组）            | [commands/script.md](./commands/script.md)                       |
| `libtv model`（含 `search` / 默认完整 schema）                       | [commands/model.md](./commands/model.md)                         |
| 画布节点类型（`-t` 枚举、对应 `-s` / `-u` 字段）                     | [node-types/README.md](./node-types/README.md)                   |
| 模型 schema 字段（`properties` / `config` / `rules` / `modeType`）   | [model-schema/schema.md](./model-schema/schema.md)               |

> 本 skill 内文档的编写规范（谁写什么、禁出现哪些散文）：**[../../.docs/skill-write-convention.md](../../.docs/skill-write-convention.md)**。
