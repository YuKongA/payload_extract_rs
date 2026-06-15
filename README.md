# payload-extract

[English](#english) | [中文](#中文)

---

## English

Android OTA `payload.bin` extractor written in Rust.

### Features

- **Zero-copy extraction** — memory-mapped I/O with direct `pwrite`
- **Parallel processing** — rayon work-stealing thread pool for concurrent decompression
- **Streaming decompression** — operation output is written incrementally, keeping heap memory bounded regardless of partition size
- **HTTP range requests** — extract specific partitions from remote OTA packages without downloading the entire file
- **Rich operation types** — REPLACE, REPLACE_BZ, REPLACE_XZ, REPLACE_ZSTD, BROTLI_BSDIFF, LZ4DIFF_BSDIFF, ZERO, DISCARD, SOURCE_COPY, SOURCE_BSDIFF
- **Multiple input sources** — local `.bin` files, OTA ZIP archives, HTTP/HTTPS URLs
- **Delta OTA support** — incremental updates with `--source-dir`
- **Integrity verification** — per-operation SHA256, partition hash, dm-verity hash tree, FEC

### Installation

Download pre-built binaries from [Releases](../../releases), or build from source:

```bash
cargo build --release
```

The binary will be at `target/release/payload-extract`.

### Usage

#### Extract partitions

```bash
# Extract all partitions
payload-extract extract payload.bin -o output/

# Extract specific partitions
payload-extract extract payload.bin -p boot,init_boot,vbmeta

# Extract from OTA ZIP
payload-extract extract ota.zip -p init_boot

# Extract from HTTP URL (downloads only needed data)
payload-extract extract "https://example.com/ota.zip" -p init_boot

# Exclude specific partitions
payload-extract extract payload.bin -x system,vendor,product

# With SHA256 verification
payload-extract extract payload.bin -p boot --verify

# Control thread count
payload-extract extract payload.bin -j 4

# Delta/incremental OTA
payload-extract extract delta_payload.bin --source-dir old_images/

# Write back dm-verity hash tree and FEC after extraction
payload-extract extract delta_payload.bin --source-dir old_images/ --verify-update

# Only for specific partitions
payload-extract extract delta_payload.bin --source-dir old_images/ --verify-update=system,vendor

# Custom output paths
payload-extract extract payload.bin --out-config paths.txt
```

#### List partitions

```bash
payload-extract list payload.bin
payload-extract list payload.bin --hash       # show SHA256
payload-extract list payload.bin --json       # JSON output
payload-extract list "https://example.com/ota.zip"  # from URL
```

#### Verify extracted images

```bash
payload-extract verify payload.bin -d output/
payload-extract verify payload.bin -d output/ -p boot,init_boot
payload-extract verify payload.bin -d output/ --hash-tree --fec
```

#### Show payload metadata

```bash
payload-extract metadata payload.bin
payload-extract metadata payload.bin --json
```

#### Show OTA package metadata

```bash
payload-extract ota-metadata ota.zip
payload-extract ota-metadata ota.zip --json
payload-extract ota-metadata "https://example.com/ota.zip"
```

#### Global options

```bash
# skip SSL verification
payload-extract -k extract "https://..."

# Override User-Agent
payload-extract -A "CustomAgent/1.0" list "https://..."
```

### Supported platforms

| Platform | Architecture    |
| -------- | --------------- |
| Windows  | x86_64, aarch64 |
| macOS    | x86_64, aarch64 |
| Linux    | x86_64, aarch64 |
| Android  | x86_64, aarch64 |

### License

[GPL-2.0](LICENSE)

---

## 中文

使用 Rust 编写的 Android OTA `payload.bin` 提取工具。

### 功能特性

- **零拷贝提取** — 内存映射 I/O + 直接 `pwrite`
- **并行处理** — rayon work-stealing 线程池，并发解压缩
- **流式解压** — 操作输出增量写盘，堆内存占用不随分区大小增长
- **HTTP 分段下载** — 从远程 OTA 包中提取指定分区，无需下载完整文件
- **丰富的操作类型** — REPLACE、REPLACE_BZ、REPLACE_XZ、REPLACE_ZSTD、BROTLI_BSDIFF、LZ4DIFF_BSDIFF、ZERO、DISCARD、SOURCE_COPY、SOURCE_BSDIFF
- **多输入源** — 本地 `.bin` 文件、OTA ZIP 压缩包、HTTP/HTTPS URL
- **增量 OTA 支持** — 通过 `--source-dir` 指定旧分区目录
- **完整性验证** — 操作级 SHA256、分区哈希、dm-verity 哈希树、FEC 前向纠错

### 安装

从 [Releases](../../releases) 下载预编译二进制，或从源码构建：

```bash
cargo build --release
```

二进制文件位于 `target/release/payload-extract`。

### 使用方法

#### 提取分区

```bash
# 提取所有分区
payload-extract extract payload.bin -o output/

# 提取指定分区
payload-extract extract payload.bin -p boot,init_boot,vbmeta

# 从 OTA ZIP 提取
payload-extract extract ota.zip -p init_boot

# 从 HTTP URL 提取（仅下载所需数据）
payload-extract extract "https://example.com/ota.zip" -p init_boot

# 排除指定分区
payload-extract extract payload.bin -x system,vendor,product

# 启用 SHA256 校验
payload-extract extract payload.bin -p boot --verify

# 控制线程数
payload-extract extract payload.bin -j 4

# 增量 OTA
payload-extract extract delta_payload.bin --source-dir old_images/

# 提取后写回 dm-verity 哈希树和 FEC 数据
payload-extract extract delta_payload.bin --source-dir old_images/ --verify-update

# 仅对指定分区写回
payload-extract extract delta_payload.bin --source-dir old_images/ --verify-update=system,vendor

# 自定义输出路径
payload-extract extract payload.bin --out-config paths.txt
```

#### 列出分区

```bash
payload-extract list payload.bin
payload-extract list payload.bin --hash       # 显示 SHA256
payload-extract list payload.bin --json       # JSON 输出
payload-extract list "https://example.com/ota.zip"  # 从 URL
```

#### 校验已提取的镜像

```bash
payload-extract verify payload.bin -d output/
payload-extract verify payload.bin -d output/ -p boot,init_boot
payload-extract verify payload.bin -d output/ --hash-tree --fec
```

#### 显示 payload 元数据

```bash
payload-extract metadata payload.bin
payload-extract metadata payload.bin --json
```

#### 显示 OTA 包元数据

```bash
payload-extract ota-metadata ota.zip
payload-extract ota-metadata ota.zip --json
payload-extract ota-metadata "https://example.com/ota.zip"
```

#### 全局选项

```bash
# 跳过 SSL 证书验证
payload-extract -k extract "https://..."

# 覆盖 User-Agent
payload-extract -A "CustomAgent/1.0" list "https://..."
```

### 支持平台

| 平台    | 架构            |
| ------- | --------------- |
| Windows | x86_64, aarch64 |
| macOS   | x86_64, aarch64 |
| Linux   | x86_64, aarch64 |
| Android | x86_64, aarch64 |

### 许可证

[GPL-2.0](LICENSE)
