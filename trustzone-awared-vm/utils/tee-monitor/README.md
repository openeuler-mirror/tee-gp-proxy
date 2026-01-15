# TEE Monitor

TEE 服务进程 monitor，用于监控和保活 TEE 相关内核模块和进程。

## 项目说明

### 功能特性

- **环境自动检测**: 自动识别运行环境（Host 或虚拟机）
- **内核模块管理**:
  - Host 环境: 加载并监控 `tzdriver.ko`
  - VM 环境 (5.10内核): 启动时初始化 `virtio_console.ko`（从trustzone路径加载），加载并监控 `vtzfdriver.ko`
  - VM 环境 (4.19内核): 加载并监控 `vtzfdriver.ko`
- **智能进程监控**:
  - Host 环境（有 VM 通信）: 监控 `vtz_proxy` 和 `teecd`
  - Host 环境（无 VM 通信）: 仅监控 `teecd`（通过 `ENABLE_VTZ_PROXY=false` 设置）
  - VM 环境: 仅监控 `teecd`
- **容器场景支持**: 通过 `ENABLE_SDF_UTILS=true` 启用 `sdf-utils` 监控
- **依赖顺序保证**: 确保内核模块 → 核心进程 → sdf-utils 的启动顺序
- **智能依赖检查**: sdf-utils 异常退出时，先检查并恢复依赖，再重启 sdf-utils
- **定时检查**: 默认每30秒检查一次模块和进程状态（可配置）
- **自动保活**: 模块卸载或进程意外退出后自动重新加载/启动
- **可靠的模块加载**: VM 5.10 内核下，每次启动时自动重新初始化 virtio_console（先卸载再加载）
- **开机自启**: 注册为 systemd 服务，支持开机自动启动
- **日志管理**: 使用 journalctl 统一管理日志

---

## 支持的场景

### 环境变量说明

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `CHECK_INTERVAL` | `30` | 检查间隔（秒） |
| `ENABLE_VTZ_PROXY` | `true` | Host 环境下是否监控 vtz_proxy（用于与 VM 通信） |
| `ENABLE_SDF_UTILS` | `false` | 是否监控 sdf-utils（容器场景） |
| `SDF_UTILS_PATH` | `/usr/bin/sdf-utils` | sdf-utils 程序路径 |

### 场景矩阵

#### Host 相关场景

| 场景 | 监控模块 | 监控进程 | 环境变量设置 |
|------|---------|---------|-------------|
| **Host（有 VM 通信）** | tzdriver | vtz_proxy, teecd | 默认，无需设置 |
| **Host（无 VM 通信）** | tzdriver | teecd | `ENABLE_VTZ_PROXY=false` |
| **Host + 容器（有 VM 通信）** | tzdriver | vtz_proxy, teecd, sdf-utils | `ENABLE_SDF_UTILS=true` |
| **Host + 容器（无 VM 通信）** | tzdriver | teecd, sdf-utils | `ENABLE_VTZ_PROXY=false`<br>`ENABLE_SDF_UTILS=true` |

#### VM 相关场景

| 场景 | 监控模块 | 监控进程 | 环境变量设置 |
|------|---------|---------|-------------|
| **VM（5.10 内核）** | virtio_console*, vtzfdriver | teecd | 默认，无需设置 |
| **VM（4.19 内核）** | vtzfdriver | teecd | 默认，无需设置 |
| **VM + 容器（5.10 内核）** | virtio_console*, vtzfdriver | teecd, sdf-utils | `ENABLE_SDF_UTILS=true` |
| **VM + 容器（4.19 内核）** | vtzfdriver | teecd, sdf-utils | `ENABLE_SDF_UTILS=true` |

> *注：virtio_console 仅在启动时初始化（先卸载再从 trustzone 路径加载），不持续监控。

---

## 启动顺序与监控内容

### Host 环境（有 VM 通信）

| 顺序 | 类型 | 组件 | 路径 | 持续监控 |
|------|------|------|------|----------|
| 1 | 内核模块 | tzdriver.ko | `/lib/modules/$(uname -r)/kernel/drivers/trustzone/tzdriver.ko` | ✓ |
| 2 | 进程 | vtz_proxy | `/usr/bin/vtz_proxy` | ✓ |
| 3 | 进程 | teecd | `/usr/bin/teecd` | ✓ |
| 4 | 进程 | sdf-utils | `/usr/bin/sdf-utils` | ✓ (仅当 ENABLE_SDF_UTILS=true) |

### Host 环境（无 VM 通信，ENABLE_VTZ_PROXY=false）

| 顺序 | 类型 | 组件 | 路径 | 持续监控 |
|------|------|------|------|----------|
| 1 | 内核模块 | tzdriver.ko | `/lib/modules/$(uname -r)/kernel/drivers/trustzone/tzdriver.ko` | ✓ |
| 2 | 进程 | teecd | `/usr/bin/teecd` | ✓ |
| 3 | 进程 | sdf-utils | `/usr/bin/sdf-utils` | ✓ (仅当 ENABLE_SDF_UTILS=true) |

### VM 环境 (5.10 内核)

| 顺序 | 类型 | 组件 | 路径 | 持续监控 |
|------|------|------|------|----------|
| 1 | 内核模块 | virtio_console.ko | `/lib/modules/$(uname -r)/kernel/drivers/trustzone/virtio_console.ko` | ✗ (仅启动时初始化) |
| 2 | 内核模块 | vtzfdriver.ko | `/lib/modules/$(uname -r)/kernel/drivers/trustzone/vtzfdriver.ko` | ✓ |
| 3 | 进程 | teecd | `/usr/bin/teecd` | ✓ |
| 4 | 进程 | sdf-utils | `/usr/bin/sdf-utils` | ✓ (仅当 ENABLE_SDF_UTILS=true) |

### VM 环境 (4.19 内核)

| 顺序 | 类型 | 组件 | 路径 | 持续监控 |
|------|------|------|------|----------|
| 1 | 内核模块 | vtzfdriver.ko | `/lib/modules/$(uname -r)/kernel/drivers/trustzone/vtzfdriver.ko` | ✓ |
| 2 | 进程 | teecd | `/usr/bin/teecd` | ✓ |
| 3 | 进程 | sdf-utils | `/usr/bin/sdf-utils` | ✓ (仅当 ENABLE_SDF_UTILS=true) |

---

## 文件结构

```
tee-monitor/
├── README.md                # 项目说明文档
├── build.sh                 # RPM 自动构建脚本
├── tee-monitor.sh          # monitor 脚本
├── tee-monitor.service     # systemd 服务文件
└── tee-monitor.spec        # RPM 打包规范文件
```

---

## 快速开始

### 前置条件

确保系统已安装 RPM 构建工具：

```bash
# openEuler/CentOS/RHEL
sudo yum install -y rpm-build rpmdevtools

# 或者使用 dnf
sudo dnf install -y rpm-build rpmdevtools
```

### 一键构建安装

```bash
# 进入项目目录
cd tee-monitor

# 构建并安装
./build.sh -i
```

---

## 构建脚本使用

### 命令格式

```bash
./build.sh [选项]
```

### 可用选项

| 选项 | 说明 |
|------|------|
| `-c, --clean` | 清理构建环境 |
| `-i, --install` | 构建成功后自动安装 RPM 包 |
| `-h, --help` | 显示帮助信息 |

### 使用示例

```bash
# 仅构建 RPM 包
./build.sh

# 构建并自动安装
./build.sh -i

# 清理构建环境
./build.sh -c

# 清理后重新构建并安装
./build.sh -c -i
```

### 构建产物

构建成功后，RPM 包位于：
- 二进制包: `~/rpmbuild/RPMS/noarch/tee-monitor-1.2.0-1.*.noarch.rpm`
- 源码包: `~/rpmbuild/SRPMS/tee-monitor-1.2.0-1.*.src.rpm`

---

## 安装与使用

### 安装 RPM 包

```bash
# 新安装
sudo rpm -ivh ~/rpmbuild/RPMS/noarch/tee-monitor-1.2.0-*.noarch.rpm

# 升级安装
sudo rpm -Uvh ~/rpmbuild/RPMS/noarch/tee-monitor-1.2.0-*.noarch.rpm

# 或者使用 yum/dnf 安装（可自动处理依赖）
sudo yum localinstall ~/rpmbuild/RPMS/noarch/tee-monitor-1.2.0-*.noarch.rpm
```

### 服务管理

安装后，服务会自动启用并启动。也可以手动管理服务：

```bash
# 查看服务状态
sudo systemctl status tee-monitor

# 启动/停止/重启服务
sudo systemctl start tee-monitor
sudo systemctl stop tee-monitor
sudo systemctl restart tee-monitor

# 启用/禁用开机自启
sudo systemctl enable tee-monitor
sudo systemctl disable tee-monitor
```

### 日志查看

```bash
# 实时跟踪日志
sudo journalctl -u tee-monitor -f

# 查看最近 50 行日志
sudo journalctl -u tee-monitor -n 50

# 查看今天的日志
sudo journalctl -u tee-monitor --since today

# 按优先级过滤（错误和警告）
sudo journalctl -u tee-monitor -p err
```

---

## 场景配置指南

### 配置方式

推荐使用 `systemctl edit` 命令创建 override 配置：

```bash
sudo systemctl edit tee-monitor
```

在打开的编辑器中添加所需配置，保存后执行：

```bash
sudo systemctl daemon-reload
sudo systemctl restart tee-monitor
```

> **重要提示**：使用 `systemctl edit` 时，编辑器会显示原始 service 文件内容作为参考（以 `#` 注释）。请注意以下内容：
> ```
> ### Lines below this comment will be discarded
> ```
> 这行下面的所有内容都会被丢弃。**你的配置必须添加在这行之前（文件顶部）**，而不是在下面的注释中修改。
>
> 正确示例：
> ```ini
> [Service]
> Environment=ENABLE_SDF_UTILS=true
>
> ### Lines below this comment will be discarded
> ### /usr/lib/systemd/system/tee-monitor.service
> # ...（以下内容会被丢弃，无需修改）
> ```

### 场景 1：Host（有 VM 通信）— 默认配置

无需额外配置，安装后直接使用。

**验证：**
```bash
sudo journalctl -u tee-monitor -n 20
# 应看到：
# [INFO] Detected environment: Host
# [INFO] VTZ Proxy enabled (for VM communication)
# [INFO] Monitored processes: /usr/bin/vtz_proxy /usr/bin/teecd
```

### 场景 2：Host（无 VM 通信）

```bash
sudo systemctl edit tee-monitor
```

添加：
```ini
[Service]
Environment=ENABLE_VTZ_PROXY=false
```

**验证：**
```bash
sudo journalctl -u tee-monitor -n 20
# 应看到：
# [INFO] VTZ Proxy disabled (Host-only mode, no VM communication)
# [INFO] Monitored processes: /usr/bin/teecd
```

### 场景 3：Host + 容器（有 VM 通信）

**前提**：确保 `/usr/bin/sdf-utils` 已存在。

```bash
sudo systemctl edit tee-monitor
```

添加：
```ini
[Service]
Environment=ENABLE_SDF_UTILS=true
```

**验证：**
```bash
sudo journalctl -u tee-monitor -n 20
# 应看到：
# [INFO] SDF Utils monitoring enabled: /usr/bin/sdf-utils
# [INFO] SDF Utils depends on: modules [tzdriver] and processes [/usr/bin/vtz_proxy /usr/bin/teecd]
```

### 场景 4：Host + 容器（无 VM 通信）

**前提**：确保 `/usr/bin/sdf-utils` 已存在。

```bash
sudo systemctl edit tee-monitor
```

添加：
```ini
[Service]
Environment=ENABLE_VTZ_PROXY=false
Environment=ENABLE_SDF_UTILS=true
```

### 场景 5/6：VM（无容器）— 默认配置

无需额外配置，脚本自动检测 VM 环境。

**验证：**
```bash
sudo journalctl -u tee-monitor -n 20
# 应看到：
# [INFO] Detected environment: Virtual Machine
# [INFO] Monitored modules: vtzfdriver
# [INFO] Monitored processes: /usr/bin/teecd
```

### 场景 7/8：VM + 容器

**前提**：确保 `/usr/bin/sdf-utils` 已存在。

```bash
sudo systemctl edit tee-monitor
```

添加：
```ini
[Service]
Environment=ENABLE_SDF_UTILS=true
```

### 恢复默认配置

```bash
# 删除 override 配置文件
sudo rm -rf /etc/systemd/system/tee-monitor.service.d/

# 重新加载并重启
sudo systemctl daemon-reload
sudo systemctl restart tee-monitor
```

### 查看当前配置

```bash
# 查看 override 配置
cat /etc/systemd/system/tee-monitor.service.d/override.conf

# 查看完整的服务配置
systemctl cat tee-monitor
```

---

## 高级配置

### 修改检查间隔

```bash
sudo systemctl edit tee-monitor
```

添加（例如改为 60 秒）：
```ini
[Service]
Environment=CHECK_INTERVAL=60
```

### 自定义 sdf-utils 路径

```bash
sudo systemctl edit tee-monitor
```

添加：
```ini
[Service]
Environment=ENABLE_SDF_UTILS=true
Environment=SDF_UTILS_PATH=/opt/custom/sdf-utils
```

### 组合配置示例

多个环境变量可以组合使用：

```ini
[Service]
Environment=CHECK_INTERVAL=60
Environment=ENABLE_VTZ_PROXY=false
Environment=ENABLE_SDF_UTILS=true
Environment=SDF_UTILS_PATH=/usr/bin/sdf-utils
```

---

## 卸载

```bash
# 卸载 RPM 包（会自动停止并禁用服务）
sudo rpm -e tee-monitor

# 或使用 yum/dnf
sudo yum remove tee-monitor
```

---

## 故障排查

### 服务无法启动

```bash
# 检查服务状态
sudo systemctl status tee-monitor

# 查看详细日志
sudo journalctl -u tee-monitor -n 50

# 手动测试脚本
sudo /usr/libexec/tee-monitor.sh
```

### 内核模块无法加载

```bash
# 确认模块文件存在
ls -la /lib/modules/$(uname -r)/kernel/drivers/trustzone/

# 检查模块是否已加载
lsmod | grep -E "tzdriver|vtzfdriver|virtio_console"

# 查看 dmesg 获取详细错误
dmesg | tail -50
```

### 进程无法启动

```bash
# 确认内核模块已正确加载
lsmod | grep -E "tzdriver|vtzfdriver"

# 确认程序存在且可执行
ls -la /usr/bin/vtz_proxy /usr/bin/teecd /usr/bin/sdf-utils

# 检查日志中的错误信息
sudo journalctl -u tee-monitor -p err
```

### sdf-utils 无法启动

```bash
# 确认 sdf-utils 存在
ls -la /usr/bin/sdf-utils

# 确认环境变量已设置
systemctl cat tee-monitor | grep SDF_UTILS

# 检查依赖是否就绪
sudo journalctl -u tee-monitor | grep -E "dependencies|sdf-utils"
```

### 环境检测问题

```bash
# 手动检测当前环境
systemd-detect-virt
# 返回 "none" 表示 Host 环境
# 返回其他值（如 kvm、vmware 等）表示 VM 环境

# 查看日志确认检测结果
sudo journalctl -u tee-monitor | grep "Detected environment"
```

---

## 注意事项

1. **sdf-utils 依赖**：sdf-utils 依赖于所有模块和进程正常运行。如果 sdf-utils 异常退出，脚本会先检查并恢复所有依赖，再重启 sdf-utils。

2. **virtio_console 初始化**：VM 5.10 内核场景下，每次服务启动时都会先卸载 virtio_console（如果已加载），然后从 trustzone 路径重新加载，确保模块状态一致。

3. **环境自动检测**：脚本会自动检测运行环境（Host/VM），无需手动指定。

4. **配置生效**：修改环境变量后，必须执行 `systemctl daemon-reload` 和 `systemctl restart tee-monitor` 才能生效。

5. **ENABLE_VTZ_PROXY 仅影响 Host**：该变量在 VM 环境下会被忽略。

---

## 版本历史

### v1.2.0
- 新增 `ENABLE_VTZ_PROXY` 环境变量，支持 Host-only 模式（无 VM 通信）
- 新增容器场景支持，通过 `ENABLE_SDF_UTILS` 启用 sdf-utils 监控
- 新增 `SDF_UTILS_PATH` 环境变量，支持自定义 sdf-utils 路径
- sdf-utils 监控包含依赖检查（模块和进程必须先就绪）
- 简化 virtio_console 初始化，每次启动时先卸载再从 trustzone 路径加载

### v1.1.0
- 新增内核模块管理功能
- Host 环境: 自动加载和监控 tzdriver.ko
- VM 环境: 自动加载和监控 vtzfdriver.ko
- VM 环境 (5.10内核): 启动时自动初始化 virtio_console.ko
- 确保内核模块在进程启动前加载完成
- 新增 kmod 依赖

### v1.0.0
- 初始版本
- 支持 Host/VM 环境自动检测
- Host 环境监控 vtz_proxy 和 teecd 进程
- VM 环境仅监控 teecd 进程
- systemd 服务集成
- 可配置的检查间隔
- journalctl 日志集成
- 提供自动化构建脚本
