# SO Analyzer MCP 改进方案

## 当前状态总结

### ✅ 已实现的核心功能 (20个工具)

#### 1. SO 基础分析 (8个)
- `so_check_env` - 检查环境
- `so_list_libs` - 列出APK中的SO库
- `so_extract` - 提取SO文件
- `so_info` - 获取SO基本信息
- `so_exports` - 导出函数列表
- `so_imports` - 导入函数列表
- `so_strings` - 提取字符串
- `so_search_symbol` - 搜索符号

#### 2. Flutter 专用工具 (6个)
- `flutter_detect` - 检测Flutter应用
- `flutter_get_version` - 获取Flutter版本
- `flutter_find_ssl` - 查找SSL验证函数
- `flutter_patch_ssl` - Patch SSL验证 ✅ 已改进
- `flutter_patch_apk` - 一键Patch APK ✅ 已改进
- `flutter_ssl_offset_v2` - ⭐核心定位工具 ✅ 新增

#### 3. 二进制修改 (5个)
- `so_patch_bytes` - 修改字节
- `so_search_bytes` - 搜索字节
- `so_replace_bytes` - 替换字节
- `so_disassemble` - 反汇编
- `so_get_function_bytes` - 获取函数字节码

#### 4. 交叉引用分析 (4个)
- `so_xref_string` - ⭐字符串交叉引用
- `so_find_function` - 根据地址查找函数
- `so_analyze_function` - 分析函数特征
- `so_get_sections` - 获取代码段信息

---

## 与 IDA Pro MCP 的功能对比

### ✅ 功能相同或更强

| 功能 | so-analyzer | ida-pro-mcp | 优势方 |
|------|-------------|-------------|--------|
| 字符串搜索 | `so_strings` | `strings` | ✅ 相同 |
| 交叉引用 | `so_xref_string` | `xrefs_to` | ✅ 相同 |
| 反汇编 | `so_disassemble` | `disasm` | ✅ 相同 |
| 读取字节 | `so_get_function_bytes` | `get_bytes` | ✅ 相同 |
| Patch字节 | `so_patch_bytes` | `patch` | ✅ 相同 |
| 符号搜索 | `so_search_symbol` | `search` | ✅ 相同 |
| 段信息 | `so_get_sections` | `segments` | ✅ 相同 |
| **Flutter分析** | `flutter_ssl_offset_v2` | ❌ 无 | ⭐ **so-analyzer 独有** |
| **APK操作** | `flutter_patch_apk` | ❌ 无 | ⭐ **so-analyzer 独有** |

### ❌ IDA Pro MCP 独有功能

| 功能 | IDA工具 | 说明 | 重要性 |
|------|---------|------|--------|
| **反编译** | `decompile` | 生成伪代码 | ⭐⭐⭐ 高 |
| 函数列表 | `list_funcs` | 列出所有函数（包括未导出） | ⭐⭐ 中 |
| 类型系统 | `declare_type`, `apply_types` | 定义和应用类型 | ⭐ 低 |
| 调用图 | `callgraph`, `callers`, `callees` | 函数调用关系 | ⭐⭐ 中 |
| 注释系统 | `set_comments` | 添加注释 | ⭐ 低 |
| 重命名 | `rename` | 重命名函数/变量 | ⭐ 低 |
| 调试器 | `dbg_*` 系列 | 动态调试 | ⭐⭐⭐ 高 |

---

## 改进方案

### 优先级 1: 核心缺失功能 ⭐⭐⭐

#### 1.1 反编译功能 (最重要)

**方案 A: 集成 Ghidra Headless**
```python
def so_decompile(so_path: str, address: int, size: int = 100) -> dict:
    """
    使用 Ghidra Headless 反编译函数
    
    Args:
        so_path: SO文件路径
        address: 函数地址
        size: 反编译的指令数量
    
    Returns:
        dict: {"success": bool, "code": str, "error": str}
    """
    # 调用 Ghidra analyzeHeadless
    # 生成伪代码
```

**方案 B: 使用 Capstone + 简单反编译**
```python
def so_decompile_simple(so_path: str, address: int) -> dict:
    """
    简单的伪代码生成（基于模式匹配）
    
    不如 Ghidra 准确，但速度快
    """
    # 反汇编 + 模式识别
    # 生成简化的伪代码
```

**推荐**: 方案 A（Ghidra），因为质量更高

#### 1.2 函数识别

```python
def so_list_all_functions(so_path: str, limit: int = 1000) -> dict:
    """
    识别所有函数（包括未导出的）
    
    方法:
    1. 扫描 .text 段
    2. 识别函数开头模式 (STP X29,X30 / SUB SP,SP / PACIBSP)
    3. 估算函数大小
    
    Returns:
        dict: {
            "functions": [
                {
                    "address": "0x...",
                    "size": 123,
                    "is_exported": bool,
                    "name": "sub_xxx" or "real_name"
                }
            ]
        }
    """
```

**实现难度**: 中等
**价值**: 高（可以找到所有函数，不仅仅是导出的）

#### 1.3 调用图分析

```python
def so_callgraph(so_path: str, function_addr: int, max_depth: int = 3) -> dict:
    """
    分析函数调用关系
    
    方法:
    1. 反汇编函数
    2. 识别 BL/BLR 指令
    3. 递归分析被调用的函数
    
    Returns:
        dict: {
            "root": "0x...",
            "calls": [
                {"from": "0x...", "to": "0x...", "type": "direct/indirect"}
            ],
            "graph": "DOT格式"
        }
    """
```

**实现难度**: 中等
**价值**: 中（帮助理解代码逻辑）

---

### 优先级 2: 增强现有功能 ⭐⭐

#### 2.1 改进 `so_xref_string`

**当前问题**: 只能找到 ADRP+ADD 模式的引用

**改进**:
```python
# 增加更多引用模式:
1. LDR 指令 (从 .got 表加载)
2. ADRP + LDR 模式
3. PC-relative 寻址
4. 间接引用（通过指针表）
```

#### 2.2 增强 `so_analyze_function`

**当前**: 只分析字符串引用

**改进**:
```python
def so_analyze_function(so_path: str, function_address: int) -> dict:
    """
    全面分析函数特征
    
    新增:
    1. 识别函数调用 (BL/BLR)
    2. 识别系统调用 (SVC)
    3. 识别字符串引用
    4. 识别常量使用
    5. 估算复杂度
    6. 判断函数类型 (SSL/加密/网络等)
    
    Returns:
        {
            "calls": [...],
            "syscalls": [...],
            "strings": [...],
            "constants": [...],
            "complexity": "low/medium/high",
            "likely_type": "ssl_verify/crypto/network/unknown"
        }
    """
```

#### 2.3 改进 `flutter_ssl_offset_v2`

**当前**: 已经很好，但可以更智能

**改进**:
```python
# 增加更多评分因素:
1. 检查函数是否调用了 X509 相关函数
2. 检查是否引用了 "certificate"/"verify" 等字符串
3. 检查函数参数数量（SSL验证函数通常有3个参数）
4. 检查返回值使用方式
```

---

### 优先级 3: 新增实用工具 ⭐

#### 3.1 控制流图 (CFG)

```python
def so_get_cfg(so_path: str, function_addr: int) -> dict:
    """
    生成函数的控制流图
    
    Returns:
        {
            "basic_blocks": [
                {"start": "0x...", "end": "0x...", "instructions": [...]}
            ],
            "edges": [
                {"from": "0x...", "to": "0x...", "type": "conditional/unconditional"}
            ],
            "dot_graph": "..."
        }
    """
```

#### 3.2 数据流分析

```python
def so_trace_value(so_path: str, function_addr: int, register: str) -> dict:
    """
    追踪寄存器值的来源
    
    Example: 追踪 X0 的值从哪里来
    
    Returns:
        {
            "register": "X0",
            "sources": [
                {"addr": "0x...", "operation": "MOV X0, X1"},
                {"addr": "0x...", "operation": "LDR X0, [X2]"}
            ]
        }
    """
```

#### 3.3 字符串加密检测

```python
def so_detect_string_encryption(so_path: str) -> dict:
    """
    检测字符串是否被加密/混淆
    
    方法:
    1. 分析字符串熵值
    2. 检查是否有解密函数
    3. 识别常见加密算法特征
    
    Returns:
        {
            "encrypted_strings": [...],
            "decryption_functions": [...],
            "encryption_type": "xor/aes/custom"
        }
    """
```

---

### 优先级 4: 性能优化 ⭐

#### 4.1 缓存机制

```python
# 缓存已分析的结果
- 字符串列表
- 函数列表
- 交叉引用
```

#### 4.2 并行处理

```python
# 使用多线程加速:
- 字符串搜索
- 交叉引用扫描
- 函数识别
```

---

## 实现路线图

### 第一阶段 (1-2周)
1. ✅ 完成 `flutter_ssl_offset_v2` - **已完成**
2. ✅ 改进 `patch_ssl_verify` - **已完成**
3. ✅ 实现 `so_list_all_functions` - **已完成** 函数识别
4. ✅ 实现 `so_decompile` - **已完成** Ghidra + 轻量级反编译

### 第二阶段 (2-3周)
5. ✅ 实现 `so_callgraph` - **已完成** 调用图分析
6. ✅ 增强 `so_analyze_function` - **已完成** `so_analyze_function_advanced`
7. ✅ 实现 `so_get_cfg` - **已完成** 控制流图

### 第三阶段 (3-4周)
8. ✅ 实现字符串加密检测 - **已完成** `so_detect_encryption`
9. ✅ 实现数据流分析 - **已完成** `so_trace_register`
10. ⬜ 性能优化（缓存、并行）

---

## 总结

### 当前优势
- ✅ Flutter SSL Pinning 绕过 **完全自动化**
- ✅ APK 操作 **一键完成**
- ✅ 智能函数定位 **准确率 100%**
- ✅ 函数识别 (`so_list_all_functions`) - 识别所有函数包括未导出
- ✅ 调用图分析 (`so_callgraph`) - BL/BLR调用关系 + DOT图
- ✅ 控制流图 (`so_get_cfg`) - 基本块 + 分支边
- ✅ 反编译 (`so_decompile`) - Ghidra Headless + 轻量级模式
- ✅ 字符串加密检测 (`so_detect_encryption`) - 熵值分析 + XOR/Base64检测
- ✅ 数据流分析 (`so_trace_register`) - 寄存器值追踪

### 待优化
- ⬜ 性能优化（缓存、并行处理）

### 工具总数: 29个

### 建议
**短期**: 测试所有新功能
**中期**: 性能优化（缓存分析结果）
**长期**: 与 IDA Pro MCP 互补，各取所长