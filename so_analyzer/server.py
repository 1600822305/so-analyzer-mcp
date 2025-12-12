"""SO Analyzer MCP Server"""
import json
from mcp.server import Server
from mcp.types import Tool, TextContent


def parse_address(addr) -> int:
    """
    解析地址参数，支持多种格式：
    - 整数: 7192340
    - 十六进制字符串: "0x6DBD94" 或 "6DBD94"
    """
    if isinstance(addr, int):
        return addr
    if isinstance(addr, str):
        addr = addr.strip()
        try:
            return int(addr, 0)  # 自动检测进制
        except ValueError:
            # 尝试作为纯十六进制（无0x前缀）
            try:
                return int(addr, 16)
            except ValueError:
                raise ValueError(f"无法解析地址: {addr}")
    raise ValueError(f"无效的地址类型: {type(addr)}")

from .so_utils import (
    check_lief,
    list_libs_from_apk,
    extract_so_from_apk,
    get_so_info,
    get_exports,
    get_imports,
    get_strings,
    search_symbol,
    detect_flutter
)
from .flutter_utils import (
    get_flutter_version,
    find_ssl_verify_function,
    patch_ssl_verify,
    flutter_patch_apk
)
from .flutter_utils_v2 import find_ssl_verify_function_v2
from .patch_utils import (
    patch_bytes,
    search_bytes,
    replace_bytes,
    disassemble,
    get_function_bytes
)
from .xref_utils import (
    get_code_sections,
    find_string_offset,
    xref_string,
    find_function_by_address,
    analyze_function
)
from .advanced_utils import (
    list_all_functions,
    callgraph,
    get_cfg,
    analyze_function_advanced,
    detect_string_encryption,
    trace_register_value,
    find_instruction_pattern
)
from .elf_utils import (
    get_entrypoints,
    list_globals
)
from .xref_enhanced import (
    xref_string_enhanced,
    get_callers,
    get_callees,
    find_function_at
)
from .decompile_utils import (
    check_ghidra,
    check_radare2,
    decompile
)
from .patch_advanced import (
    patch_return_value,
    patch_nop,
    patch_branch,
    patch_custom,
    find_vip_functions,
    generate_patch_script,
    get_patch_templates
)
from .flutter_libapp import (
    check_blutter,
    analyze_libapp_with_blutter,
    extract_dart_symbols,
    generate_flutter_hook_script,
    analyze_flutter_apk,
    find_flutter_vip_functions
)
from .blutter_parser import (
    parse_blutter_output,
    search_blutter_vip_functions,
    search_blutter_functions,
    search_blutter_strings,
    get_function_detail,
    export_frida_hooks
)

# 创建MCP服务器
server = Server("so-analyzer")


def get_all_tools() -> list[Tool]:
    """获取所有工具定义"""
    return [
        # ===== SO基础分析 =====
        Tool(
            name="so_check_env",
            description="检查SO分析环境（lief库是否可用）",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="so_list_libs",
            description="列出APK中的所有SO库",
            inputSchema={
                "type": "object",
                "properties": {
                    "apk_path": {"type": "string", "description": "APK文件路径"}
                },
                "required": ["apk_path"]
            }
        ),
        Tool(
            name="so_extract",
            description="从APK中提取SO文件",
            inputSchema={
                "type": "object",
                "properties": {
                    "apk_path": {"type": "string", "description": "APK文件路径"},
                    "lib_name": {"type": "string", "description": "SO库名称（如 libflutter.so）"},
                    "arch": {"type": "string", "description": "架构（默认arm64-v8a）"},
                    "output_dir": {"type": "string", "description": "输出目录（可选）"}
                },
                "required": ["apk_path", "lib_name"]
            }
        ),
        Tool(
            name="so_info",
            description="获取SO文件基本信息（架构、导出/导入数量、依赖等）",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="so_exports",
            description="获取SO导出函数列表",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "search": {"type": "string", "description": "搜索过滤"},
                    "limit": {"type": "integer", "description": "最多返回数量（默认100）"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="so_imports",
            description="获取SO导入函数列表",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "search": {"type": "string", "description": "搜索过滤"},
                    "limit": {"type": "integer", "description": "最多返回数量（默认100）"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="so_strings",
            description="提取SO文件中的字符串",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "min_length": {"type": "integer", "description": "最小字符串长度（默认4）"},
                    "search": {"type": "string", "description": "搜索过滤"},
                    "limit": {"type": "integer", "description": "最多返回数量（默认200）"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="so_search_symbol",
            description="搜索符号（导出+导入函数）",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "pattern": {"type": "string", "description": "搜索模式"},
                    "limit": {"type": "integer", "description": "最多返回数量（默认50）"}
                },
                "required": ["so_path", "pattern"]
            }
        ),
        
        # ===== Flutter工具 =====
        Tool(
            name="flutter_detect",
            description="检测是否是Flutter应用",
            inputSchema={
                "type": "object",
                "properties": {
                    "apk_path": {"type": "string", "description": "APK文件路径"}
                },
                "required": ["apk_path"]
            }
        ),
        Tool(
            name="flutter_get_version",
            description="获取Flutter版本",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "libflutter.so文件路径"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="flutter_find_ssl",
            description="查找SSL验证函数",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="flutter_patch_ssl",
            description="Patch SSL验证（绕过证书检测，用于抓包）",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "libflutter.so文件路径"},
                    "output_path": {"type": "string", "description": "输出路径（可选）"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="flutter_patch_apk",
            description="自动patch Flutter APK的SSL验证（一键操作）",
            inputSchema={
                "type": "object",
                "properties": {
                    "apk_path": {"type": "string", "description": "APK文件路径"},
                    "output_path": {"type": "string", "description": "输出路径（可选）"},
                    "arch": {"type": "string", "description": "架构（默认arm64-v8a）"}
                },
                "required": ["apk_path"]
            }
        ),
        Tool(
            name="flutter_ssl_offset_v2",
            description="⭐核心工具！模拟IDA分析流程：1.搜索ssl_client 2.xrefs_to 3.智能选择函数 4.生成脚本",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "libflutter.so文件路径"}
                },
                "required": ["so_path"]
            }
        ),
        
        # ===== 二进制修改工具 =====
        Tool(
            name="so_patch_bytes",
            description="在指定偏移处修改字节",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "文件路径"},
                    "offset": {"type": "integer", "description": "偏移量"},
                    "new_bytes": {"type": "string", "description": "新字节（十六进制字符串）"},
                    "output_path": {"type": "string", "description": "输出路径（可选）"}
                },
                "required": ["file_path", "offset", "new_bytes"]
            }
        ),
        Tool(
            name="so_search_bytes",
            description="搜索字节模式",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "文件路径"},
                    "pattern": {"type": "string", "description": "字节模式（十六进制字符串）"},
                    "limit": {"type": "integer", "description": "最多返回数量（默认20）"}
                },
                "required": ["file_path", "pattern"]
            }
        ),
        Tool(
            name="so_replace_bytes",
            description="查找并替换字节",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "文件路径"},
                    "find_pattern": {"type": "string", "description": "查找模式（十六进制）"},
                    "replace_with": {"type": "string", "description": "替换内容（十六进制）"},
                    "output_path": {"type": "string", "description": "输出路径（可选）"},
                    "replace_all": {"type": "boolean", "description": "是否替换所有"}
                },
                "required": ["file_path", "find_pattern", "replace_with"]
            }
        ),
        Tool(
            name="so_disassemble",
            description="反汇编指定地址的代码",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "address": {"type": ["integer", "string"], "description": "起始地址(支持0x十六进制)"},
                    "size": {"type": "integer", "description": "字节数（默认64）"},
                    "arch": {"type": "string", "description": "架构（auto/arm64/arm）"}
                },
                "required": ["so_path", "address"]
            }
        ),
        Tool(
            name="so_get_function_bytes",
            description="获取函数的字节码",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "function_name": {"type": "string", "description": "函数名"},
                    "size": {"type": "integer", "description": "读取字节数（默认64）"}
                },
                "required": ["so_path", "function_name"]
            }
        ),
        
        # ===== 交叉引用分析工具 =====
        Tool(
            name="so_find_function",
            description="根据地址查找所属的函数",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "address": {"type": ["integer", "string"], "description": "地址(支持0x十六进制)"}
                },
                "required": ["so_path", "address"]
            }
        ),
        Tool(
            name="so_analyze_function",
            description="分析函数特征，判断是否是SSL验证函数",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "function_address": {"type": ["integer", "string"], "description": "函数地址(支持0x十六进制)"},
                    "size": {"type": "integer", "description": "分析的字节数（默认256）"}
                },
                "required": ["so_path", "function_address"]
            }
        ),
        Tool(
            name="so_get_sections",
            description="获取所有代码段信息",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"}
                },
                "required": ["so_path"]
            }
        ),
        
        # ===== 高级分析工具 (新增) =====
        Tool(
            name="so_list_all_functions",
            description="⭐识别所有函数（包括未导出的内部函数），通过扫描函数开头特征识别",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "limit": {"type": "integer", "description": "最大返回数量（默认2000）"},
                    "search": {"type": "string", "description": "搜索过滤（函数名）"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="so_callgraph",
            description="⭐分析函数调用关系图，识别BL/BLR调用指令，生成DOT格式调用图",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "function_addr": {"type": ["integer", "string"], "description": "函数虚拟地址(支持0x十六进制)"},
                    "max_depth": {"type": "integer", "description": "最大递归深度（默认3）"}
                },
                "required": ["so_path", "function_addr"]
            }
        ),
        Tool(
            name="so_get_cfg",
            description="⭐生成函数的控制流图(CFG)，识别基本块和分支边，生成DOT格式图",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "function_addr": {"type": ["integer", "string"], "description": "函数虚拟地址(支持0x十六进制)"},
                    "max_size": {"type": "integer", "description": "最大分析字节数（默认8192）"}
                },
                "required": ["so_path", "function_addr"]
            }
        ),
        Tool(
            name="so_analyze_function_advanced",
            description="⭐全面分析函数特征：调用关系、系统调用、字符串引用、复杂度、类型判断(SSL/加密/网络)",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "function_address": {"type": ["integer", "string"], "description": "函数虚拟地址(支持0x十六进制)"},
                    "size": {"type": "integer", "description": "分析的字节数（默认512）"}
                },
                "required": ["so_path", "function_address"]
            }
        ),
        Tool(
            name="so_decompile",
            description="⭐反编译函数生成伪代码。支持radare2(默认,轻量)/ghidra(高质量)/simple(无依赖)",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "address": {"type": ["integer", "string"], "description": "函数虚拟地址(支持0x十六进制)"},
                    "method": {"type": "string", "description": "反编译方法: radare2(默认)/ghidra/simple"},
                    "size": {"type": "integer", "description": "分析字节数(simple模式，默认256)"}
                },
                "required": ["so_path", "address"]
            }
        ),
        Tool(
            name="so_check_ghidra",
            description="检查Ghidra环境是否可用",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="so_check_radare2",
            description="检查Radare2环境是否可用",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="so_detect_encryption",
            description="⭐检测字符串加密/混淆：分析熵值、检测XOR/Base64、查找解密函数",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "min_length": {"type": "integer", "description": "最小字符串长度（默认8）"},
                    "max_strings": {"type": "integer", "description": "最大分析字符串数（默认100）"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="so_trace_register",
            description="⭐数据流分析：追踪寄存器值的来源，分析参数传递和返回值",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "function_addr": {"type": ["integer", "string"], "description": "函数虚拟地址(支持0x十六进制)"},
                    "register": {"type": "string", "description": "目标寄存器（默认x0）"},
                    "size": {"type": "integer", "description": "分析字节数（默认512）"}
                },
                "required": ["so_path", "function_addr"]
            }
        ),
        Tool(
            name="so_find_instruction",
            description="⭐搜索指令模式。支持:简单指令(bl/svc/ret)、预定义模式(syscall/compare/xor)、正则表达式、指令序列(stp;mov;bl)",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "pattern": {"type": "string", "description": "搜索模式：指令名/预定义/正则/序列(分号分隔)"},
                    "operand_filter": {"type": "string", "description": "操作数过滤（可选，支持正则）"},
                    "limit": {"type": "integer", "description": "最大返回数量（默认100）"}
                },
                "required": ["so_path", "pattern"]
            }
        ),
        Tool(
            name="so_get_entrypoints",
            description="⭐获取SO文件所有入口点：ELF入口、_init/_fini、构造/析构函数、JNI_OnLoad等",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="so_list_globals",
            description="⭐列出全局变量：.data/.bss/.rodata/.got段中的数据，显示名称、地址、大小、值预览",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "search": {"type": "string", "description": "搜索过滤（名称或地址）"},
                    "limit": {"type": "integer", "description": "最大返回数量（默认500）"},
                    "include_rodata": {"type": "boolean", "description": "是否包含只读数据（默认true）"},
                    "min_size": {"type": "integer", "description": "最小变量大小过滤"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="so_xref_string",
            description="⭐核心工具！查找字符串交叉引用 - 返回函数上下文（IDA级功能）",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "search_string": {"type": "string", "description": "要搜索的字符串"},
                    "max_xrefs": {"type": "integer", "description": "最大返回数量（默认20）"}
                },
                "required": ["so_path", "search_string"]
            }
        ),
        Tool(
            name="so_callers",
            description="⭐获取调用指定函数的所有位置（IDA callers功能）",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "func_address": {"type": "integer", "description": "目标函数地址"},
                    "limit": {"type": "integer", "description": "最大返回数量（默认50）"}
                },
                "required": ["so_path", "func_address"]
            }
        ),
        Tool(
            name="so_callees",
            description="⭐获取函数调用的所有函数（IDA callees功能）",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "func_address": {"type": "integer", "description": "函数起始地址"},
                    "func_size": {"type": "integer", "description": "函数大小（可选，默认自动检测）"}
                },
                "required": ["so_path", "func_address"]
            }
        ),
        Tool(
            name="so_find_function_v2",
            description="⭐改进版函数查找 - 修复边界检测问题",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "address": {"type": ["integer", "string"], "description": "目标地址(支持0x十六进制)"}
                },
                "required": ["so_path", "address"]
            }
        ),
        
        # ===== 高级Patch工具 =====
        Tool(
            name="so_patch_return",
            description="⭐修改函数直接返回指定值(VIP破解核心工具)。支持:0/1/true/false/-1/max/自定义数值",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "address": {"type": ["integer", "string"], "description": "函数地址(支持0x十六进制)"},
                    "return_value": {"type": ["integer", "string"], "description": "返回值:0/1/true/false/-1/max/数字"},
                    "output_path": {"type": "string", "description": "输出路径（可选，默认覆盖原文件）"}
                },
                "required": ["so_path", "address"]
            }
        ),
        Tool(
            name="so_patch_nop",
            description="将指令替换为NOP(空操作)，用于跳过检测代码",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "address": {"type": ["integer", "string"], "description": "起始地址(支持0x十六进制)"},
                    "count": {"type": "integer", "description": "NOP数量（每个4字节，默认1）"},
                    "output_path": {"type": "string", "description": "输出路径（可选）"}
                },
                "required": ["so_path", "address"]
            }
        ),
        Tool(
            name="so_patch_branch",
            description="修改分支跳转指令。force_jump=强制跳转/no_jump=不跳转/invert=反转条件",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "address": {"type": ["integer", "string"], "description": "分支指令地址(支持0x十六进制)"},
                    "patch_type": {"type": "string", "description": "类型:force_jump/no_jump/invert"},
                    "output_path": {"type": "string", "description": "输出路径（可选）"}
                },
                "required": ["so_path", "address", "patch_type"]
            }
        ),
        Tool(
            name="so_patch_hex",
            description="自定义Patch-直接写入十六进制字节（高级用户）",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "address": {"type": ["integer", "string"], "description": "目标地址(支持0x十六进制)"},
                    "hex_bytes": {"type": "string", "description": "十六进制字节(如20008052C0035FD6)"},
                    "output_path": {"type": "string", "description": "输出路径（可选）"}
                },
                "required": ["so_path", "address", "hex_bytes"]
            }
        ),
        Tool(
            name="so_find_vip",
            description="⭐自动查找VIP/会员验证函数（isVip/isPremium/checkLicense等）",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "keywords": {"type": "array", "items": {"type": "string"}, "description": "自定义关键词（可选）"},
                    "limit": {"type": "integer", "description": "最大返回数量（默认50）"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="so_patch_templates",
            description="获取所有预设Patch模板(return_true/return_false/nop/infinite_value等)",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        
        # ===== Flutter libapp.so 分析 =====
        Tool(
            name="flutter_check_blutter",
            description="检查Blutter环境是否可用（用于分析libapp.so）",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="flutter_analyze_libapp",
            description="⭐使用Blutter分析libapp.so，恢复Dart符号和函数（核心工具）",
            inputSchema={
                "type": "object",
                "properties": {
                    "lib_dir": {"type": "string", "description": "包含libapp.so的目录(如lib/arm64-v8a)"},
                    "output_dir": {"type": "string", "description": "输出目录（可选）"},
                    "rebuild": {"type": "boolean", "description": "是否重新编译Blutter（默认false）"}
                },
                "required": ["lib_dir"]
            }
        ),
        Tool(
            name="flutter_extract_strings",
            description="从libapp.so提取字符串和包名（无需Blutter）",
            inputSchema={
                "type": "object",
                "properties": {
                    "libapp_path": {"type": "string", "description": "libapp.so文件路径"}
                },
                "required": ["libapp_path"]
            }
        ),
        Tool(
            name="flutter_generate_hook",
            description="生成Flutter Frida Hook脚本。类型:trace/modify/args",
            inputSchema={
                "type": "object",
                "properties": {
                    "symbols": {"type": "array", "description": "符号列表（来自flutter_analyze_libapp）"},
                    "hook_type": {"type": "string", "description": "类型:trace(追踪)/modify(修改返回值)/args(打印参数)"},
                    "filter_pattern": {"type": "string", "description": "过滤模式（正则表达式，可选）"}
                },
                "required": ["symbols"]
            }
        ),
        Tool(
            name="flutter_analyze_apk",
            description="⭐完整分析Flutter APK：解压→提取SO→Blutter分析→生成Hook脚本",
            inputSchema={
                "type": "object",
                "properties": {
                    "apk_path": {"type": "string", "description": "APK文件路径"},
                    "output_dir": {"type": "string", "description": "输出目录（可选）"},
                    "use_blutter": {"type": "boolean", "description": "是否使用Blutter（默认true）"}
                },
                "required": ["apk_path"]
            }
        ),
        Tool(
            name="flutter_find_vip",
            description="⭐在Flutter libapp.so中查找VIP/会员相关函数",
            inputSchema={
                "type": "object",
                "properties": {
                    "libapp_path": {"type": "string", "description": "libapp.so文件路径"},
                    "blutter_output_dir": {"type": "string", "description": "Blutter输出目录（可选，如果已分析过）"}
                },
                "required": ["libapp_path"]
            }
        ),
        
        # ===== Blutter输出解析 =====
        Tool(
            name="blutter_parse",
            description="⭐解析Blutter输出目录，获取包、函数、类、字符串等完整信息",
            inputSchema={
                "type": "object",
                "properties": {
                    "blutter_dir": {"type": "string", "description": "Blutter输出目录路径"}
                },
                "required": ["blutter_dir"]
            }
        ),
        Tool(
            name="blutter_search_vip",
            description="⭐在Blutter输出中搜索VIP/会员相关函数，自动生成修改建议",
            inputSchema={
                "type": "object",
                "properties": {
                    "blutter_dir": {"type": "string", "description": "Blutter输出目录"},
                    "keywords": {"type": "array", "items": {"type": "string"}, "description": "自定义关键词（可选）"}
                },
                "required": ["blutter_dir"]
            }
        ),
        Tool(
            name="blutter_search_func",
            description="搜索Blutter解析出的函数。类型:name/address/package/class",
            inputSchema={
                "type": "object",
                "properties": {
                    "blutter_dir": {"type": "string", "description": "Blutter输出目录"},
                    "query": {"type": "string", "description": "搜索关键词"},
                    "search_type": {"type": "string", "description": "搜索类型:name/address/package/class"}
                },
                "required": ["blutter_dir", "query"]
            }
        ),
        Tool(
            name="blutter_search_string",
            description="搜索Blutter解析出的字符串（从pp.txt）",
            inputSchema={
                "type": "object",
                "properties": {
                    "blutter_dir": {"type": "string", "description": "Blutter输出目录"},
                    "query": {"type": "string", "description": "搜索关键词"},
                    "case_sensitive": {"type": "boolean", "description": "是否区分大小写（默认false）"}
                },
                "required": ["blutter_dir", "query"]
            }
        ),
        Tool(
            name="blutter_func_detail",
            description="获取指定地址函数的详细信息和汇编代码",
            inputSchema={
                "type": "object",
                "properties": {
                    "blutter_dir": {"type": "string", "description": "Blutter输出目录"},
                    "address": {"type": "string", "description": "函数地址（如0xa716a8）"}
                },
                "required": ["blutter_dir", "address"]
            }
        ),
        Tool(
            name="blutter_export_hooks",
            description="为指定函数生成Frida Hook脚本。类型:trace/modify/log",
            inputSchema={
                "type": "object",
                "properties": {
                    "blutter_dir": {"type": "string", "description": "Blutter输出目录"},
                    "functions": {"type": "array", "description": "函数列表[{address,name},...]"},
                    "hook_type": {"type": "string", "description": "Hook类型:trace/modify/log"}
                },
                "required": ["blutter_dir", "functions"]
            }
        )
    ]


@server.list_tools()
async def list_tools():
    """列出所有可用工具"""
    return get_all_tools()


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    """调用工具"""
    result = None
    
    try:
        # SO基础分析
        if name == "so_check_env":
            result = check_lief()
        
        elif name == "so_list_libs":
            result = list_libs_from_apk(apk_path=arguments["apk_path"])
        
        elif name == "so_extract":
            result = extract_so_from_apk(
                apk_path=arguments["apk_path"],
                lib_name=arguments["lib_name"],
                arch=arguments.get("arch", "arm64-v8a"),
                output_dir=arguments.get("output_dir")
            )
        
        elif name == "so_info":
            result = get_so_info(so_path=arguments["so_path"])
        
        elif name == "so_exports":
            result = get_exports(
                so_path=arguments["so_path"],
                search=arguments.get("search", ""),
                limit=arguments.get("limit", 100)
            )
        
        elif name == "so_imports":
            result = get_imports(
                so_path=arguments["so_path"],
                search=arguments.get("search", ""),
                limit=arguments.get("limit", 100)
            )
        
        elif name == "so_strings":
            result = get_strings(
                so_path=arguments["so_path"],
                min_length=arguments.get("min_length", 4),
                search=arguments.get("search", ""),
                limit=arguments.get("limit", 200)
            )
        
        elif name == "so_search_symbol":
            result = search_symbol(
                so_path=arguments["so_path"],
                pattern=arguments["pattern"],
                limit=arguments.get("limit", 50)
            )
        
        # Flutter工具
        elif name == "flutter_detect":
            result = detect_flutter(apk_path=arguments["apk_path"])
        
        elif name == "flutter_get_version":
            result = get_flutter_version(so_path=arguments["so_path"])
        
        elif name == "flutter_find_ssl":
            result = find_ssl_verify_function(so_path=arguments["so_path"])
        
        elif name == "flutter_patch_ssl":
            result = patch_ssl_verify(
                so_path=arguments["so_path"],
                output_path=arguments.get("output_path")
            )
        
        elif name == "flutter_patch_apk":
            result = flutter_patch_apk(
                apk_path=arguments["apk_path"],
                output_path=arguments.get("output_path"),
                arch=arguments.get("arch", "arm64-v8a")
            )
        
        elif name == "flutter_ssl_offset_v2":
            result = find_ssl_verify_function_v2(so_path=arguments["so_path"])
        
        # 二进制修改
        elif name == "so_patch_bytes":
            result = patch_bytes(
                file_path=arguments["file_path"],
                offset=arguments["offset"],
                new_bytes=bytes.fromhex(arguments["new_bytes"]),
                output_path=arguments.get("output_path")
            )
        
        elif name == "so_search_bytes":
            result = search_bytes(
                file_path=arguments["file_path"],
                pattern=bytes.fromhex(arguments["pattern"]),
                limit=arguments.get("limit", 20)
            )
        
        elif name == "so_replace_bytes":
            result = replace_bytes(
                file_path=arguments["file_path"],
                find_pattern=bytes.fromhex(arguments["find_pattern"]),
                replace_with=bytes.fromhex(arguments["replace_with"]),
                output_path=arguments.get("output_path"),
                replace_all=arguments.get("replace_all", False)
            )
        
        elif name == "so_disassemble":
            result = disassemble(
                so_path=arguments["so_path"],
                address=parse_address(arguments["address"]),
                size=arguments.get("size", 64),
                arch=arguments.get("arch", "auto")
            )
        
        elif name == "so_get_function_bytes":
            result = get_function_bytes(
                so_path=arguments["so_path"],
                function_name=arguments["function_name"],
                size=arguments.get("size", 64)
            )
        
        # 交叉引用分析
        elif name == "so_xref_string":
            result = xref_string_enhanced(
                so_path=arguments["so_path"],
                search_string=arguments["search_string"],
                max_xrefs=arguments.get("max_xrefs", 20)
            )
        
        elif name == "so_find_function":
            result = find_function_by_address(
                so_path=arguments["so_path"],
                address=parse_address(arguments["address"])
            )
        
        elif name == "so_analyze_function":
            result = analyze_function(
                so_path=arguments["so_path"],
                function_address=parse_address(arguments["function_address"]),
                size=arguments.get("size", 256)
            )
        
        elif name == "so_get_sections":
            result = get_code_sections(so_path=arguments["so_path"])
        
        # 高级分析工具
        elif name == "so_list_all_functions":
            result = list_all_functions(
                so_path=arguments["so_path"],
                limit=arguments.get("limit", 2000),
                search=arguments.get("search", "")
            )
        
        elif name == "so_callgraph":
            result = callgraph(
                so_path=arguments["so_path"],
                function_addr=parse_address(arguments["function_addr"]),
                max_depth=arguments.get("max_depth", 3)
            )
        
        elif name == "so_get_cfg":
            result = get_cfg(
                so_path=arguments["so_path"],
                function_addr=parse_address(arguments["function_addr"]),
                max_size=arguments.get("max_size", 0x2000)
            )
        
        elif name == "so_analyze_function_advanced":
            result = analyze_function_advanced(
                so_path=arguments["so_path"],
                function_address=parse_address(arguments["function_address"]),
                size=arguments.get("size", 512)
            )
        
        elif name == "so_decompile":
            result = decompile(
                so_path=arguments["so_path"],
                address=parse_address(arguments["address"]),
                method=arguments.get("method", "radare2"),
                size=arguments.get("size", 256)
            )
        
        elif name == "so_check_ghidra":
            result = check_ghidra()
        
        elif name == "so_check_radare2":
            result = check_radare2()
        
        elif name == "so_detect_encryption":
            result = detect_string_encryption(
                so_path=arguments["so_path"],
                min_length=arguments.get("min_length", 8),
                max_strings=arguments.get("max_strings", 100)
            )
        
        elif name == "so_trace_register":
            result = trace_register_value(
                so_path=arguments["so_path"],
                function_addr=parse_address(arguments["function_addr"]),
                target_register=arguments.get("register", "x0"),
                size=arguments.get("size", 512)
            )
        
        elif name == "so_find_instruction":
            result = find_instruction_pattern(
                so_path=arguments["so_path"],
                pattern=arguments["pattern"],
                operand_filter=arguments.get("operand_filter", ""),
                limit=arguments.get("limit", 100)
            )
        
        elif name == "so_get_entrypoints":
            result = get_entrypoints(so_path=arguments["so_path"])
        
        elif name == "so_list_globals":
            result = list_globals(
                so_path=arguments["so_path"],
                search=arguments.get("search", ""),
                limit=arguments.get("limit", 500),
                include_rodata=arguments.get("include_rodata", True),
                min_size=arguments.get("min_size", 0)
            )
        
        elif name == "so_callers":
            result = get_callers(
                so_path=arguments["so_path"],
                func_address=parse_address(arguments["func_address"]),
                limit=arguments.get("limit", 50)
            )
        
        elif name == "so_callees":
            result = get_callees(
                so_path=arguments["so_path"],
                func_address=parse_address(arguments["func_address"]),
                func_size=arguments.get("func_size", 0x1000)
            )
        
        elif name == "so_find_function_v2":
            result = find_function_at(
                so_path=arguments["so_path"],
                address=parse_address(arguments["address"])
            )
        
        # 高级Patch工具
        elif name == "so_patch_return":
            result = patch_return_value(
                so_path=arguments["so_path"],
                address=parse_address(arguments["address"]),
                return_value=arguments.get("return_value", 1),
                output_path=arguments.get("output_path")
            )
        
        elif name == "so_patch_nop":
            result = patch_nop(
                so_path=arguments["so_path"],
                address=parse_address(arguments["address"]),
                count=arguments.get("count", 1),
                output_path=arguments.get("output_path")
            )
        
        elif name == "so_patch_branch":
            result = patch_branch(
                so_path=arguments["so_path"],
                address=parse_address(arguments["address"]),
                patch_type=arguments["patch_type"],
                output_path=arguments.get("output_path")
            )
        
        elif name == "so_patch_hex":
            result = patch_custom(
                so_path=arguments["so_path"],
                address=parse_address(arguments["address"]),
                hex_bytes=arguments["hex_bytes"],
                output_path=arguments.get("output_path")
            )
        
        elif name == "so_find_vip":
            result = find_vip_functions(
                so_path=arguments["so_path"],
                keywords=arguments.get("keywords"),
                limit=arguments.get("limit", 50)
            )
        
        elif name == "so_patch_templates":
            result = get_patch_templates()
        
        # Flutter libapp.so 分析
        elif name == "flutter_check_blutter":
            result = check_blutter()
        
        elif name == "flutter_analyze_libapp":
            result = analyze_libapp_with_blutter(
                lib_dir=arguments["lib_dir"],
                output_dir=arguments.get("output_dir"),
                rebuild=arguments.get("rebuild", False)
            )
        
        elif name == "flutter_extract_strings":
            result = extract_dart_symbols(
                libapp_path=arguments["libapp_path"]
            )
        
        elif name == "flutter_generate_hook":
            result = generate_flutter_hook_script(
                symbols=arguments["symbols"],
                hook_type=arguments.get("hook_type", "trace"),
                filter_pattern=arguments.get("filter_pattern", "")
            )
        
        elif name == "flutter_analyze_apk":
            result = analyze_flutter_apk(
                apk_path=arguments["apk_path"],
                output_dir=arguments.get("output_dir"),
                use_blutter=arguments.get("use_blutter", True)
            )
        
        elif name == "flutter_find_vip":
            result = find_flutter_vip_functions(
                libapp_path=arguments["libapp_path"],
                blutter_output_dir=arguments.get("blutter_output_dir")
            )
        
        # Blutter输出解析
        elif name == "blutter_parse":
            result = parse_blutter_output(
                blutter_dir=arguments["blutter_dir"]
            )
        
        elif name == "blutter_search_vip":
            result = search_blutter_vip_functions(
                blutter_dir=arguments["blutter_dir"],
                custom_keywords=arguments.get("keywords")
            )
        
        elif name == "blutter_search_func":
            result = search_blutter_functions(
                blutter_dir=arguments["blutter_dir"],
                query=arguments["query"],
                search_type=arguments.get("search_type", "name")
            )
        
        elif name == "blutter_search_string":
            result = search_blutter_strings(
                blutter_dir=arguments["blutter_dir"],
                query=arguments["query"],
                case_sensitive=arguments.get("case_sensitive", False)
            )
        
        elif name == "blutter_func_detail":
            result = get_function_detail(
                blutter_dir=arguments["blutter_dir"],
                address=arguments["address"]
            )
        
        elif name == "blutter_export_hooks":
            result = export_frida_hooks(
                blutter_dir=arguments["blutter_dir"],
                functions=arguments["functions"],
                hook_type=arguments.get("hook_type", "trace")
            )
        
        else:
            result = {"success": False, "error": f"Unknown tool: {name}"}
    
    except Exception as e:
        result = {"success": False, "error": str(e)}
    
    return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]


async def main():
    """主入口"""
    from mcp.server.stdio import stdio_server
    
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )
