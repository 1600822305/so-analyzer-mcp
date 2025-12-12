"""二进制修改工具"""
import os
from typing import Optional, List, Dict, Union

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    CS_MODE_THUMB = 0  # fallback
    try:
        from capstone import CS_MODE_THUMB
    except:
        pass
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


def patch_bytes(
    file_path: str,
    offset: int,
    new_bytes: bytes,
    output_path: Optional[str] = None
) -> dict:
    """
    在指定偏移处修改字节
    
    Args:
        file_path: 文件路径
        offset: 偏移量
        new_bytes: 新字节
        output_path: 输出路径（可选，默认覆盖原文件）
    
    Returns:
        dict: {"success": bool, "original": str, "patched": str, "error": str}
    """
    if not os.path.exists(file_path):
        return {"success": False, "error": f"File not found: {file_path}"}
    
    try:
        with open(file_path, 'rb') as f:
            data = bytearray(f.read())
        
        if offset < 0 or offset + len(new_bytes) > len(data):
            return {"success": False, "error": f"Invalid offset: {offset}"}
        
        # 保存原始字节
        original = bytes(data[offset:offset + len(new_bytes)])
        
        # 修改
        data[offset:offset + len(new_bytes)] = new_bytes
        
        # 保存
        out_path = output_path or file_path
        with open(out_path, 'wb') as f:
            f.write(data)
        
        return {
            "success": True,
            "offset": hex(offset),
            "original": original.hex(),
            "patched": new_bytes.hex(),
            "output_path": out_path,
            "error": ""
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def search_bytes(
    file_path: str,
    pattern: bytes,
    limit: int = 20
) -> dict:
    """
    搜索字节模式
    
    Args:
        file_path: 文件路径
        pattern: 字节模式
        limit: 最多返回数量
    
    Returns:
        dict: {"success": bool, "offsets": list, "error": str}
    """
    if not os.path.exists(file_path):
        return {"success": False, "offsets": [], "error": f"File not found: {file_path}"}
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        offsets = []
        start = 0
        while len(offsets) < limit:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            offsets.append({
                "offset": pos,
                "hex_offset": hex(pos)
            })
            start = pos + 1
        
        return {
            "success": True,
            "offsets": offsets,
            "count": len(offsets),
            "pattern": pattern.hex(),
            "error": ""
        }
    except Exception as e:
        return {"success": False, "offsets": [], "error": str(e)}


def replace_bytes(
    file_path: str,
    find_pattern: bytes,
    replace_with: bytes,
    output_path: Optional[str] = None,
    replace_all: bool = False
) -> dict:
    """
    查找并替换字节
    
    Args:
        file_path: 文件路径
        find_pattern: 查找模式
        replace_with: 替换内容
        output_path: 输出路径
        replace_all: 是否替换所有
    
    Returns:
        dict: {"success": bool, "replaced_count": int, "error": str}
    """
    if not os.path.exists(file_path):
        return {"success": False, "replaced_count": 0, "error": f"File not found: {file_path}"}
    
    if len(find_pattern) != len(replace_with):
        return {
            "success": False,
            "replaced_count": 0,
            "error": "Find and replace patterns must be the same length"
        }
    
    try:
        with open(file_path, 'rb') as f:
            data = bytearray(f.read())
        
        count = 0
        start = 0
        while True:
            pos = data.find(find_pattern, start)
            if pos == -1:
                break
            
            data[pos:pos + len(replace_with)] = replace_with
            count += 1
            
            if not replace_all:
                break
            
            start = pos + len(replace_with)
        
        if count == 0:
            return {
                "success": False,
                "replaced_count": 0,
                "error": "Pattern not found"
            }
        
        out_path = output_path or file_path
        with open(out_path, 'wb') as f:
            f.write(data)
        
        return {
            "success": True,
            "replaced_count": count,
            "find_pattern": find_pattern.hex(),
            "replace_with": replace_with.hex(),
            "output_path": out_path,
            "error": ""
        }
    except Exception as e:
        return {"success": False, "replaced_count": 0, "error": str(e)}


def vaddr_to_file_offset(binary, vaddr: int) -> int:
    """
    将虚拟地址转换为文件偏移
    
    Args:
        binary: LIEF解析的二进制对象
        vaddr: 虚拟地址
    
    Returns:
        int: 文件偏移，找不到返回-1
    """
    for segment in binary.segments:
        if segment.virtual_address <= vaddr < segment.virtual_address + segment.virtual_size:
            offset_in_segment = vaddr - segment.virtual_address
            if offset_in_segment < segment.physical_size:
                return segment.file_offset + offset_in_segment
    return -1


def disassemble(
    so_path: str,
    address: int,
    size: int = 64,
    arch: str = "auto"
) -> dict:
    """
    反汇编指定地址的代码
    
    Args:
        so_path: SO文件路径
        address: 起始地址（虚拟地址，兼容IDA风格）
        size: 字节数
        arch: 架构（auto/arm64/arm）
    
    Returns:
        dict: {"success": bool, "instructions": list, "error": str}
    """
    if not CAPSTONE_AVAILABLE:
        return {
            "success": False,
            "instructions": [],
            "error": "capstone not available. Install: pip install capstone"
        }
    
    if not os.path.exists(so_path):
        return {"success": False, "instructions": [], "error": f"File not found: {so_path}"}
    
    try:
        with open(so_path, 'rb') as f:
            data = f.read()
        
        binary = None
        file_offset = address  # 默认当作文件偏移
        virtual_addr = address  # 用于反汇编输出
        
        # 自动检测架构并解析ELF
        if LIEF_AVAILABLE:
            binary = lief.parse(so_path)
            if binary and hasattr(binary, 'header'):
                arch_name = binary.header.machine_type.name if hasattr(binary.header.machine_type, 'name') else ""
                if "AARCH64" in arch_name or "ARM64" in arch_name.upper():
                    arch = "arm64" if arch == "auto" else arch
                elif arch == "auto":
                    arch = "arm"
                
                # 判断address是虚拟地址还是文件偏移
                # 通常虚拟地址 > 0x10000 且在某个段范围内
                converted_offset = vaddr_to_file_offset(binary, address)
                if converted_offset >= 0:
                    # address是有效的虚拟地址
                    file_offset = converted_offset
                    virtual_addr = address
                else:
                    # 可能已经是文件偏移，或者是无效地址
                    # 尝试当作文件偏移使用
                    file_offset = address
                    # 计算对应的虚拟地址（用于反汇编输出）
                    for segment in binary.segments:
                        if segment.file_offset <= address < segment.file_offset + segment.physical_size:
                            offset_in_segment = address - segment.file_offset
                            virtual_addr = segment.virtual_address + offset_in_segment
                            break
            else:
                if arch == "auto":
                    arch = "arm64"
        else:
            if arch == "auto":
                arch = "arm64"
        
        # 配置反汇编器
        if arch == "arm64":
            md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        else:
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_THUMB)
        
        # 提取代码（使用文件偏移）
        if file_offset < 0 or file_offset + size > len(data):
            return {"success": False, "instructions": [], "error": f"Invalid address range: file_offset={hex(file_offset)}, size={size}, file_size={len(data)}"}
        
        code = bytes(data[file_offset:file_offset + size])
        
        # 反汇编（使用虚拟地址作为起始地址）
        instructions = []
        try:
            for insn in md.disasm(code, virtual_addr):
                instructions.append({
                    "address": hex(insn.address),
                    "bytes": insn.bytes.hex(),
                    "mnemonic": insn.mnemonic,
                    "operands": insn.op_str,
                    "text": f"{insn.mnemonic} {insn.op_str}"
                })
        except Exception as disasm_err:
            # 如果反汇编失败，返回原始字节
            return {
                "success": True,
                "instructions": [],
                "raw_bytes": code.hex(),
                "count": 0,
                "architecture": arch,
                "error": f"Disassembly failed: {disasm_err}, showing raw bytes"
            }
        
        # 如果没有指令但有数据，可能是数据段或对齐问题
        if not instructions and code:
            return {
                "success": True,
                "instructions": [],
                "raw_bytes": code.hex(),
                "count": 0,
                "architecture": arch,
                "note": "No valid instructions found at this address. Might be data section or misaligned.",
                "error": ""
            }
        
        return {
            "success": True,
            "instructions": instructions,
            "count": len(instructions),
            "architecture": arch,
            "start_address": hex(virtual_addr),
            "file_offset": hex(file_offset),
            "error": ""
        }
    except Exception as e:
        import traceback
        return {"success": False, "instructions": [], "error": f"{str(e)}\n{traceback.format_exc()}"}


def get_function_bytes(
    so_path: str,
    function_name: str,
    size: int = 64
) -> dict:
    """
    获取函数的字节码
    
    Args:
        so_path: SO文件路径
        function_name: 函数名
        size: 读取字节数
    
    Returns:
        dict: {"success": bool, "bytes": str, "address": str, "error": str}
    """
    if not LIEF_AVAILABLE:
        return {"success": False, "bytes": "", "address": "", "error": "lief not available"}
    
    if not os.path.exists(so_path):
        return {"success": False, "bytes": "", "address": "", "error": f"File not found: {so_path}"}
    
    try:
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "bytes": "", "address": "", "error": "Failed to parse SO file"}
        
        # 查找函数
        target_func = None
        for func in binary.exported_functions:
            name = func.name if hasattr(func, 'name') else str(func)
            if name == function_name or function_name in name:
                target_func = func
                break
        
        if target_func is None:
            return {
                "success": False,
                "bytes": "",
                "address": "",
                "error": f"Function not found: {function_name}"
            }
        
        address = target_func.address if hasattr(target_func, 'address') else 0
        
        # 读取字节
        with open(so_path, 'rb') as f:
            data = f.read()
        
        if address < 0 or address + size > len(data):
            return {"success": False, "bytes": "", "address": hex(address), "error": "Invalid address"}
        
        func_bytes = data[address:address + size]
        
        return {
            "success": True,
            "function_name": target_func.name if hasattr(target_func, 'name') else function_name,
            "address": hex(address),
            "bytes": func_bytes.hex(),
            "size": len(func_bytes),
            "error": ""
        }
    except Exception as e:
        return {"success": False, "bytes": "", "address": "", "error": str(e)}
