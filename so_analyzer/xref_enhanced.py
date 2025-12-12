"""增强版交叉引用分析 - 返回函数上下文（IDA级功能）"""
import os
import struct
from typing import Optional, List, Dict, Tuple

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


def _find_function_boundaries(binary, data: bytes, address: int, 
                              all_functions: list = None) -> Optional[dict]:
    """
    找到包含指定地址的函数边界
    
    策略:
    1. 检查已知导出函数
    2. 使用预先扫描的函数列表
    3. 向前搜索函数序言
    4. 向后搜索函数结尾确定大小
    """
    if not LIEF_AVAILABLE:
        return None
    
    try:
        # 方法1: 检查导出函数
        for func in binary.exported_functions:
            func_addr = func.address if hasattr(func, 'address') else 0
            func_name = func.name if hasattr(func, 'name') else ""
            if func_addr and func_addr <= address:
                # 需要验证address在函数范围内
                pass
        
        # 方法2: 如果有预扫描的函数列表，直接查找
        if all_functions:
            for func in all_functions:
                start = func.get("address", 0)
                size = func.get("size", 0)
                if start <= address < start + size:
                    return {
                        "name": func.get("name", f"sub_{start:x}"),
                        "address": hex(start),
                        "size": size,
                        "end_address": hex(start + size),
                        "source": "function_list"
                    }
        
        # 方法3: 向前搜索函数序言
        func_start = _find_function_prologue(data, address)
        if func_start:
            # 向后搜索函数结尾
            func_end = _find_function_epilogue(data, func_start, max_size=0x2000)
            size = func_end - func_start if func_end else 0x100
            
            # 检查是否有对应的符号
            func_name = f"sub_{func_start:X}"
            for func in binary.exported_functions:
                if hasattr(func, 'address') and func.address == func_start:
                    func_name = func.name
                    break
            
            return {
                "name": func_name,
                "address": hex(func_start),
                "size": size,
                "end_address": hex(func_start + size),
                "source": "heuristic"
            }
        
        return None
    except:
        return None


def _find_function_prologue(data: bytes, address: int, max_search: int = 0x1000) -> Optional[int]:
    """向前搜索函数序言"""
    # ARM64 常见函数序言模式
    PROLOGUE_PATTERNS = [
        # stp x29, x30, [sp, #-imm]! - 标准帧指针保存
        (0xFFC003E0, 0xA9A003E0),  # 宽松匹配
        (0xFFC07FFF, 0xA9BF7BFD),  # stp x29, x30, [sp, #-0x10]!
        # pacibsp - PAC 指令 (ARMv8.3+)
        (0xFFFFFFFF, 0xD503237F),
        # sub sp, sp, #imm
        (0xFF0003FF, 0xD10003FF),
    ]
    
    search_start = max(0, address - max_search)
    
    for offset in range(address, search_start, -4):
        if offset + 4 > len(data):
            continue
        insn = struct.unpack('<I', data[offset:offset+4])[0]
        
        for mask, pattern in PROLOGUE_PATTERNS:
            if (insn & mask) == pattern:
                return offset
    
    return None


def _find_function_epilogue(data: bytes, start: int, max_size: int = 0x1000) -> Optional[int]:
    """向后搜索函数结尾"""
    # ARM64 常见函数结尾模式
    EPILOGUE_PATTERNS = [
        # ret
        (0xFFFFFFFF, 0xD65F03C0),
        # retab / retaa (PAC)
        (0xFFFFFFF0, 0xD65F0BF0),
        # br x30 (等效于ret)
        (0xFFFFFFFF, 0xD61F03C0),
    ]
    
    for offset in range(start, min(start + max_size, len(data) - 4), 4):
        insn = struct.unpack('<I', data[offset:offset+4])[0]
        
        for mask, pattern in EPILOGUE_PATTERNS:
            if (insn & mask) == pattern:
                return offset + 4  # 返回函数结束地址（ret后一条）
    
    return start + max_size  # 默认大小


def _scan_all_functions(binary, data: bytes) -> list:
    """
    扫描所有函数（改进版 - 精确检测内部函数）
    
    策略：
    1. 导出函数
    2. 符号表函数  
    3. 精确搜索函数序言模式（更多模式）
    4. 检测 ret 后的函数边界
    """
    functions = []
    known_addrs = set()
    
    # 获取 .text 段信息
    text_section = None
    for section in binary.sections:
        if section.name == ".text":
            text_section = section
            break
    
    if not text_section:
        return functions
    
    text_start = text_section.file_offset
    text_vaddr = text_section.virtual_address
    text_size = text_section.size
    text_end = text_start + text_size
    
    # 1. 添加所有导出函数
    for func in binary.exported_functions:
        if hasattr(func, 'address') and func.address:
            addr = func.address
            if text_vaddr <= addr < text_vaddr + text_size:
                known_addrs.add(addr)
                functions.append({
                    "name": func.name if hasattr(func, 'name') else f"sub_{addr:X}",
                    "address": addr,
                    "type": "exported"
                })
    
    # 2. 从符号表添加函数
    try:
        for symbol in binary.symbols:
            if symbol.type == lief.ELF.Symbol.TYPE.FUNC and symbol.value != 0:
                addr = symbol.value
                if addr not in known_addrs and text_vaddr <= addr < text_vaddr + text_size:
                    functions.append({
                        "name": symbol.name if symbol.name else f"sub_{addr:X}",
                        "address": addr,
                        "type": "symbol"
                    })
                    known_addrs.add(addr)
    except:
        pass
    
    # 3. 精确搜索函数序言模式
    # ARM64 函数序言特征 - 按优先级排序
    PROLOGUE_PATTERNS = [
        # pacibsp - ARMv8.3+ PAC (最高优先级，绝对是函数开头)
        (0xFFFFFFFF, 0xD503237F, "pacibsp"),
        # stp x29, x30, [sp, #-imm]! - 标准帧保存
        (0xFFC003E0, 0xA9A003E0, "stp_pre"),
        # stp x29, x30, [sp, #-0x10]! 精确匹配
        (0xFFFFFFFF, 0xA9BF7BFD, "stp_16"),
        # stp x29, x30, [sp, #-0x20]!
        (0xFFFFFFFF, 0xA9BE7BFD, "stp_32"),
        # stp x29, x30, [sp, #-0x30]!
        (0xFFFFFFFF, 0xA9BD7BFD, "stp_48"),
        # stp x29, x30, [sp, #-0x40]!
        (0xFFFFFFFF, 0xA9BC7BFD, "stp_64"),
        # stp 其他寄存器对 [sp, #-imm]! (也可能是函数开头)
        (0xFFC003E0, 0xA9A003E0, "stp_other"),
        # sub sp, sp, #imm 后跟 stp
        (0xFF0003FF, 0xD10003FF, "sub_sp"),
    ]
    
    # 扫描整个 .text 段
    for offset in range(text_start, min(text_end, len(data) - 4), 4):
        insn = struct.unpack('<I', data[offset:offset+4])[0]
        
        for mask, pattern, ptype in PROLOGUE_PATTERNS:
            if (insn & mask) == pattern:
                vaddr = text_vaddr + (offset - text_start)
                if vaddr not in known_addrs:
                    is_valid_start = False
                    
                    # pacibsp 绝对是函数开头
                    if ptype == "pacibsp":
                        is_valid_start = True
                    
                    # stp x29, x30 模式需要额外验证
                    elif ptype.startswith("stp"):
                        # 检查前一条指令
                        if offset >= text_start + 4:
                            prev_insn = struct.unpack('<I', data[offset-4:offset])[0]
                            # ret/retab/br x30
                            if prev_insn == 0xD65F03C0 or (prev_insn & 0xFFFFFFF0) == 0xD65F0BF0 or prev_insn == 0xD61F03C0:
                                is_valid_start = True
                            # b imm (无条件跳转)
                            elif (prev_insn & 0xFC000000) == 0x14000000:
                                is_valid_start = True
                            # nop (可能是对齐填充)
                            elif prev_insn == 0xD503201F:
                                is_valid_start = True
                            # brk (断点，可能是函数边界)
                            elif (prev_insn & 0xFFE00000) == 0xD4200000:
                                is_valid_start = True
                        elif offset == text_start:
                            is_valid_start = True
                    
                    # sub sp, sp 需要检查下一条是否是 stp
                    elif ptype == "sub_sp":
                        if offset + 4 < text_end:
                            next_insn = struct.unpack('<I', data[offset+4:offset+8])[0]
                            # 下一条是 stp
                            if (next_insn & 0xFFC00000) == 0xA9000000:
                                if offset >= text_start + 4:
                                    prev_insn = struct.unpack('<I', data[offset-4:offset])[0]
                                    if prev_insn == 0xD65F03C0 or (prev_insn & 0xFC000000) == 0x14000000:
                                        is_valid_start = True
                    
                    if is_valid_start:
                        functions.append({
                            "name": f"sub_{vaddr:X}",
                            "address": vaddr,
                            "type": "detected"
                        })
                        known_addrs.add(vaddr)
                break
    
    # 4. 按地址排序
    functions.sort(key=lambda x: x["address"])
    
    # 5. 计算函数大小（基于下一个函数的起始地址）
    for i, func in enumerate(functions):
        if i + 1 < len(functions):
            next_addr = functions[i + 1]["address"]
            size = next_addr - func["address"]
            # 限制最大函数大小为 256KB
            func["size"] = min(size, 0x40000)
        else:
            func["size"] = 0x1000
    
    return functions


def _find_precise_function_start(data: bytes, text_start: int, text_vaddr: int,
                                  ref_addr: int, max_search: int = 0x200) -> Optional[int]:
    """
    从引用地址向前精确查找函数开头
    
    支持的函数序言模式:
    1. pacibsp
    2. stp x29, x30, [sp, #-imm]!  (pre-index)
    3. stp x29, x30, [sp, #imm]   (offset)
    4. sub sp, sp, #imm + stp     (常见模式)
    """
    ref_file_offset = text_start + (ref_addr - text_vaddr)
    search_start = max(text_start, ref_file_offset - max_search)
    
    for offset in range(ref_file_offset, search_start, -4):
        if offset + 4 > len(data):
            continue
        insn = struct.unpack('<I', data[offset:offset+4])[0]
        
        is_prologue = False
        actual_start = offset
        
        # 模式1: pacibsp
        if insn == 0xD503237F:
            is_prologue = True
        
        # 模式2: stp x29, x30, [sp, #-imm]! (pre-index)
        elif (insn & 0xFFC003E0) == 0xA9A003E0:
            is_prologue = True
        
        # 模式3: stp x29, x30, [sp, #imm] (offset)
        elif (insn & 0xFFC00000) == 0xA9000000:
            # 检查低5位是否包含 x29/x30/sp 相关寄存器
            rt = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            rt2 = (insn >> 10) & 0x1F
            # x29=29, x30=30, sp=31
            if rn == 31 and (rt == 29 or rt2 == 29 or rt2 == 30):
                is_prologue = True
                # 检查前一条是否是 sub sp, sp, #imm
                if offset >= text_start + 4:
                    prev_insn = struct.unpack('<I', data[offset-4:offset])[0]
                    # sub sp, sp, #imm: 1101 0001 00xx xxxx xxxx xx11 1111 1111
                    if (prev_insn & 0xFF0003FF) == 0xD10003FF:
                        actual_start = offset - 4
        
        # 模式4: sub sp, sp, #imm 后跟 stp
        elif (insn & 0xFF0003FF) == 0xD10003FF:
            if offset + 8 <= len(data):
                next_insn = struct.unpack('<I', data[offset+4:offset+8])[0]
                # 下一条是 stp
                if (next_insn & 0xFFC00000) == 0xA9000000:
                    is_prologue = True
        
        if is_prologue:
            # 验证前一条指令是函数边界
            if actual_start >= text_start + 4:
                prev_insn = struct.unpack('<I', data[actual_start-4:actual_start])[0]
                if (prev_insn == 0xD65F03C0 or  # ret
                    (prev_insn & 0xFFFFFFF0) == 0xD65F0BF0 or  # retab
                    (prev_insn & 0xFC000000) == 0x14000000 or  # b imm
                    prev_insn == 0xD503201F or  # nop
                    (prev_insn & 0xFFE00000) == 0xD4200000):  # brk
                    return text_vaddr + (actual_start - text_start)
            elif actual_start == text_start:
                return text_vaddr + (actual_start - text_start)
    
    return None


def _find_precise_function_end(data: bytes, text_start: int, text_vaddr: int,
                                func_start: int, max_size: int = 0x2000) -> int:
    """
    从函数开头向后搜索函数结尾（IDA风格 - CFG分析）
    
    策略：追踪所有分支目标，找到函数内所有代码块的最大地址
    
    返回函数大小（字节数）
    """
    func_file_offset = text_start + (func_start - text_vaddr)
    
    # CFG 分析：追踪所有可达的代码块
    visited = set()
    pending = [func_start]
    max_addr = func_start
    
    while pending:
        current_vaddr = pending.pop()
        
        if current_vaddr in visited:
            continue
        
        # 超出合理范围，跳过
        if current_vaddr < func_start or current_vaddr > func_start + max_size:
            continue
        
        visited.add(current_vaddr)
        current_offset = text_start + (current_vaddr - text_vaddr)
        
        # 扫描这个基本块
        block_offset = current_offset
        while block_offset < current_offset + max_size and block_offset + 4 <= len(data):
            insn = struct.unpack('<I', data[block_offset:block_offset+4])[0]
            insn_vaddr = text_vaddr + (block_offset - text_start)
            
            # 更新最大地址
            if insn_vaddr > max_addr:
                max_addr = insn_vaddr
            
            # 检测 LDP x29, x30 后跟 B (far) - 共享尾调用结束
            is_ldp_x29_x30 = (insn & 0x7FFF) == 0x7BFD and ((insn >> 22) & 1)
            if is_ldp_x29_x30 and block_offset + 4 < len(data):
                next_insn = struct.unpack('<I', data[block_offset+4:block_offset+8])[0]
                # B (far)
                if (next_insn & 0xFC000000) == 0x14000000:
                    imm26 = next_insn & 0x3FFFFFF
                    if imm26 & 0x2000000:
                        imm26 = imm26 - 0x4000000
                    target = (insn_vaddr + 4) + (imm26 << 2)
                    jump_distance = abs(target - (insn_vaddr + 4))
                    if jump_distance > 0x1000:
                        # 共享尾调用，基本块到此结束
                        if insn_vaddr + 8 > max_addr:
                            max_addr = insn_vaddr + 4  # B 指令是最后一条
                        break
            
            # RET - 基本块结束
            if insn == 0xD65F03C0 or (insn & 0xFFFFFFF0) == 0xD65F0BF0:
                break
            
            # BR - 间接跳转，基本块结束
            if (insn & 0xFFFFFC1F) == 0xD61F0000:
                break
            
            # BLR - 间接调用，继续
            # BL - 直接调用，继续（下一条是返回地址）
            
            # B - 无条件跳转
            if (insn & 0xFC000000) == 0x14000000:
                imm26 = insn & 0x3FFFFFF
                if imm26 & 0x2000000:
                    imm26 = imm26 - 0x4000000
                target = insn_vaddr + (imm26 << 2)
                
                # 如果目标在合理范围内，添加到待处理列表
                if func_start <= target <= func_start + max_size:
                    pending.append(target)
                break  # 基本块结束
            
            # B.cond - 条件跳转
            if (insn & 0xFF000010) == 0x54000000:
                imm19 = (insn >> 5) & 0x7FFFF
                if imm19 & 0x40000:
                    imm19 = imm19 - 0x80000
                target = insn_vaddr + (imm19 << 2)
                
                # 添加分支目标
                if func_start <= target <= func_start + max_size:
                    pending.append(target)
                # 继续线性扫描 (fall-through)
            
            # CBZ/CBNZ
            if (insn & 0x7E000000) == 0x34000000:
                imm19 = (insn >> 5) & 0x7FFFF
                if imm19 & 0x40000:
                    imm19 = imm19 - 0x80000
                target = insn_vaddr + (imm19 << 2)
                
                if func_start <= target <= func_start + max_size:
                    pending.append(target)
            
            # TBZ/TBNZ
            if (insn & 0x7E000000) == 0x36000000:
                imm14 = (insn >> 5) & 0x3FFF
                if imm14 & 0x2000:
                    imm14 = imm14 - 0x4000
                target = insn_vaddr + (imm14 << 2)
                
                if func_start <= target <= func_start + max_size:
                    pending.append(target)
            
            block_offset += 4
    
    # 返回函数大小：最大地址 - 函数开始 + 4 (最后一条指令的长度)
    return (max_addr - func_start) + 4


def xref_string_enhanced(so_path: str, search_string: str, max_xrefs: int = 20) -> dict:
    """
    增强版字符串交叉引用 - 返回函数上下文（IDA级功能）
    
    返回格式:
    {
        "xrefs": [
            {
                "virtual_address": "0x6e8658",
                "type": "adrp+add",
                "function": {
                    "name": "sub_6E8578",
                    "address": "0x6e8578",
                    "size": 488,
                    "offset_in_func": 224
                }
            }
        ]
    }
    """
    if not LIEF_AVAILABLE:
        return {"success": False, "xrefs": [], "error": "lief not available"}
    
    if not os.path.exists(so_path):
        return {"success": False, "xrefs": [], "error": f"File not found: {so_path}"}
    
    try:
        with open(so_path, 'rb') as f:
            data = f.read()
        
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "xrefs": [], "error": "Failed to parse SO file"}
        
        # 预扫描所有函数
        all_functions = _scan_all_functions(binary, data)
        
        # 1. 找到字符串位置
        search_bytes = search_string.encode('utf-8')
        string_file_offset = data.find(search_bytes)
        
        if string_file_offset == -1:
            return {"success": False, "xrefs": [], "error": f"String not found: {search_string}"}
        
        # 2. 计算字符串的虚拟地址
        string_vaddr = string_file_offset
        for section in binary.sections:
            if section.file_offset <= string_file_offset < section.file_offset + section.size:
                string_vaddr = section.virtual_address + (string_file_offset - section.file_offset)
                break
        
        # 3. 获取.text段
        text_section = None
        for section in binary.sections:
            if section.name == ".text":
                text_section = section
                break
        
        if not text_section:
            return {"success": False, "xrefs": [], "error": ".text section not found"}
        
        text_file_start = text_section.file_offset
        text_vaddr_base = text_section.virtual_address
        
        # 4. 搜索引用
        target_page = string_vaddr & ~0xFFF
        target_page_offset = string_vaddr & 0xFFF
        
        xrefs = []
        
        # 搜索 ADRP + ADD 模式
        for file_offset in range(text_file_start, min(text_file_start + text_section.size, len(data) - 8), 4):
            if len(xrefs) >= max_xrefs:
                break
            
            insn = struct.unpack('<I', data[file_offset:file_offset+4])[0]
            
            # ADRP 指令
            if (insn & 0x9F000000) == 0x90000000:
                immlo = (insn >> 29) & 0x3
                immhi = (insn >> 5) & 0x7FFFF
                imm = (immhi << 2) | immlo
                if imm & 0x100000:
                    imm = imm - 0x200000
                
                current_vaddr = text_vaddr_base + (file_offset - text_file_start)
                pc_page = current_vaddr & ~0xFFF
                adrp_target_page = (pc_page + (imm << 12)) & 0xFFFFFFFFFFFFFFFF
                
                if adrp_target_page == target_page:
                    # 检查后续 ADD 指令
                    next_insn = struct.unpack('<I', data[file_offset+4:file_offset+8])[0]
                    
                    if (next_insn & 0x7F800000) == 0x11000000 or (next_insn & 0xFF800000) == 0x91000000:
                        add_imm = (next_insn >> 10) & 0xFFF
                        
                        # 精确匹配目标地址（避免误报相邻字符串）
                        if add_imm == target_page_offset:
                            # 找到引用！精确查找函数开头
                            func_info = None
                            
                            # 方法1: 使用精确向后搜索找函数开头
                            precise_start = _find_precise_function_start(
                                data, text_file_start, text_vaddr_base, 
                                current_vaddr, max_search=0x200
                            )
                            
                            if precise_start:
                                # 找到精确的函数开头，精确计算函数大小
                                func_size = _find_precise_function_end(
                                    data, text_file_start, text_vaddr_base,
                                    precise_start, max_size=0x1000
                                )
                                
                                func_info = {
                                    "name": f"sub_{precise_start:X}",
                                    "address": hex(precise_start),
                                    "size": func_size,
                                    "end_address": hex(precise_start + func_size),
                                    "offset_in_func": current_vaddr - precise_start
                                }
                            else:
                                # 方法2: 从预扫描的函数列表查找
                                for func in all_functions:
                                    if func["address"] <= current_vaddr < func["address"] + func["size"]:
                                        func_info = {
                                            "name": func["name"],
                                            "address": hex(func["address"]),
                                            "size": func["size"],
                                            "end_address": hex(func["address"] + func["size"]),
                                            "offset_in_func": current_vaddr - func["address"]
                                        }
                                        break
                            
                            xrefs.append({
                                "file_offset": hex(file_offset),
                                "virtual_address": hex(current_vaddr),
                                "type": "adrp+add",
                                "target": hex(adrp_target_page + add_imm),
                                "function": func_info
                            })
        
        return {
            "success": True,
            "string": search_string,
            "string_vaddr": hex(string_vaddr),
            "xrefs": xrefs,
            "count": len(xrefs),
            "functions_scanned": len(all_functions),
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "xrefs": [], "error": f"{str(e)}\n{traceback.format_exc()}"}


def get_callers(so_path: str, func_address: int, limit: int = 50) -> dict:
    """
    获取调用指定函数的所有位置（IDA callers功能）
    
    Args:
        so_path: SO文件路径
        func_address: 目标函数地址
        limit: 最大返回数量
    
    Returns:
        dict: 调用者列表，每个包含函数上下文
    """
    if not LIEF_AVAILABLE:
        return {"success": False, "callers": [], "error": "lief not available"}
    
    if not os.path.exists(so_path):
        return {"success": False, "callers": [], "error": f"File not found: {so_path}"}
    
    try:
        with open(so_path, 'rb') as f:
            data = f.read()
        
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "callers": [], "error": "Failed to parse SO file"}
        
        # 预扫描函数
        all_functions = _scan_all_functions(binary, data)
        
        # 获取 .text 段
        text_section = None
        for section in binary.sections:
            if section.name == ".text":
                text_section = section
                break
        
        if not text_section:
            return {"success": False, "callers": [], "error": ".text section not found"}
        
        text_start = text_section.file_offset
        text_vaddr = text_section.virtual_address
        text_size = text_section.size
        
        callers = []
        
        # 搜索 BL 指令
        for offset in range(text_start, min(text_start + text_size, len(data) - 4), 4):
            if len(callers) >= limit:
                break
            
            insn = struct.unpack('<I', data[offset:offset+4])[0]
            
            # BL imm26: 100101 [imm26]
            if (insn & 0xFC000000) == 0x94000000:
                imm26 = insn & 0x3FFFFFF
                # 符号扩展
                if imm26 & 0x2000000:
                    imm26 = imm26 - 0x4000000
                
                current_vaddr = text_vaddr + (offset - text_start)
                target = current_vaddr + (imm26 << 2)
                
                if target == func_address:
                    # 找到调用者！查找所属函数
                    func_info = None
                    for func in all_functions:
                        if func["address"] <= current_vaddr < func["address"] + func["size"]:
                            func_info = {
                                "name": func["name"],
                                "address": hex(func["address"]),
                                "size": func["size"]
                            }
                            break
                    
                    callers.append({
                        "call_address": hex(current_vaddr),
                        "file_offset": hex(offset),
                        "type": "bl",
                        "function": func_info
                    })
        
        # 获取目标函数名
        target_name = f"sub_{func_address:X}"
        for func in all_functions:
            if func["address"] == func_address:
                target_name = func["name"]
                break
        
        return {
            "success": True,
            "target_function": {
                "name": target_name,
                "address": hex(func_address)
            },
            "callers": callers,
            "count": len(callers),
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "callers": [], "error": f"{str(e)}\n{traceback.format_exc()}"}


def get_callees(so_path: str, func_address: int, func_size: int = 0x1000) -> dict:
    """
    获取指定函数调用的所有函数（IDA callees功能）
    
    Args:
        so_path: SO文件路径
        func_address: 函数起始地址
        func_size: 函数大小（默认0x1000）
    
    Returns:
        dict: 被调用函数列表
    """
    if not LIEF_AVAILABLE:
        return {"success": False, "callees": [], "error": "lief not available"}
    
    if not os.path.exists(so_path):
        return {"success": False, "callees": [], "error": f"File not found: {so_path}"}
    
    try:
        with open(so_path, 'rb') as f:
            data = f.read()
        
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "callees": [], "error": "Failed to parse SO file"}
        
        # 预扫描函数
        all_functions = _scan_all_functions(binary, data)
        func_map = {f["address"]: f for f in all_functions}
        
        # 找到源函数
        source_func = None
        for func in all_functions:
            if func["address"] == func_address:
                source_func = func
                func_size = func["size"]
                break
        
        if not source_func:
            source_func = {"name": f"sub_{func_address:X}", "address": func_address}
        
        # 获取 .text 段信息
        text_section = None
        for section in binary.sections:
            if section.name == ".text":
                text_section = section
                break
        
        if not text_section:
            return {"success": False, "callees": [], "error": ".text section not found"}
        
        text_start = text_section.file_offset
        text_vaddr = text_section.virtual_address
        
        # 计算函数的文件偏移范围
        func_file_offset = text_start + (func_address - text_vaddr)
        
        callees = []
        seen_targets = set()
        
        # 在函数范围内搜索 BL 指令
        for offset in range(func_file_offset, min(func_file_offset + func_size, len(data) - 4), 4):
            insn = struct.unpack('<I', data[offset:offset+4])[0]
            
            # BL imm26
            if (insn & 0xFC000000) == 0x94000000:
                imm26 = insn & 0x3FFFFFF
                if imm26 & 0x2000000:
                    imm26 = imm26 - 0x4000000
                
                current_vaddr = text_vaddr + (offset - text_start)
                target = current_vaddr + (imm26 << 2)
                
                if target not in seen_targets:
                    seen_targets.add(target)
                    
                    # 查找目标函数信息
                    target_func = func_map.get(target, {
                        "name": f"sub_{target:X}",
                        "address": target
                    })
                    
                    callees.append({
                        "call_address": hex(current_vaddr),
                        "target_address": hex(target),
                        "target_function": {
                            "name": target_func.get("name", f"sub_{target:X}"),
                            "address": hex(target_func.get("address", target)),
                            "size": target_func.get("size", 0)
                        }
                    })
        
        return {
            "success": True,
            "source_function": {
                "name": source_func["name"],
                "address": hex(source_func["address"]),
                "size": func_size
            },
            "callees": callees,
            "count": len(callees),
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "callees": [], "error": f"{str(e)}\n{traceback.format_exc()}"}


def find_function_at(so_path: str, address: int) -> dict:
    """
    改进版函数查找 - 使用全函数扫描（修复 so_find_function 问题）
    
    Args:
        so_path: SO文件路径
        address: 目标地址
    
    Returns:
        dict: 函数信息
    """
    if not LIEF_AVAILABLE:
        return {"success": False, "function": None, "error": "lief not available"}
    
    if not os.path.exists(so_path):
        return {"success": False, "function": None, "error": f"File not found: {so_path}"}
    
    try:
        with open(so_path, 'rb') as f:
            data = f.read()
        
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "function": None, "error": "Failed to parse SO file"}
        
        # 预扫描所有函数
        all_functions = _scan_all_functions(binary, data)
        
        # 查找包含该地址的函数
        for func in all_functions:
            if func["address"] <= address < func["address"] + func["size"]:
                return {
                    "success": True,
                    "function": {
                        "name": func["name"],
                        "address": hex(func["address"]),
                        "size": func["size"],
                        "end_address": hex(func["address"] + func["size"]),
                        "type": func.get("type", "unknown"),
                        "offset_from_query": address - func["address"]
                    },
                    "query_address": hex(address),
                    "error": ""
                }
        
        return {
            "success": False,
            "function": None,
            "query_address": hex(address),
            "error": "Could not determine function boundaries"
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "function": None, "error": f"{str(e)}\n{traceback.format_exc()}"}
