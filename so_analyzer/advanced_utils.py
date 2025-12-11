"""高级分析工具 - 函数识别、调用图、控制流图"""
import os
import struct
from typing import Optional, List, Dict, Set, Tuple
from collections import defaultdict

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    from capstone.arm64 import ARM64_OP_IMM, ARM64_GRP_CALL, ARM64_GRP_JUMP, ARM64_GRP_RET, ARM64_GRP_BRANCH_RELATIVE
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


# ARM64 函数开头特征
FUNCTION_PROLOGUE_PATTERNS = [
    # PACIBSP - PAC指令 (常见于新版本)
    (0xD503237F, 0xFFFFFFFF, "pacibsp"),
    # STP X29, X30, [SP, #imm]! - 常见函数开头
    (0xA98003E0, 0xFFC003FF, "stp x29, x30"),
    # SUB SP, SP, #imm (64位)
    (0xD10003FF, 0xFF0003FF, "sub sp, sp"),
    # STP with pre-index (通用)
    (0xA9800000, 0xFFC00000, "stp pre-index"),
]

# ARM64 函数结尾特征
FUNCTION_EPILOGUE_PATTERNS = [
    # RET
    (0xD65F03C0, 0xFFFFFFFF, "ret"),
    # RETAB/RETAA (PAC)
    (0xD65F0FFF, 0xFFFFFFFF, "retab"),
    (0xD65F0BFF, 0xFFFFFFFF, "retaa"),
]


def list_all_functions(so_path: str, limit: int = 2000, search: str = "") -> dict:
    """
    识别所有函数（包括未导出的）
    
    方法:
    1. 扫描 .text 段
    2. 识别函数开头模式 (STP X29,X30 / SUB SP,SP / PACIBSP)
    3. 估算函数大小
    4. 与导出函数合并
    
    Args:
        so_path: SO文件路径
        limit: 最大返回数量
        search: 搜索过滤（用于导出函数名）
    
    Returns:
        dict: {"success": bool, "functions": list, "error": str}
    """
    if not LIEF_AVAILABLE:
        return {"success": False, "functions": [], "error": "lief not available"}
    
    if not os.path.exists(so_path):
        return {"success": False, "functions": [], "error": f"File not found: {so_path}"}
    
    try:
        with open(so_path, 'rb') as f:
            data = f.read()
        
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "functions": [], "error": "Failed to parse SO file"}
        
        # 1. 获取 .text 段信息
        text_section = None
        for section in binary.sections:
            if section.name == ".text":
                text_section = section
                break
        
        if text_section is None:
            return {"success": False, "functions": [], "error": ".text section not found"}
        
        text_file_start = text_section.file_offset
        text_file_end = text_section.file_offset + text_section.size
        text_vaddr_base = text_section.virtual_address
        
        # 2. 收集导出函数信息
        exported_funcs = {}  # vaddr -> name
        for func in binary.exported_functions:
            if hasattr(func, 'address') and hasattr(func, 'name'):
                exported_funcs[func.address] = func.name
        
        # 3. 扫描 .text 段识别函数开头
        functions = []
        found_addrs = set()
        
        for file_offset in range(text_file_start, min(text_file_end, len(data) - 4), 4):
            insn = struct.unpack('<I', data[file_offset:file_offset+4])[0]
            
            # 检查是否匹配函数开头模式
            for pattern, mask, desc in FUNCTION_PROLOGUE_PATTERNS:
                if (insn & mask) == pattern:
                    # 计算虚拟地址
                    vaddr = text_vaddr_base + (file_offset - text_file_start)
                    
                    if vaddr in found_addrs:
                        continue
                    found_addrs.add(vaddr)
                    
                    # 检查是否是导出函数
                    is_exported = vaddr in exported_funcs
                    name = exported_funcs.get(vaddr, f"sub_{vaddr:x}")
                    
                    # 搜索过滤
                    if search and search.lower() not in name.lower():
                        continue
                    
                    # 估算函数大小
                    func_size = _estimate_function_size(data, file_offset, text_file_end)
                    
                    functions.append({
                        "address": hex(vaddr),
                        "file_offset": hex(file_offset),
                        "size": func_size,
                        "is_exported": is_exported,
                        "name": name,
                        "prologue_type": desc
                    })
                    
                    if len(functions) >= limit:
                        break
                    break
            
            if len(functions) >= limit:
                break
        
        # 4. 添加导出但未被扫描到的函数
        for vaddr, name in exported_funcs.items():
            if vaddr not in found_addrs:
                if search and search.lower() not in name.lower():
                    continue
                
                # 计算文件偏移
                if text_vaddr_base <= vaddr < text_vaddr_base + text_section.size:
                    file_offset = text_file_start + (vaddr - text_vaddr_base)
                    func_size = _estimate_function_size(data, file_offset, text_file_end)
                else:
                    file_offset = 0
                    func_size = 0
                
                functions.append({
                    "address": hex(vaddr),
                    "file_offset": hex(file_offset) if file_offset else "unknown",
                    "size": func_size,
                    "is_exported": True,
                    "name": name,
                    "prologue_type": "exported"
                })
                
                if len(functions) >= limit:
                    break
        
        # 按地址排序
        functions.sort(key=lambda x: int(x["address"], 16))
        
        return {
            "success": True,
            "functions": functions,
            "total_count": len(functions),
            "exported_count": sum(1 for f in functions if f["is_exported"]),
            "internal_count": sum(1 for f in functions if not f["is_exported"]),
            "text_section": {
                "vaddr": hex(text_vaddr_base),
                "size": text_section.size,
                "file_offset": hex(text_file_start)
            },
            "error": ""
        }
    except Exception as e:
        import traceback
        return {"success": False, "functions": [], "error": f"{str(e)}\n{traceback.format_exc()}"}


def _estimate_function_size(data: bytes, func_start: int, text_end: int) -> int:
    """估算函数大小"""
    max_search = min(func_start + 0x10000, text_end, len(data) - 4)  # 最多64KB
    
    for offset in range(func_start + 4, max_search, 4):
        insn = struct.unpack('<I', data[offset:offset+4])[0]
        
        # RET指令
        if insn == 0xD65F03C0:
            return offset - func_start + 4
        
        # RETAB/RETAA
        if insn in (0xD65F0FFF, 0xD65F0BFF):
            return offset - func_start + 4
        
        # 遇到下一个函数开头
        for pattern, mask, _ in FUNCTION_PROLOGUE_PATTERNS:
            if (insn & mask) == pattern:
                # 检查前一条指令是否是RET或NOP
                if offset >= 4:
                    prev_insn = struct.unpack('<I', data[offset-4:offset])[0]
                    if prev_insn == 0xD65F03C0 or prev_insn == 0xD503201F:
                        return offset - func_start
    
    return min(0x1000, max_search - func_start)  # 默认4KB


def callgraph(so_path: str, function_addr: int, max_depth: int = 3) -> dict:
    """
    分析函数调用关系
    
    方法:
    1. 反汇编函数
    2. 识别 BL/BLR 指令
    3. 递归分析被调用的函数
    
    Args:
        so_path: SO文件路径
        function_addr: 函数地址（虚拟地址）
        max_depth: 最大递归深度
    
    Returns:
        dict: {"success": bool, "calls": list, "graph": str, "error": str}
    """
    if not LIEF_AVAILABLE or not CAPSTONE_AVAILABLE:
        return {"success": False, "calls": [], "graph": "", 
                "error": "lief and capstone required"}
    
    if not os.path.exists(so_path):
        return {"success": False, "calls": [], "graph": "", 
                "error": f"File not found: {so_path}"}
    
    try:
        with open(so_path, 'rb') as f:
            data = f.read()
        
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "calls": [], "graph": "", 
                    "error": "Failed to parse SO file"}
        
        # 获取 .text 段信息
        text_section = None
        for section in binary.sections:
            if section.name == ".text":
                text_section = section
                break
        
        if text_section is None:
            return {"success": False, "calls": [], "graph": "", 
                    "error": ".text section not found"}
        
        text_file_start = text_section.file_offset
        text_vaddr_base = text_section.virtual_address
        text_size = text_section.size
        
        # 收集导出函数名
        exported_funcs = {}
        for func in binary.exported_functions:
            if hasattr(func, 'address') and hasattr(func, 'name'):
                exported_funcs[func.address] = func.name
        
        # 初始化反汇编器
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        
        # BFS遍历调用图
        calls = []
        visited = set()
        queue = [(function_addr, 0)]  # (addr, depth)
        nodes = set()
        edges = []
        
        def get_func_name(addr):
            return exported_funcs.get(addr, f"sub_{addr:x}")
        
        while queue:
            current_addr, depth = queue.pop(0)
            
            if current_addr in visited or depth > max_depth:
                continue
            visited.add(current_addr)
            nodes.add(current_addr)
            
            # 计算文件偏移
            if not (text_vaddr_base <= current_addr < text_vaddr_base + text_size):
                continue
            
            file_offset = text_file_start + (current_addr - text_vaddr_base)
            
            # 估算函数大小
            func_size = _estimate_function_size(data, file_offset, 
                                                text_file_start + text_size)
            func_size = min(func_size, 0x4000)  # 限制16KB
            
            if file_offset + func_size > len(data):
                continue
            
            code = bytes(data[file_offset:file_offset + func_size])
            
            # 反汇编并查找调用
            try:
                for insn in md.disasm(code, current_addr):
                    # BL指令 (直接调用)
                    if insn.mnemonic == "bl":
                        # 解析目标地址
                        if insn.operands and len(insn.operands) > 0:
                            target = insn.operands[0].imm
                            
                            call_info = {
                                "from": hex(current_addr),
                                "from_name": get_func_name(current_addr),
                                "call_site": hex(insn.address),
                                "to": hex(target),
                                "to_name": get_func_name(target),
                                "type": "direct",
                                "depth": depth
                            }
                            calls.append(call_info)
                            edges.append((current_addr, target))
                            
                            if target not in visited and depth < max_depth:
                                queue.append((target, depth + 1))
                    
                    # BLR指令 (间接调用)
                    elif insn.mnemonic == "blr":
                        call_info = {
                            "from": hex(current_addr),
                            "from_name": get_func_name(current_addr),
                            "call_site": hex(insn.address),
                            "to": "indirect",
                            "to_name": f"[{insn.op_str}]",
                            "type": "indirect",
                            "depth": depth
                        }
                        calls.append(call_info)
            except Exception:
                pass
        
        # 生成DOT格式图
        dot_lines = ["digraph callgraph {", "    rankdir=TB;", 
                     "    node [shape=box];"]
        
        for addr in nodes:
            name = get_func_name(addr)
            is_root = addr == function_addr
            style = 'style=filled,fillcolor=lightblue' if is_root else ''
            dot_lines.append(f'    "{name}" [{style}];')
        
        for from_addr, to_addr in edges:
            from_name = get_func_name(from_addr)
            to_name = get_func_name(to_addr)
            dot_lines.append(f'    "{from_name}" -> "{to_name}";')
        
        dot_lines.append("}")
        dot_graph = "\n".join(dot_lines)
        
        return {
            "success": True,
            "root": hex(function_addr),
            "root_name": get_func_name(function_addr),
            "calls": calls,
            "nodes_count": len(nodes),
            "edges_count": len(edges),
            "graph": dot_graph,
            "error": ""
        }
    except Exception as e:
        import traceback
        return {"success": False, "calls": [], "graph": "", 
                "error": f"{str(e)}\n{traceback.format_exc()}"}


def get_cfg(so_path: str, function_addr: int, max_size: int = 0x2000) -> dict:
    """
    生成函数的控制流图 (CFG)
    
    Args:
        so_path: SO文件路径
        function_addr: 函数地址（虚拟地址）
        max_size: 最大分析字节数
    
    Returns:
        dict: {"success": bool, "basic_blocks": list, "edges": list, "graph": str}
    """
    if not LIEF_AVAILABLE or not CAPSTONE_AVAILABLE:
        return {"success": False, "basic_blocks": [], "edges": [], "graph": "",
                "error": "lief and capstone required"}
    
    if not os.path.exists(so_path):
        return {"success": False, "basic_blocks": [], "edges": [], "graph": "",
                "error": f"File not found: {so_path}"}
    
    try:
        with open(so_path, 'rb') as f:
            data = f.read()
        
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "basic_blocks": [], "edges": [], "graph": "",
                    "error": "Failed to parse SO file"}
        
        # 获取 .text 段
        text_section = None
        for section in binary.sections:
            if section.name == ".text":
                text_section = section
                break
        
        if text_section is None:
            return {"success": False, "basic_blocks": [], "edges": [], "graph": "",
                    "error": ".text section not found"}
        
        text_file_start = text_section.file_offset
        text_vaddr_base = text_section.virtual_address
        text_size = text_section.size
        
        # 计算文件偏移
        if not (text_vaddr_base <= function_addr < text_vaddr_base + text_size):
            return {"success": False, "basic_blocks": [], "edges": [], "graph": "",
                    "error": f"Address {hex(function_addr)} not in .text section"}
        
        file_offset = text_file_start + (function_addr - text_vaddr_base)
        
        # 估算函数大小
        func_size = _estimate_function_size(data, file_offset, text_file_start + text_size)
        func_size = min(func_size, max_size)
        
        code = bytes(data[file_offset:file_offset + func_size])
        
        # 反汇编
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        
        # 识别基本块边界
        # 基本块结束于: 分支指令、跳转指令、RET
        # 基本块开始于: 函数入口、分支目标
        
        instructions = list(md.disasm(code, function_addr))
        if not instructions:
            return {"success": False, "basic_blocks": [], "edges": [], "graph": "",
                    "error": "Failed to disassemble function"}
        
        # 收集所有基本块起始地址
        block_starts = {function_addr}  # 函数入口
        branch_targets = {}  # addr -> list of targets
        
        branch_mnemonics = {'b', 'bl', 'br', 'blr', 'ret', 'b.eq', 'b.ne', 'b.lt', 
                           'b.le', 'b.gt', 'b.ge', 'b.hi', 'b.lo', 'b.hs', 'b.ls',
                           'cbz', 'cbnz', 'tbz', 'tbnz'}
        
        for insn in instructions:
            mnemonic_lower = insn.mnemonic.lower()
            
            if mnemonic_lower in branch_mnemonics or mnemonic_lower.startswith('b.'):
                # 下一条指令是新基本块的开始
                next_addr = insn.address + insn.size
                if next_addr < function_addr + func_size:
                    block_starts.add(next_addr)
                
                # 获取跳转目标
                targets = []
                if insn.operands:
                    for op in insn.operands:
                        if hasattr(op, 'imm') and op.imm:
                            target = op.imm
                            if function_addr <= target < function_addr + func_size:
                                block_starts.add(target)
                                targets.append(target)
                
                branch_targets[insn.address] = {
                    "mnemonic": insn.mnemonic,
                    "targets": targets,
                    "is_conditional": mnemonic_lower.startswith('b.') or mnemonic_lower in {'cbz', 'cbnz', 'tbz', 'tbnz'}
                }
        
        # 构建基本块
        sorted_starts = sorted(block_starts)
        basic_blocks = []
        edges = []
        
        for i, block_start in enumerate(sorted_starts):
            # 找到块结束
            block_end = sorted_starts[i + 1] if i + 1 < len(sorted_starts) else function_addr + func_size
            
            # 收集块内指令
            block_insns = []
            last_insn = None
            for insn in instructions:
                if block_start <= insn.address < block_end:
                    block_insns.append({
                        "address": hex(insn.address),
                        "mnemonic": insn.mnemonic,
                        "operands": insn.op_str
                    })
                    last_insn = insn
            
            if not block_insns:
                continue
            
            block = {
                "id": f"bb_{block_start:x}",
                "start": hex(block_start),
                "end": hex(block_end),
                "size": block_end - block_start,
                "instruction_count": len(block_insns),
                "instructions": block_insns[:10],  # 只显示前10条
                "is_entry": block_start == function_addr
            }
            basic_blocks.append(block)
            
            # 添加边
            if last_insn and last_insn.address in branch_targets:
                bt = branch_targets[last_insn.address]
                for target in bt["targets"]:
                    edges.append({
                        "from": f"bb_{block_start:x}",
                        "to": f"bb_{target:x}",
                        "type": "conditional" if bt["is_conditional"] else "unconditional"
                    })
                
                # 条件分支有fall-through
                if bt["is_conditional"]:
                    next_addr = last_insn.address + last_insn.size
                    if next_addr in block_starts:
                        edges.append({
                            "from": f"bb_{block_start:x}",
                            "to": f"bb_{next_addr:x}",
                            "type": "fall-through"
                        })
            else:
                # 顺序执行到下一个块
                if i + 1 < len(sorted_starts):
                    edges.append({
                        "from": f"bb_{block_start:x}",
                        "to": f"bb_{sorted_starts[i+1]:x}",
                        "type": "fall-through"
                    })
        
        # 生成DOT图
        dot_lines = ["digraph cfg {", "    rankdir=TB;", "    node [shape=box,fontname=Courier];"]
        
        for block in basic_blocks:
            label = f"{block['id']}\\n{block['instruction_count']} insns"
            style = 'style=filled,fillcolor=lightgreen' if block['is_entry'] else ''
            dot_lines.append(f'    "{block["id"]}" [label="{label}" {style}];')
        
        for edge in edges:
            style = 'style=dashed' if edge['type'] == 'conditional' else ''
            color = 'color=red' if edge['type'] == 'conditional' else 'color=blue' if edge['type'] == 'fall-through' else ''
            dot_lines.append(f'    "{edge["from"]}" -> "{edge["to"]}" [{style} {color}];')
        
        dot_lines.append("}")
        dot_graph = "\n".join(dot_lines)
        
        return {
            "success": True,
            "function_address": hex(function_addr),
            "function_size": func_size,
            "basic_blocks": basic_blocks,
            "block_count": len(basic_blocks),
            "edges": edges,
            "edge_count": len(edges),
            "graph": dot_graph,
            "error": ""
        }
    except Exception as e:
        import traceback
        return {"success": False, "basic_blocks": [], "edges": [], "graph": "",
                "error": f"{str(e)}\n{traceback.format_exc()}"}


def analyze_function_advanced(so_path: str, function_address: int, size: int = 512) -> dict:
    """
    全面分析函数特征
    
    分析内容:
    1. 识别函数调用 (BL/BLR)
    2. 识别系统调用 (SVC)
    3. 识别字符串引用
    4. 识别常量使用
    5. 估算复杂度
    6. 判断函数类型 (SSL/加密/网络等)
    
    Args:
        so_path: SO文件路径
        function_address: 函数虚拟地址
        size: 分析的字节数
    
    Returns:
        dict: 详细分析结果
    """
    if not LIEF_AVAILABLE or not CAPSTONE_AVAILABLE:
        return {"success": False, "analysis": {}, 
                "error": "lief and capstone required"}
    
    if not os.path.exists(so_path):
        return {"success": False, "analysis": {}, 
                "error": f"File not found: {so_path}"}
    
    try:
        with open(so_path, 'rb') as f:
            data = f.read()
        
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "analysis": {}, 
                    "error": "Failed to parse SO file"}
        
        # 获取段信息
        text_section = None
        for section in binary.sections:
            if section.name == ".text":
                text_section = section
                break
        
        if text_section is None:
            return {"success": False, "analysis": {}, 
                    "error": ".text section not found"}
        
        text_file_start = text_section.file_offset
        text_vaddr_base = text_section.virtual_address
        
        # 计算文件偏移
        file_offset = text_file_start + (function_address - text_vaddr_base)
        
        # 获取导出函数映射
        exported_funcs = {}
        for func in binary.exported_functions:
            if hasattr(func, 'address') and hasattr(func, 'name'):
                exported_funcs[func.address] = func.name
        
        # 读取函数代码
        func_size = min(size, len(data) - file_offset)
        code = bytes(data[file_offset:file_offset + func_size])
        
        # 反汇编
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        
        instructions = list(md.disasm(code, function_address))
        
        analysis = {
            "address": hex(function_address),
            "file_offset": hex(file_offset),
            "size_analyzed": func_size,
            "instruction_count": len(instructions),
            "calls": [],
            "indirect_calls": [],
            "syscalls": [],
            "string_refs": [],
            "constants": [],
            "branches": 0,
            "loops_detected": False,
            "complexity": "low",
            "likely_type": "unknown",
            "ssl_indicators": [],
            "crypto_indicators": []
        }
        
        # 分析每条指令
        backward_branches = 0
        adrp_targets = {}  # 用于跟踪ADRP加载的地址
        
        for insn in instructions:
            mnemonic = insn.mnemonic.lower()
            
            # 1. 函数调用
            if mnemonic == "bl":
                if insn.operands:
                    target = insn.operands[0].imm
                    name = exported_funcs.get(target, f"sub_{target:x}")
                    analysis["calls"].append({
                        "address": hex(insn.address),
                        "target": hex(target),
                        "name": name
                    })
                    
                    # 检查SSL相关调用
                    name_lower = name.lower()
                    if any(kw in name_lower for kw in ['ssl', 'tls', 'cert', 'x509', 'verify']):
                        analysis["ssl_indicators"].append(name)
                    if any(kw in name_lower for kw in ['aes', 'sha', 'md5', 'hmac', 'encrypt', 'decrypt']):
                        analysis["crypto_indicators"].append(name)
            
            elif mnemonic == "blr":
                analysis["indirect_calls"].append({
                    "address": hex(insn.address),
                    "register": insn.op_str
                })
            
            # 2. 系统调用
            elif mnemonic == "svc":
                if insn.operands:
                    syscall_num = insn.operands[0].imm
                    analysis["syscalls"].append({
                        "address": hex(insn.address),
                        "number": syscall_num
                    })
            
            # 3. ADRP指令 (用于字符串引用)
            elif mnemonic == "adrp":
                if insn.operands and len(insn.operands) >= 2:
                    reg = insn.op_str.split(',')[0].strip()
                    target = insn.operands[1].imm
                    adrp_targets[reg] = target
            
            # 4. ADD指令 (配合ADRP)
            elif mnemonic == "add" and insn.op_str:
                parts = insn.op_str.split(',')
                if len(parts) >= 3:
                    src_reg = parts[1].strip()
                    if src_reg in adrp_targets and insn.operands:
                        base = adrp_targets[src_reg]
                        offset = insn.operands[2].imm if len(insn.operands) > 2 else 0
                        full_addr = base + offset
                        
                        # 尝试在该地址找字符串
                        if 0 < full_addr < len(data):
                            # 简单读取字符串
                            str_bytes = []
                            for i in range(min(64, len(data) - full_addr)):
                                b = data[full_addr + i]
                                if b == 0:
                                    break
                                if 32 <= b < 127:
                                    str_bytes.append(chr(b))
                                else:
                                    break
                            
                            if len(str_bytes) >= 4:
                                string = ''.join(str_bytes)
                                analysis["string_refs"].append({
                                    "address": hex(insn.address),
                                    "string_addr": hex(full_addr),
                                    "value": string[:50]
                                })
                                
                                # 检查SSL相关字符串
                                str_lower = string.lower()
                                if any(kw in str_lower for kw in ['ssl', 'cert', 'verify', 'x509', 'tls']):
                                    analysis["ssl_indicators"].append(string[:30])
            
            # 5. 分支指令
            if mnemonic.startswith('b') and mnemonic not in ['bl', 'blr', 'br']:
                analysis["branches"] += 1
                
                # 检查是否是向后跳转（可能是循环）
                if insn.operands:
                    target = insn.operands[0].imm if hasattr(insn.operands[0], 'imm') else 0
                    if target < insn.address:
                        backward_branches += 1
            
            # 6. 常量加载
            if mnemonic in ['mov', 'movz', 'movk']:
                if insn.operands and len(insn.operands) >= 2:
                    if hasattr(insn.operands[1], 'imm'):
                        imm = insn.operands[1].imm
                        if imm > 0xFF:  # 只记录较大的常量
                            analysis["constants"].append({
                                "address": hex(insn.address),
                                "value": hex(imm)
                            })
        
        # 计算复杂度
        analysis["loops_detected"] = backward_branches > 0
        
        total_complexity = (
            len(analysis["calls"]) * 2 +
            len(analysis["indirect_calls"]) * 3 +
            analysis["branches"] +
            backward_branches * 2
        )
        
        if total_complexity < 10:
            analysis["complexity"] = "low"
        elif total_complexity < 30:
            analysis["complexity"] = "medium"
        else:
            analysis["complexity"] = "high"
        
        # 判断函数类型
        ssl_score = len(analysis["ssl_indicators"])
        crypto_score = len(analysis["crypto_indicators"])
        
        if ssl_score >= 2:
            analysis["likely_type"] = "ssl_verify"
        elif crypto_score >= 2:
            analysis["likely_type"] = "crypto"
        elif len(analysis["syscalls"]) >= 2:
            analysis["likely_type"] = "system"
        elif len(analysis["string_refs"]) >= 3:
            analysis["likely_type"] = "string_processing"
        else:
            analysis["likely_type"] = "general"
        
        return {
            "success": True,
            "analysis": analysis,
            "error": ""
        }
    except Exception as e:
        import traceback
        return {"success": False, "analysis": {}, 
                "error": f"{str(e)}\n{traceback.format_exc()}"}


def detect_string_encryption(so_path: str, min_length: int = 8, max_strings: int = 100) -> dict:
    """
    检测字符串是否被加密/混淆
    
    方法:
    1. 分析字符串熵值（高熵 = 可能加密）
    2. 检查是否有解密函数特征
    3. 识别常见加密算法特征（XOR、Base64等）
    4. 检查字符串分布异常
    
    Args:
        so_path: SO文件路径
        min_length: 最小字符串长度
        max_strings: 最大分析字符串数
    
    Returns:
        dict: {"success": bool, "encrypted_strings": list, "decryption_hints": list}
    """
    import math
    
    if not LIEF_AVAILABLE:
        return {"success": False, "error": "lief not available"}
    
    if not os.path.exists(so_path):
        return {"success": False, "error": f"File not found: {so_path}"}
    
    try:
        with open(so_path, 'rb') as f:
            data = f.read()
        
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "error": "Failed to parse SO file"}
        
        def calculate_entropy(s: bytes) -> float:
            """计算字节序列的熵"""
            if len(s) == 0:
                return 0
            freq = {}
            for b in s:
                freq[b] = freq.get(b, 0) + 1
            entropy = 0
            for count in freq.values():
                p = count / len(s)
                entropy -= p * math.log2(p)
            return entropy
        
        def is_printable_ratio(s: bytes) -> float:
            """计算可打印字符比例"""
            printable = sum(1 for b in s if 32 <= b < 127)
            return printable / len(s) if len(s) > 0 else 0
        
        def detect_xor_pattern(s: bytes) -> Optional[int]:
            """检测简单XOR加密"""
            # 尝试常见的XOR键
            for key in range(1, 256):
                decoded = bytes(b ^ key for b in s)
                if is_printable_ratio(decoded) > 0.8:
                    return key
            return None
        
        def is_base64_like(s: bytes) -> bool:
            """检测是否像Base64编码"""
            b64_chars = set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
            return all(b in b64_chars for b in s) and len(s) % 4 == 0
        
        # 提取字符串
        strings = []
        current = []
        current_start = 0
        
        for i, b in enumerate(data):
            if 32 <= b < 127:
                if not current:
                    current_start = i
                current.append(b)
            else:
                if len(current) >= min_length:
                    strings.append({
                        "offset": current_start,
                        "data": bytes(current),
                        "text": bytes(current).decode('ascii', errors='ignore')
                    })
                current = []
            
            if len(strings) >= max_strings * 2:  # 收集更多用于分析
                break
        
        # 分析字符串
        normal_strings = []
        suspicious_strings = []
        encrypted_candidates = []
        
        for s in strings:
            entropy = calculate_entropy(s["data"])
            printable_ratio = is_printable_ratio(s["data"])
            
            s["entropy"] = round(entropy, 2)
            s["printable_ratio"] = round(printable_ratio, 2)
            
            # 高熵字符串（可能是加密或压缩数据）
            if entropy > 5.5 and len(s["data"]) > 16:
                s["suspicious_reason"] = "high_entropy"
                
                # 检查XOR加密
                xor_key = detect_xor_pattern(s["data"])
                if xor_key:
                    s["possible_xor_key"] = xor_key
                    s["xor_decoded"] = bytes(b ^ xor_key for b in s["data"]).decode('ascii', errors='ignore')[:50]
                
                # 检查Base64
                if is_base64_like(s["data"]):
                    s["possible_encoding"] = "base64"
                    try:
                        import base64
                        decoded = base64.b64decode(s["data"])
                        s["base64_decoded"] = decoded[:50].hex()
                    except:
                        pass
                
                encrypted_candidates.append({
                    "offset": hex(s["offset"]),
                    "text": s["text"][:50],
                    "entropy": s["entropy"],
                    "length": len(s["data"]),
                    "details": {k: v for k, v in s.items() 
                               if k not in ["offset", "data", "text"]}
                })
            
            # 看起来像编码的字符串
            elif is_base64_like(s["data"]) and len(s["data"]) > 20:
                suspicious_strings.append({
                    "offset": hex(s["offset"]),
                    "text": s["text"][:50],
                    "reason": "base64_like"
                })
            
            else:
                normal_strings.append(s)
        
        # 检查解密函数特征
        decryption_hints = []
        
        # 搜索常见加密/解密相关符号
        crypto_symbols = [
            b"decrypt", b"Decrypt", b"DECRYPT",
            b"encode", b"Encode", b"decode", b"Decode",
            b"cipher", b"Cipher",
            b"xor", b"XOR",
            b"base64", b"Base64",
            b"AES", b"aes",
            b"RC4", b"rc4",
        ]
        
        for symbol in crypto_symbols:
            if symbol in data:
                pos = data.find(symbol)
                decryption_hints.append({
                    "symbol": symbol.decode('ascii'),
                    "offset": hex(pos)
                })
        
        # 检查导出函数
        for func in binary.exported_functions:
            name = func.name if hasattr(func, 'name') else ""
            name_lower = name.lower()
            if any(kw in name_lower for kw in ['decrypt', 'encode', 'decode', 'cipher', 'xor']):
                decryption_hints.append({
                    "function": name,
                    "address": hex(func.address) if hasattr(func, 'address') else "unknown"
                })
        
        # 统计分析
        all_entropies = [calculate_entropy(s["data"]) for s in strings[:100]]
        avg_entropy = sum(all_entropies) / len(all_entropies) if all_entropies else 0
        
        # 判断是否有字符串加密
        encryption_detected = len(encrypted_candidates) > 5 or avg_entropy > 5.0
        
        return {
            "success": True,
            "encryption_detected": encryption_detected,
            "encrypted_candidates": encrypted_candidates[:20],
            "suspicious_strings": suspicious_strings[:10],
            "decryption_hints": decryption_hints[:10],
            "statistics": {
                "total_strings_analyzed": len(strings),
                "average_entropy": round(avg_entropy, 2),
                "high_entropy_count": len(encrypted_candidates),
                "suspicious_count": len(suspicious_strings)
            },
            "note": "High entropy (>5.5) may indicate encryption, compression, or binary data",
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}


def trace_register_value(so_path: str, function_addr: int, 
                         target_register: str = "x0", size: int = 512) -> dict:
    """
    追踪寄存器值的来源（数据流分析）
    
    分析函数内指定寄存器的值从哪里来，用于理解参数传递和返回值
    
    Args:
        so_path: SO文件路径
        function_addr: 函数虚拟地址
        target_register: 目标寄存器（默认x0，即返回值/第一个参数）
        size: 分析字节数
    
    Returns:
        dict: {"success": bool, "register": str, "sources": list, "data_flow": list}
    """
    if not LIEF_AVAILABLE or not CAPSTONE_AVAILABLE:
        return {"success": False, "error": "lief and capstone required"}
    
    if not os.path.exists(so_path):
        return {"success": False, "error": f"File not found: {so_path}"}
    
    try:
        with open(so_path, 'rb') as f:
            data = f.read()
        
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "error": "Failed to parse SO file"}
        
        # 获取段信息
        text_section = None
        for section in binary.sections:
            if section.name == ".text":
                text_section = section
                break
        
        if text_section is None:
            return {"success": False, "error": ".text section not found"}
        
        text_file_start = text_section.file_offset
        text_vaddr_base = text_section.virtual_address
        
        file_offset = text_file_start + (function_addr - text_vaddr_base)
        code = bytes(data[file_offset:file_offset + size])
        
        # 反汇编
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        
        instructions = list(md.disasm(code, function_addr))
        
        # 规范化寄存器名
        target_reg = target_register.lower().strip()
        # 处理 w0/x0 等同
        reg_variants = {target_reg}
        if target_reg.startswith('x'):
            reg_variants.add('w' + target_reg[1:])
        elif target_reg.startswith('w'):
            reg_variants.add('x' + target_reg[1:])
        
        # 追踪数据流
        data_flow = []
        sources = []
        
        # 寄存器依赖图
        reg_deps = defaultdict(list)  # reg -> [(addr, source_type, source)]
        
        for insn in instructions:
            mnemonic = insn.mnemonic.lower()
            ops = insn.op_str.lower()
            addr = insn.address
            
            # 解析操作数
            parts = [p.strip() for p in ops.split(',')]
            
            # 检查是否写入目标寄存器
            writes_target = False
            if parts:
                dst = parts[0]
                if any(v in dst for v in reg_variants):
                    writes_target = True
            
            if not writes_target:
                continue
            
            flow_entry = {
                "address": hex(addr),
                "instruction": f"{insn.mnemonic} {ops}",
                "operation": "",
                "source": ""
            }
            
            # MOV指令
            if mnemonic == "mov":
                if len(parts) >= 2:
                    flow_entry["operation"] = "assign"
                    flow_entry["source"] = parts[1]
                    sources.append({
                        "address": hex(addr),
                        "type": "register_copy",
                        "from": parts[1]
                    })
            
            # MOVZ/MOVK - 立即数加载
            elif mnemonic in ["movz", "movk"]:
                if len(parts) >= 2:
                    flow_entry["operation"] = "load_immediate"
                    flow_entry["source"] = ','.join(parts[1:])
                    sources.append({
                        "address": hex(addr),
                        "type": "immediate",
                        "value": parts[1] if len(parts) > 1 else ""
                    })
            
            # LDR - 内存加载
            elif mnemonic == "ldr":
                if len(parts) >= 2:
                    flow_entry["operation"] = "load_memory"
                    flow_entry["source"] = parts[1]
                    sources.append({
                        "address": hex(addr),
                        "type": "memory_load",
                        "from": parts[1]
                    })
            
            # ADD/SUB - 算术运算
            elif mnemonic in ["add", "sub"]:
                if len(parts) >= 3:
                    flow_entry["operation"] = mnemonic
                    flow_entry["source"] = f"{parts[1]} {mnemonic} {parts[2]}"
                    sources.append({
                        "address": hex(addr),
                        "type": "arithmetic",
                        "operation": mnemonic,
                        "operands": parts[1:]
                    })
            
            # ADRP - 页地址加载
            elif mnemonic == "adrp":
                if len(parts) >= 2:
                    flow_entry["operation"] = "load_page_address"
                    flow_entry["source"] = parts[1]
                    sources.append({
                        "address": hex(addr),
                        "type": "address_load",
                        "page": parts[1]
                    })
            
            # 其他指令
            else:
                flow_entry["operation"] = mnemonic
                flow_entry["source"] = ','.join(parts[1:]) if len(parts) > 1 else ""
            
            data_flow.append(flow_entry)
        
        # 分析返回值
        return_value_info = None
        for i, insn in enumerate(reversed(instructions)):
            if insn.mnemonic.lower() == "ret":
                # 查找ret之前对x0/w0的最后一次赋值
                for j in range(len(instructions) - 1 - i - 1, -1, -1):
                    prev = instructions[j]
                    if prev.mnemonic.lower() in ["mov", "movz", "ldr", "add"]:
                        parts = prev.op_str.lower().split(',')
                        if parts and any(v in parts[0] for v in ['x0', 'w0']):
                            return_value_info = {
                                "address": hex(prev.address),
                                "instruction": f"{prev.mnemonic} {prev.op_str}",
                                "note": "Last assignment before RET"
                            }
                            break
                break
        
        return {
            "success": True,
            "register": target_register,
            "register_variants": list(reg_variants),
            "data_flow": data_flow,
            "sources": sources,
            "source_count": len(sources),
            "return_value": return_value_info,
            "instruction_count": len(instructions),
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}


# ============ 指令模式搜索 ============

# 预定义的常用搜索模式
COMMON_PATTERNS = {
    # 系统调用
    "syscall": {"mnemonic": "svc", "description": "系统调用"},
    "svc": {"mnemonic": "svc", "description": "系统调用"},
    
    # 函数调用
    "call": {"mnemonic": "bl", "description": "直接函数调用"},
    "bl": {"mnemonic": "bl", "description": "直接函数调用"},
    "blr": {"mnemonic": "blr", "description": "间接函数调用(寄存器)"},
    
    # 返回
    "ret": {"mnemonic": "ret", "description": "函数返回"},
    "return": {"mnemonic": "ret", "description": "函数返回"},
    
    # 内存操作
    "load": {"mnemonic_regex": r"^ld[rbp]?", "description": "加载指令"},
    "store": {"mnemonic_regex": r"^st[rbp]?", "description": "存储指令"},
    "ldr": {"mnemonic": "ldr", "description": "加载寄存器"},
    "str": {"mnemonic": "str", "description": "存储寄存器"},
    
    # 比较和分支
    "compare": {"mnemonic_regex": r"^(cmp|cmn|tst)", "description": "比较指令"},
    "cmp": {"mnemonic": "cmp", "description": "比较"},
    "branch": {"mnemonic_regex": r"^b\.", "description": "条件分支"},
    "cbz": {"mnemonic": "cbz", "description": "为零跳转"},
    "cbnz": {"mnemonic": "cbnz", "description": "非零跳转"},
    
    # 算术运算
    "add": {"mnemonic": "add", "description": "加法"},
    "sub": {"mnemonic": "sub", "description": "减法"},
    "mul": {"mnemonic": "mul", "description": "乘法"},
    
    # 逻辑运算
    "and": {"mnemonic": "and", "description": "与操作"},
    "or": {"mnemonic_regex": r"^orr?", "description": "或操作"},
    "xor": {"mnemonic": "eor", "description": "异或操作"},
    "eor": {"mnemonic": "eor", "description": "异或操作"},
    
    # 移位
    "shift": {"mnemonic_regex": r"^(lsl|lsr|asr|ror)", "description": "移位操作"},
    
    # 加密相关模式
    "aes": {"mnemonic_regex": r"^aes", "description": "AES加密指令"},
    "sha": {"mnemonic_regex": r"^sha", "description": "SHA哈希指令"},
    
    # SIMD/NEON
    "neon": {"mnemonic_regex": r"^(ld[1-4]|st[1-4]|fmla|fmul|fadd)", "description": "NEON/SIMD指令"},
}


def find_instruction_pattern(so_path: str, pattern: str, 
                             operand_filter: str = "",
                             limit: int = 100,
                             section: str = ".text") -> dict:
    """
    搜索指令模式
    
    支持的模式格式:
    1. 简单指令名: "bl", "svc", "ret"
    2. 预定义模式: "syscall", "call", "compare", "xor"
    3. 正则表达式: "b\\..*" (条件分支), "ld[rbp].*" (加载指令)
    4. 指令序列: "stp;mov;bl" (用分号分隔)
    5. 带操作数过滤: pattern="bl", operand_filter="#0x" (调用特定范围)
    
    Args:
        so_path: SO文件路径
        pattern: 搜索模式
        operand_filter: 操作数过滤（可选，支持正则）
        limit: 最大返回数量
        section: 搜索的段（默认.text）
    
    Returns:
        dict: {
            "success": bool,
            "matches": [{address, mnemonic, operands, context}],
            "count": int,
            "pattern_info": str
        }
    """
    import re
    
    if not LIEF_AVAILABLE:
        return {"success": False, "error": "lief not available"}
    
    if not CAPSTONE_AVAILABLE:
        return {"success": False, "error": "capstone not available"}
    
    if not os.path.exists(so_path):
        return {"success": False, "error": f"File not found: {so_path}"}
    
    try:
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "error": "Failed to parse binary"}
        
        # 查找目标段
        target_section = None
        for sec in binary.sections:
            if sec.name == section:
                target_section = sec
                break
        
        if not target_section:
            # 尝试使用 .text 或可执行段
            for sec in binary.sections:
                if sec.has_characteristic(lief.ELF.Section.FLAGS.EXECINSTR):
                    target_section = sec
                    break
        
        if not target_section:
            return {"success": False, "error": f"Section {section} not found"}
        
        # 获取段数据
        section_data = bytes(target_section.content)
        section_vaddr = target_section.virtual_address
        
        # 初始化反汇编器
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        
        # 解析搜索模式
        pattern_info = ""
        patterns_to_match = []
        is_sequence = ";" in pattern
        
        if is_sequence:
            # 指令序列搜索
            seq_parts = [p.strip().lower() for p in pattern.split(";") if p.strip()]
            patterns_to_match = seq_parts
            pattern_info = f"Instruction sequence: {' -> '.join(seq_parts)}"
        elif pattern.lower() in COMMON_PATTERNS:
            # 预定义模式
            preset = COMMON_PATTERNS[pattern.lower()]
            if "mnemonic" in preset:
                patterns_to_match = [{"type": "exact", "value": preset["mnemonic"]}]
            elif "mnemonic_regex" in preset:
                patterns_to_match = [{"type": "regex", "value": preset["mnemonic_regex"]}]
            pattern_info = f"Preset pattern: {preset['description']}"
        else:
            # 自定义模式（可能是正则）
            if any(c in pattern for c in r".*+?[](){}|^$\\"):
                patterns_to_match = [{"type": "regex", "value": pattern}]
                pattern_info = f"Regex pattern: {pattern}"
            else:
                patterns_to_match = [{"type": "exact", "value": pattern.lower()}]
                pattern_info = f"Exact match: {pattern}"
        
        # 编译操作数过滤正则
        operand_regex = None
        if operand_filter:
            try:
                operand_regex = re.compile(operand_filter, re.IGNORECASE)
            except:
                operand_regex = re.compile(re.escape(operand_filter), re.IGNORECASE)
        
        # 反汇编整个段
        instructions = list(md.disasm(section_data, section_vaddr))
        
        matches = []
        
        if is_sequence:
            # 序列匹配
            seq_len = len(patterns_to_match)
            i = 0
            while i < len(instructions) - seq_len + 1 and len(matches) < limit:
                match = True
                matched_insns = []
                
                for j, pattern_item in enumerate(patterns_to_match):
                    insn = instructions[i + j]
                    mnem = insn.mnemonic.lower()
                    
                    if isinstance(pattern_item, str):
                        # 简单字符串匹配
                        if pattern_item not in mnem and not re.match(pattern_item, mnem):
                            match = False
                            break
                    matched_insns.append(insn)
                
                if match:
                    # 检查操作数过滤
                    if operand_regex:
                        ops_str = " ".join(ins.op_str for ins in matched_insns)
                        if not operand_regex.search(ops_str):
                            i += 1
                            continue
                    
                    # 获取上下文
                    context_before = []
                    context_after = []
                    
                    for k in range(max(0, i-2), i):
                        ctx_insn = instructions[k]
                        context_before.append({
                            "address": hex(ctx_insn.address),
                            "instruction": f"{ctx_insn.mnemonic} {ctx_insn.op_str}"
                        })
                    
                    for k in range(i + seq_len, min(len(instructions), i + seq_len + 2)):
                        ctx_insn = instructions[k]
                        context_after.append({
                            "address": hex(ctx_insn.address),
                            "instruction": f"{ctx_insn.mnemonic} {ctx_insn.op_str}"
                        })
                    
                    matches.append({
                        "address": hex(matched_insns[0].address),
                        "file_offset": hex(matched_insns[0].address - section_vaddr + target_section.offset),
                        "sequence": [
                            {
                                "address": hex(ins.address),
                                "mnemonic": ins.mnemonic,
                                "operands": ins.op_str
                            }
                            for ins in matched_insns
                        ],
                        "context_before": context_before,
                        "context_after": context_after
                    })
                    i += seq_len  # 跳过匹配的序列
                else:
                    i += 1
        else:
            # 单指令匹配
            for i, insn in enumerate(instructions):
                if len(matches) >= limit:
                    break
                
                mnem = insn.mnemonic.lower()
                matched = False
                
                for pattern_item in patterns_to_match:
                    if isinstance(pattern_item, dict):
                        if pattern_item["type"] == "exact":
                            matched = mnem == pattern_item["value"]
                        elif pattern_item["type"] == "regex":
                            matched = bool(re.match(pattern_item["value"], mnem, re.IGNORECASE))
                    else:
                        matched = mnem == pattern_item.lower()
                    
                    if matched:
                        break
                
                if not matched:
                    continue
                
                # 检查操作数过滤
                if operand_regex and not operand_regex.search(insn.op_str):
                    continue
                
                # 获取上下文
                context_before = []
                context_after = []
                
                for k in range(max(0, i-3), i):
                    ctx_insn = instructions[k]
                    context_before.append({
                        "address": hex(ctx_insn.address),
                        "instruction": f"{ctx_insn.mnemonic} {ctx_insn.op_str}"
                    })
                
                for k in range(i+1, min(len(instructions), i+4)):
                    ctx_insn = instructions[k]
                    context_after.append({
                        "address": hex(ctx_insn.address),
                        "instruction": f"{ctx_insn.mnemonic} {ctx_insn.op_str}"
                    })
                
                # 解析特殊信息
                extra_info = {}
                
                # 对于 BL 指令，解析目标地址
                if mnem == "bl":
                    try:
                        parts = insn.op_str.split("#")
                        if len(parts) > 1:
                            target_addr = int(parts[1].strip(), 16)
                            extra_info["target_address"] = hex(target_addr)
                            # 尝试找到目标函数名
                            for sym in binary.exported_symbols:
                                if sym.value == target_addr:
                                    extra_info["target_name"] = sym.name
                                    break
                    except:
                        pass
                
                # 对于 SVC 指令，解析系统调用号
                if mnem == "svc":
                    try:
                        parts = insn.op_str.split("#")
                        if len(parts) > 1:
                            syscall_num = int(parts[1].strip(), 16)
                            extra_info["syscall_number"] = syscall_num
                            # 常见 ARM64 Linux 系统调用
                            SYSCALL_NAMES = {
                                0: "io_setup", 56: "openat", 57: "close",
                                63: "read", 64: "write", 78: "readlinkat",
                                93: "exit", 94: "exit_group",
                                172: "getpid", 220: "clone", 221: "execve",
                                226: "mprotect", 278: "getrandom"
                            }
                            if syscall_num in SYSCALL_NAMES:
                                extra_info["syscall_name"] = SYSCALL_NAMES[syscall_num]
                    except:
                        pass
                
                matches.append({
                    "address": hex(insn.address),
                    "file_offset": hex(insn.address - section_vaddr + target_section.offset),
                    "mnemonic": insn.mnemonic,
                    "operands": insn.op_str,
                    "bytes": insn.bytes.hex(),
                    "context_before": context_before,
                    "context_after": context_after,
                    **extra_info
                })
        
        # 统计信息
        stats = {
            "total_instructions": len(instructions),
            "section_size": len(section_data),
            "section_start": hex(section_vaddr)
        }
        
        return {
            "success": True,
            "pattern": pattern,
            "pattern_info": pattern_info,
            "operand_filter": operand_filter if operand_filter else None,
            "matches": matches,
            "count": len(matches),
            "truncated": len(matches) >= limit,
            "stats": stats,
            "available_presets": list(COMMON_PATTERNS.keys()),
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}
