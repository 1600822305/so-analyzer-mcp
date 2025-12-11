"""
Flutter SSL 验证函数定位工具 V2

模拟 IDA 分析流程:
1. 搜索 ssl_client 字符串
2. 通过 xrefs_to 找到引用代码
3. 向上追溯到函数开头
4. 生成 Frida Hook 脚本
"""
import os
import struct
from typing import Optional, Dict, List, Tuple

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


def find_ssl_verify_function_v2(so_path: str) -> dict:
    """
    使用 IDA 分析流程定位 Flutter SSL 验证函数
    
    流程:
    1. 搜索 "ssl_client" 字符串
    2. 查找交叉引用 (ADRP+ADD 指令)
    3. 从引用位置向上追溯函数开头
    4. 返回函数的虚拟地址
    
    Args:
        so_path: libflutter.so 文件路径
    
    Returns:
        dict: 包含函数地址和 Frida 脚本
    """
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
        
        result = {
            "success": False,
            "analysis_steps": [],
            "function_address": None,
            "frida_script": None,
            "error": ""
        }
        
        # ==================== Step 1: 搜索 ssl_client 字符串 ====================
        search_string = "ssl_client"
        search_bytes = search_string.encode('utf-8')
        string_file_offset = data.find(search_bytes)
        
        if string_file_offset == -1:
            result["error"] = "String 'ssl_client' not found"
            return result
        
        result["analysis_steps"].append({
            "step": 1,
            "action": "搜索字符串 'ssl_client'",
            "result": f"找到于文件偏移 0x{string_file_offset:x}"
        })
        
        # ==================== Step 2: 计算字符串虚拟地址 ====================
        string_vaddr = string_file_offset  # 默认
        
        for section in binary.sections:
            sec_start = section.file_offset
            sec_end = section.file_offset + section.size
            if sec_start <= string_file_offset < sec_end:
                offset_in_section = string_file_offset - sec_start
                string_vaddr = section.virtual_address + offset_in_section
                result["analysis_steps"].append({
                    "step": 2,
                    "action": "计算字符串虚拟地址",
                    "result": f"虚拟地址 0x{string_vaddr:x} (在 {section.name} 段)"
                })
                break
        
        # ==================== Step 3: 获取 .text 段信息 ====================
        text_section = None
        for section in binary.sections:
            if section.name == ".text":
                text_section = section
                break
        
        if text_section is None:
            result["error"] = ".text section not found"
            return result
        
        text_file_start = text_section.file_offset
        text_file_end = text_section.file_offset + text_section.size
        text_vaddr_base = text_section.virtual_address
        vaddr_to_file_offset = text_file_start - text_vaddr_base  # 负值用于转换
        
        result["analysis_steps"].append({
            "step": 3,
            "action": "获取 .text 段信息",
            "result": f"虚拟地址 0x{text_vaddr_base:x}, 文件偏移 0x{text_file_start:x}"
        })
        
        # ==================== Step 4: 搜索交叉引用 (ADRP+ADD) ====================
        target_page = string_vaddr & ~0xFFF
        target_page_offset = string_vaddr & 0xFFF
        
        xrefs = []
        
        for file_offset in range(text_file_start, min(text_file_end, len(data) - 8), 4):
            insn = struct.unpack('<I', data[file_offset:file_offset+4])[0]
            
            # ADRP 指令检查
            if (insn & 0x9F000000) == 0x90000000:
                # 提取立即数
                immlo = (insn >> 29) & 0x3
                immhi = (insn >> 5) & 0x7FFFF
                imm = (immhi << 2) | immlo
                
                # 符号扩展
                if imm & 0x100000:
                    imm = imm - 0x200000
                
                # 计算当前指令虚拟地址
                current_vaddr = text_vaddr_base + (file_offset - text_file_start)
                pc_page = current_vaddr & ~0xFFF
                adrp_target_page = (pc_page + (imm << 12)) & 0xFFFFFFFFFFFFFFFF
                
                # 检查是否指向目标页
                if adrp_target_page == target_page:
                    # 检查下一条 ADD 指令
                    next_insn = struct.unpack('<I', data[file_offset+4:file_offset+8])[0]
                    
                    # ADD immediate (32位或64位)
                    if (next_insn & 0x7F800000) == 0x11000000 or (next_insn & 0xFF800000) == 0x91000000:
                        add_imm = (next_insn >> 10) & 0xFFF
                        
                        if add_imm == target_page_offset:
                            xrefs.append({
                                "file_offset": file_offset,
                                "vaddr": current_vaddr
                            })
        
        if not xrefs:
            result["error"] = "No xrefs found for ssl_client"
            return result
        
        result["analysis_steps"].append({
            "step": 4,
            "action": f"搜索交叉引用 (xrefs_to 0x{string_vaddr:x})",
            "result": f"找到 {len(xrefs)} 个引用"
        })
        
        # ==================== Step 5: 分析所有候选函数 ====================
        candidates = []
        
        for i, xref in enumerate(xrefs):
            xref_file_offset = xref["file_offset"]
            xref_vaddr = xref["vaddr"]
            
            func_file_offset = find_function_start_arm64(data, text_file_start, xref_file_offset)
            
            if func_file_offset is None:
                continue
            
            # 计算函数虚拟地址
            func_vaddr = text_vaddr_base + (func_file_offset - text_file_start)
            
            # 估算函数大小
            func_size = estimate_function_size_arm64(data, func_file_offset, text_file_end)
            
            # 读取函数头部字节
            func_bytes = data[func_file_offset:func_file_offset+32]
            func_bytes_hex = ' '.join(f'{b:02x}' for b in func_bytes[:16])
            
            # 计算置信度
            confidence = 0.5
            
            # 函数大小评分 - SSL验证函数通常在300-800字节
            if 300 <= func_size <= 800:
                confidence += 0.4  # 最佳大小
            elif 200 < func_size < 1200:
                confidence += 0.2  # 可接受
            elif func_size < 200:
                confidence -= 0.3  # 太小，可能是辅助函数
            
            candidates.append({
                "index": i,
                "xref_vaddr": f"0x{xref_vaddr:x}",
                "function_vaddr": f"0x{func_vaddr:X}",
                "function_file_offset": f"0x{func_file_offset:x}",
                "function_size": func_size,
                "function_bytes": func_bytes_hex,
                "confidence": round(confidence, 2)
            })
        
        if not candidates:
            result["error"] = "Could not find any valid functions"
            return result
        
        # 按置信度排序
        candidates.sort(key=lambda x: -x["confidence"])
        
        result["candidates"] = candidates
        result["candidates_count"] = len(candidates)
        
        # 选择最佳候选
        best = candidates[0]
        func_vaddr = int(best["function_vaddr"], 16)
        
        result["analysis_steps"].append({
            "step": 5,
            "action": "分析所有候选函数并选择最佳",
            "result": f"找到 {len(candidates)} 个候选，选择 {best['function_vaddr']} (大小: {best['function_size']}字节, 置信度: {best['confidence']})"
        })
        
        # ==================== Step 6: 验证并生成脚本 ====================
        # 读取函数开头的字节作为验证
        func_bytes = data[func_file_offset:func_file_offset+32]
        func_bytes_hex = ' '.join(f'{b:02x}' for b in func_bytes)
        
        result["analysis_steps"].append({
            "step": 6,
            "action": "读取函数头部字节",
            "result": func_bytes_hex[:48] + "..."
        })
        
        # 生成 Frida 脚本 (使用标准模板)
        frida_script = f"""/**
 * Flutter SSL Bypass - 自动生成
 * 偏移: 0x{func_vaddr:X} (通过 so-analyzer-mcp 分析获得)
 */

function hook_ssl() {{
    var m = Module.findBaseAddress("libflutter.so");
    if (!m) {{
        setTimeout(hook_ssl, 500);
        return;
    }}
    
    var addr = m.add(0x{func_vaddr:X});
    console.log("[+] Hook @ " + addr);
    
    Interceptor.attach(addr, {{
        onLeave: function(ret) {{
            ret.replace(0x1);
            console.log("[√] SSL bypassed");
        }}
    }});
    
    console.log("[+] SSL Hook OK");
}}

Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {{
    onEnter: function(args) {{ this.n = args[0].readCString(); }},
    onLeave: function(r) {{ if (this.n && this.n.indexOf("libflutter.so") >= 0) hook_ssl(); }}
}});

hook_ssl();
"""
        
        # 自动保存脚本到文件
        script_saved = False
        script_path = None
        try:
            # 在 so 文件同目录创建脚本
            so_dir = os.path.dirname(so_path)
            script_filename = "flutter_ssl_bypass.js"
            script_path = os.path.join(so_dir, script_filename)
            
            with open(script_path, 'w', encoding='utf-8') as f:
                f.write(frida_script)
            
            script_saved = True
            result["script_saved_to"] = script_path
        except Exception as e:
            result["script_save_error"] = str(e)
        
        result["success"] = True
        result["function_address"] = f"0x{func_vaddr:X}"
        result["function_file_offset"] = f"0x{func_file_offset:x}"
        result["xref_address"] = f"0x{xref_vaddr:x}"
        result["string_address"] = f"0x{string_vaddr:x}"
        result["frida_script"] = frida_script
        
        return result
        
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}


def estimate_function_size_arm64(data: bytes, func_start: int, text_end: int) -> int:
    """估算 ARM64 函数大小"""
    max_search = min(func_start + 0x2000, text_end, len(data))
    
    for offset in range(func_start + 4, max_search, 4):
        if offset + 4 > len(data):
            break
        
        insn = struct.unpack('<I', data[offset:offset+4])[0]
        
        # RET 指令
        if insn == 0xD65F03C0:
            return offset - func_start + 4
        
        # 下一个函数开头
        if insn == 0xD503237F or (insn & 0xFFC003FF) == 0xA98003E0:
            if offset >= 4:
                prev_insn = struct.unpack('<I', data[offset-4:offset])[0]
                if prev_insn == 0xD65F03C0:
                    return offset - func_start
    
    return max_search - func_start


def find_function_start_arm64(data: bytes, text_start: int, ref_offset: int) -> Optional[int]:
    """
    从引用位置向上搜索 ARM64 函数开头
    
    ARM64 函数开头常见模式:
    1. PACIBSP (0xD503237F) - ARMv8.3 PAC 指令
    2. STP X29, X30, [SP, #imm]! - 保存帧指针和返回地址
    3. SUB SP, SP, #imm - 分配栈空间
    
    Args:
        data: 文件数据
        text_start: .text 段起始偏移
        ref_offset: 引用位置的文件偏移
    
    Returns:
        函数开头的文件偏移，找不到返回 None
    """
    # 向前搜索最多 4KB
    search_start = max(text_start, ref_offset - 4096)
    
    candidates = []
    
    for offset in range(ref_offset, search_start, -4):
        if offset < 4:
            break
        
        insn = struct.unpack('<I', data[offset:offset+4])[0]
        
        # 1. PACIBSP: 0xD503237F
        if insn == 0xD503237F:
            candidates.append((offset, "PACIBSP", 10))  # 高优先级
            continue
        
        # 2. SUB SP, SP, #imm (常见函数开头)
        # 编码: 1101_0001_00_xxxxxxxxxxxx_11111_11111
        if (insn & 0xFF0003FF) == 0xD10003FF:
            # 检查 imm 大小是否合理 (通常 0x10-0x200)
            imm = (insn >> 10) & 0xFFF
            if 0x10 <= imm <= 0x400:
                candidates.append((offset, "SUB SP", 8))
            continue
        
        # 3. STP X29, X30, [SP, #imm]!
        # 编码模式: 1010_1001_xx_xxxxxxx_11110_11101_11111
        if (insn & 0xFFC003FF) == 0xA98003E0:
            candidates.append((offset, "STP X29,X30", 9))
            continue
        
        # 4. STP 变体 (offset 模式)
        # STP X29, X30, [SP, #imm]
        if (insn & 0xFFC003FF) == 0xA90003E0:
            candidates.append((offset, "STP X29,X30 offset", 7))
            continue
    
    if not candidates:
        return None
    
    # 按优先级排序，返回最高优先级且最接近 ref_offset 的
    candidates.sort(key=lambda x: (-x[2], ref_offset - x[0]))
    
    return candidates[0][0]


def vaddr_to_file_offset(binary, vaddr: int) -> Optional[int]:
    """将虚拟地址转换为文件偏移"""
    for section in binary.sections:
        sec_vaddr_start = section.virtual_address
        sec_vaddr_end = section.virtual_address + section.size
        if sec_vaddr_start <= vaddr < sec_vaddr_end:
            offset_in_section = vaddr - sec_vaddr_start
            return section.file_offset + offset_in_section
    return None


def file_offset_to_vaddr(binary, file_offset: int) -> Optional[int]:
    """将文件偏移转换为虚拟地址"""
    for section in binary.sections:
        sec_file_start = section.file_offset
        sec_file_end = section.file_offset + section.size
        if sec_file_start <= file_offset < sec_file_end:
            offset_in_section = file_offset - sec_file_start
            return section.virtual_address + offset_in_section
    return None
