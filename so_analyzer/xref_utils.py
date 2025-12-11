"""交叉引用分析工具"""
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


def get_code_sections(so_path: str) -> dict:
    """
    获取所有代码段信息
    
    Args:
        so_path: SO文件路径
    
    Returns:
        dict: {"success": bool, "sections": list, "error": str}
    """
    if not LIEF_AVAILABLE:
        return {"success": False, "sections": [], "error": "lief not available"}
    
    if not os.path.exists(so_path):
        return {"success": False, "sections": [], "error": f"File not found: {so_path}"}
    
    try:
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "sections": [], "error": "Failed to parse SO file"}
        
        sections = []
        for section in binary.sections:
            # 检查是否可执行 - 多种方法判断
            is_exec = False
            
            # 方法1: 通过flags判断
            try:
                # EXECINSTR = 0x4
                if hasattr(section, 'flags'):
                    flags_value = int(section.flags)
                    is_exec = bool(flags_value & 0x4)  # SHF_EXECINSTR = 0x4
            except:
                pass
            
            # 方法2: 通过段名判断（备用）
            if not is_exec and section.name in [".text", ".plt", ".init", ".fini"]:
                is_exec = True
            
            sections.append({
                "name": section.name,
                "start": hex(section.virtual_address),
                "end": hex(section.virtual_address + section.size),
                "file_offset": hex(section.file_offset),
                "size": section.size,
                "is_executable": is_exec,
                "flags": hex(int(section.flags)) if hasattr(section, 'flags') else "0x0"
            })
        
        # 找出可执行段
        exec_sections = [s for s in sections if s["is_executable"]]
        
        return {
            "success": True,
            "sections": sections,
            "executable_sections": exec_sections,
            "error": ""
        }
    except Exception as e:
        import traceback
        return {"success": False, "sections": [], "error": f"{str(e)}\n{traceback.format_exc()}"}


def find_string_offset(so_path: str, search_string: str) -> dict:
    """
    查找字符串在文件中的偏移
    
    Args:
        so_path: SO文件路径
        search_string: 要搜索的字符串
    
    Returns:
        dict: {"success": bool, "offsets": list, "error": str}
    """
    if not os.path.exists(so_path):
        return {"success": False, "offsets": [], "error": f"File not found: {so_path}"}
    
    try:
        with open(so_path, 'rb') as f:
            data = f.read()
        
        search_bytes = search_string.encode('utf-8')
        offsets = []
        
        start = 0
        while True:
            pos = data.find(search_bytes, start)
            if pos == -1:
                break
            offsets.append({
                "offset": pos,
                "hex_offset": hex(pos),
                "context": data[max(0, pos-10):pos+len(search_bytes)+10]
            })
            start = pos + 1
            
            if len(offsets) >= 10:  # 限制数量
                break
        
        return {
            "success": True,
            "string": search_string,
            "offsets": offsets,
            "count": len(offsets),
            "error": ""
        }
    except Exception as e:
        return {"success": False, "offsets": [], "error": str(e)}


def xref_string(so_path: str, search_string: str, max_xrefs: int = 20) -> dict:
    """
    查找字符串的交叉引用（哪些代码引用了这个字符串）
    
    这是定位SSL验证函数的核心工具！
    
    Args:
        so_path: SO文件路径
        search_string: 要搜索的字符串
        max_xrefs: 最多返回的交叉引用数量
    
    Returns:
        dict: {"success": bool, "xrefs": list, "error": str}
    """
    if not LIEF_AVAILABLE:
        return {"success": False, "xrefs": [], "error": "lief not available"}
    
    if not os.path.exists(so_path):
        return {"success": False, "xrefs": [], "error": f"File not found: {so_path}"}
    
    # 使用新的搜索算法
    return xref_string_v2(so_path, search_string, max_xrefs)


def xref_string_v2(so_path: str, search_string: str, max_xrefs: int = 20) -> dict:
    """
    改进版交叉引用搜索 - 考虑虚拟地址映射
    """
    if not LIEF_AVAILABLE:
        return {"success": False, "xrefs": [], "error": "lief not available"}
    
    try:
        with open(so_path, 'rb') as f:
            data = f.read()
        
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "xrefs": [], "error": "Failed to parse SO file"}
        
        debug_info = {
            "file_size": len(data),
            "sections": [],
            "search_stats": {}
        }
        
        # 1. 找到字符串的文件偏移
        search_bytes = search_string.encode('utf-8')
        string_file_offset = data.find(search_bytes)
        
        if string_file_offset == -1:
            return {"success": False, "xrefs": [], "error": f"String not found: {search_string}"}
        
        # 2. 建立文件偏移到虚拟地址的映射
        # 找到字符串所在的段，获取其虚拟地址
        string_vaddr = string_file_offset  # 默认
        
        for section in binary.sections:
            sec_start = section.file_offset
            sec_end = section.file_offset + section.size
            if sec_start <= string_file_offset < sec_end:
                # 计算虚拟地址
                offset_in_section = string_file_offset - sec_start
                string_vaddr = section.virtual_address + offset_in_section
                debug_info["string_section"] = {
                    "name": section.name,
                    "file_offset": hex(sec_start),
                    "virtual_address": hex(section.virtual_address)
                }
                break
        
        debug_info["string_file_offset"] = hex(string_file_offset)
        debug_info["string_vaddr"] = hex(string_vaddr)
        
        # 3. 获取.text段信息
        text_section = None
        for section in binary.sections:
            debug_info["sections"].append({
                "name": section.name,
                "file_offset": hex(section.file_offset),
                "vaddr": hex(section.virtual_address),
                "size": section.size
            })
            if section.name == ".text":
                text_section = section
        
        if text_section is None:
            return {"success": False, "xrefs": [], "debug": debug_info, "error": ".text section not found"}
        
        text_file_start = text_section.file_offset
        text_file_end = text_section.file_offset + text_section.size
        text_vaddr_base = text_section.virtual_address
        
        debug_info["text_section"] = {
            "file_start": hex(text_file_start),
            "file_end": hex(text_file_end),
            "vaddr_base": hex(text_vaddr_base),
            "size": text_section.size
        }
        
        # 4. 计算目标页地址
        target_page = string_vaddr & ~0xFFF
        target_page_offset = string_vaddr & 0xFFF
        
        debug_info["target_page"] = hex(target_page)
        debug_info["target_page_offset"] = hex(target_page_offset)
        
        xrefs = []
        adrp_found = 0
        adrp_page_match = 0
        adrp_samples = []  # 采样前20个ADRP指令的解析结果
        unique_target_pages = set()  # 收集所有目标页面
        
        # 5. 在.text段中搜索ADRP指令
        for file_offset in range(text_file_start, min(text_file_end, len(data) - 8), 4):
            if len(xrefs) >= max_xrefs:
                break
            
            insn = struct.unpack('<I', data[file_offset:file_offset+4])[0]
            
            # ADRP指令: [1] [immlo:2] [10000] [immhi:19] [Rd:5]
            # 检查是否是ADRP (op=1, 识别码 10010000)
            if (insn & 0x9F000000) == 0x90000000:
                adrp_found += 1
                
                # 提取立即数
                immlo = (insn >> 29) & 0x3
                immhi = (insn >> 5) & 0x7FFFF
                imm = (immhi << 2) | immlo
                
                # 符号扩展 (21位有符号数)
                if imm & 0x100000:
                    imm = imm - 0x200000  # 正确的符号扩展
                
                # 计算当前指令的虚拟地址
                offset_in_text = file_offset - text_file_start
                current_vaddr = text_vaddr_base + offset_in_text
                
                # 计算ADRP的目标页 (PC & ~0xFFF + imm << 12)
                pc_page = current_vaddr & ~0xFFF
                adrp_target_page = (pc_page + (imm << 12)) & 0xFFFFFFFFFFFFFFFF
                
                # 收集目标页面用于调试
                if len(unique_target_pages) < 1000:
                    unique_target_pages.add(adrp_target_page)
                
                # 采样前20个ADRP指令
                if len(adrp_samples) < 20:
                    adrp_samples.append({
                        "file_offset": hex(file_offset),
                        "vaddr": hex(current_vaddr),
                        "instruction": hex(insn),
                        "imm_raw": hex(imm & 0x1FFFFF),
                        "pc_page": hex(pc_page),
                        "target_page": hex(adrp_target_page)
                    })
                
                # 检查是否指向目标页
                if adrp_target_page == target_page:
                    adrp_page_match += 1
                    
                    # 检查后续ADD指令
                    next_insn = struct.unpack('<I', data[file_offset+4:file_offset+8])[0]
                    
                    # ADD immediate: [sf:1] [00] [100010] [sh:1] [imm12:12] [Rn:5] [Rd:5]
                    # 32位: 0x11000000, 64位: 0x91000000
                    if (next_insn & 0x7F800000) == 0x11000000 or (next_insn & 0xFF800000) == 0x91000000:
                        add_imm = (next_insn >> 10) & 0xFFF
                        
                        # 检查ADD的目标是否匹配（允许一定误差）
                        if abs(add_imm - target_page_offset) <= 0x10:
                            xrefs.append({
                                "file_offset": hex(file_offset),
                                "virtual_address": hex(current_vaddr),
                                "type": "adrp+add",
                                "adrp_target_page": hex(adrp_target_page),
                                "add_offset": hex(add_imm),
                                "full_target": hex(adrp_target_page + add_imm),
                                "instruction_bytes": data[file_offset:file_offset+8].hex()
                            })
        
        # 检查目标页面是否在唯一页面集合中
        target_in_pages = target_page in unique_target_pages
        
        # 找到最接近目标页面的页面
        closest_pages = []
        if unique_target_pages:
            sorted_pages = sorted(unique_target_pages, key=lambda p: abs(p - target_page))
            closest_pages = [hex(p) for p in sorted_pages[:10]]
        
        debug_info["search_stats"] = {
            "adrp_instructions_found": adrp_found,
            "adrp_page_matches": adrp_page_match,
            "xrefs_found": len(xrefs),
            "unique_target_pages_count": len(unique_target_pages),
            "target_page_found_in_adrps": target_in_pages
        }
        debug_info["adrp_samples"] = adrp_samples
        debug_info["closest_pages_to_target"] = closest_pages
        
        # 6. 如果没找到，也尝试搜索LDR模式
        if len(xrefs) == 0:
            # 搜索包含目标地址的数据引用
            # 有些编译器会在.got或.data段放置地址
            string_vaddr_bytes = struct.pack('<Q', string_vaddr)
            
            pos = 0
            while len(xrefs) < max_xrefs:
                pos = data.find(string_vaddr_bytes[:4], pos)  # 只搜索低32位
                if pos == -1:
                    break
                # 检查是否是完整的64位地址
                if data[pos:pos+8] == string_vaddr_bytes or data[pos:pos+4] == string_vaddr_bytes[:4]:
                    xrefs.append({
                        "file_offset": hex(pos),
                        "type": "direct_pointer",
                        "value": data[pos:pos+8].hex()
                    })
                pos += 1
        
        return {
            "success": True,
            "string": search_string,
            "string_file_offset": hex(string_file_offset),
            "string_vaddr": hex(string_vaddr),
            "xrefs": xrefs,
            "count": len(xrefs),
            "debug": debug_info,
            "error": ""
        }
    except Exception as e:
        import traceback
        return {"success": False, "xrefs": [], "error": f"{str(e)}\n{traceback.format_exc()}"}


def find_function_containing_address(binary, data: bytes, address: int) -> Optional[dict]:
    """
    根据地址找到所属的函数
    
    通过向前搜索函数开头特征来找函数边界
    """
    if not LIEF_AVAILABLE:
        return None
    
    try:
        # 首先检查是否在已知的导出函数中
        for func in binary.exported_functions:
            func_addr = func.address if hasattr(func, 'address') else 0
            # 假设函数大小最大4096字节
            if func_addr <= address < func_addr + 4096:
                return {
                    "name": func.name if hasattr(func, 'name') else "unknown",
                    "start": hex(func_addr)
                }
        
        # 向前搜索函数开头特征
        # ARM64函数常见开头: stp x29, x30, [sp, #-N]! 或 sub sp, sp, #N
        search_start = max(0, address - 4096)
        
        for offset in range(address, search_start, -4):
            if offset < 4:
                break
            insn = struct.unpack('<I', data[offset:offset+4])[0]
            
            # 检查是否是stp x29, x30 (常见的函数开头)
            # stp x29, x30, [sp, #imm]! 的编码特征
            if (insn & 0xFFC003FF) == 0xA98003E0:
                return {
                    "name": "sub_" + hex(offset)[2:],
                    "start": hex(offset)
                }
            
            # 检查 pacibsp (ARM64 PAC)
            if insn == 0xD503237F:
                return {
                    "name": "sub_" + hex(offset)[2:],
                    "start": hex(offset)
                }
        
        return None
    except:
        return None


def find_function_by_address(so_path: str, address: int) -> dict:
    """
    根据地址查找函数信息
    
    Args:
        so_path: SO文件路径
        address: 地址
    
    Returns:
        dict: {"success": bool, "function": dict, "error": str}
    """
    if not LIEF_AVAILABLE:
        return {"success": False, "function": {}, "error": "lief not available"}
    
    if not os.path.exists(so_path):
        return {"success": False, "function": {}, "error": f"File not found: {so_path}"}
    
    try:
        with open(so_path, 'rb') as f:
            data = f.read()
        
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "function": {}, "error": "Failed to parse SO file"}
        
        func_info = find_function_containing_address(binary, data, address)
        
        if func_info:
            return {
                "success": True,
                "function": func_info,
                "query_address": hex(address),
                "error": ""
            }
        else:
            return {
                "success": False,
                "function": {},
                "query_address": hex(address),
                "error": "Could not determine function boundaries"
            }
    except Exception as e:
        return {"success": False, "function": {}, "error": str(e)}


def analyze_function(so_path: str, function_address: int, size: int = 256) -> dict:
    """
    分析函数特征，判断是否是SSL验证函数
    
    Args:
        so_path: SO文件路径
        function_address: 函数地址
        size: 分析的字节数
    
    Returns:
        dict: {"success": bool, "analysis": dict, "error": str}
    """
    if not os.path.exists(so_path):
        return {"success": False, "analysis": {}, "error": f"File not found: {so_path}"}
    
    try:
        with open(so_path, 'rb') as f:
            data = f.read()
        
        if function_address < 0 or function_address + size > len(data):
            return {"success": False, "analysis": {}, "error": "Invalid address range"}
        
        func_data = data[function_address:function_address + size]
        
        analysis = {
            "address": hex(function_address),
            "size_analyzed": size,
            "strings_nearby": [],
            "call_instructions": [],
            "return_instructions": [],
            "is_ssl_verify": False,
            "ssl_confidence": 0.0
        }
        
        # 搜索附近的字符串引用
        ssl_keywords = [
            b"ssl", b"SSL", b"cert", b"CERT", b"verify", b"VERIFY",
            b"x509", b"X509", b"certificate", b"CERTIFICATE"
        ]
        
        ssl_score = 0
        for keyword in ssl_keywords:
            # 在函数附近搜索
            search_start = max(0, function_address - 10000)
            search_end = min(len(data), function_address + 10000)
            search_range = data[search_start:search_end]
            
            if keyword in search_range:
                ssl_score += 1
                analysis["strings_nearby"].append(keyword.decode('utf-8', errors='ignore'))
        
        # 检查是否有CERTIFICATE_VERIFY_FAILED字符串引用
        if b"CERTIFICATE_VERIFY_FAILED" in data:
            cert_offset = data.find(b"CERTIFICATE_VERIFY_FAILED")
            # 检查函数是否引用了这个字符串
            cert_page = cert_offset & ~0xFFF
            func_page = function_address & ~0xFFF
            page_diff = abs(cert_page - func_page)
            if page_diff < 0x100000:  # 1MB范围内
                ssl_score += 5
                analysis["references_cert_verify_failed"] = True
        
        # 计算置信度
        analysis["ssl_confidence"] = min(ssl_score / 10.0, 1.0)
        analysis["is_ssl_verify"] = analysis["ssl_confidence"] > 0.5
        
        # 反汇编前几条指令
        if CAPSTONE_AVAILABLE:
            try:
                md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
                instructions = []
                for insn in md.disasm(func_data[:64], function_address):
                    instructions.append({
                        "address": hex(insn.address),
                        "mnemonic": insn.mnemonic,
                        "operands": insn.op_str,
                        "bytes": insn.bytes.hex()
                    })
                    if len(instructions) >= 10:
                        break
                analysis["first_instructions"] = instructions
            except:
                pass
        
        return {
            "success": True,
            "analysis": analysis,
            "error": ""
        }
    except Exception as e:
        return {"success": False, "analysis": {}, "error": str(e)}
