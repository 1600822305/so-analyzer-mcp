"""ELF分析工具 - 入口点和全局变量分析"""
import os
import struct
from typing import Optional, List, Dict

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


def get_entrypoints(so_path: str) -> dict:
    """
    获取SO文件的所有入口点（类似IDA Pro的entrypoints功能）
    
    包含:
    1. ELF Entry Point - 主入口点
    2. _init / _fini - 初始化/终止函数
    3. .init_array / .fini_array - 构造/析构函数数组
    4. DT_INIT / DT_FINI - 动态链接初始化
    5. JNI_OnLoad - Android JNI入口（如果存在）
    
    Args:
        so_path: SO文件路径
    
    Returns:
        dict: {
            "success": bool,
            "entrypoints": [
                {"name": str, "address": str, "type": str, "description": str}
            ],
            "summary": dict
        }
    """
    if not LIEF_AVAILABLE:
        return {"success": False, "entrypoints": [], "error": "lief not available"}
    
    if not os.path.exists(so_path):
        return {"success": False, "entrypoints": [], "error": f"File not found: {so_path}"}
    
    try:
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "entrypoints": [], "error": "Failed to parse SO file"}
        
        entrypoints = []
        
        # 1. ELF Header Entry Point
        header_entry = binary.header.entrypoint
        if header_entry != 0:
            entrypoints.append({
                "name": "_start",
                "address": hex(header_entry),
                "type": "elf_entry",
                "description": "ELF Header Entry Point (e_entry)",
                "file_offset": hex(header_entry - binary.imagebase) if binary.imagebase else hex(header_entry)
            })
        
        # 2. 从导出函数中查找特殊入口
        special_entries = {
            "_init": "Initialization function (.init)",
            "_fini": "Finalization function (.fini)", 
            "__libc_csu_init": "libc constructor initialization",
            "__libc_csu_fini": "libc destructor finalization",
            "JNI_OnLoad": "Android JNI entry point",
            "JNI_OnUnload": "Android JNI unload",
            "_Z10JNI_OnLoadP7_JavaVMPv": "JNI_OnLoad (mangled)",
        }
        
        exported_funcs = {}
        for func in binary.exported_functions:
            if hasattr(func, 'address') and hasattr(func, 'name'):
                exported_funcs[func.name] = func.address
        
        # 查找JNI方法
        jni_methods = []
        for func_name, addr in exported_funcs.items():
            if func_name.startswith("Java_"):
                jni_methods.append({
                    "name": func_name,
                    "address": hex(addr),
                    "type": "jni_method",
                    "description": "JNI native method"
                })
        
        for name, desc in special_entries.items():
            if name in exported_funcs:
                entrypoints.append({
                    "name": name,
                    "address": hex(exported_funcs[name]),
                    "type": "exported_entry",
                    "description": desc
                })
        
        # 添加JNI方法
        entrypoints.extend(jni_methods)
        
        # 3. Dynamic entries (DT_INIT, DT_FINI, DT_INIT_ARRAY, DT_FINI_ARRAY)
        for entry in binary.dynamic_entries:
            tag = entry.tag
            
            if tag == lief.ELF.DynamicEntry.TAG.INIT:
                if hasattr(entry, 'value') and entry.value != 0:
                    entrypoints.append({
                        "name": "DT_INIT",
                        "address": hex(entry.value),
                        "type": "dynamic_entry",
                        "description": "Dynamic initialization function"
                    })
            
            elif tag == lief.ELF.DynamicEntry.TAG.FINI:
                if hasattr(entry, 'value') and entry.value != 0:
                    entrypoints.append({
                        "name": "DT_FINI",
                        "address": hex(entry.value),
                        "type": "dynamic_entry",
                        "description": "Dynamic finalization function"
                    })
            
            elif tag == lief.ELF.DynamicEntry.TAG.INIT_ARRAY:
                if hasattr(entry, 'value') and entry.value != 0:
                    entrypoints.append({
                        "name": "DT_INIT_ARRAY",
                        "address": hex(entry.value),
                        "type": "init_array_ptr",
                        "description": "Pointer to .init_array section"
                    })
            
            elif tag == lief.ELF.DynamicEntry.TAG.FINI_ARRAY:
                if hasattr(entry, 'value') and entry.value != 0:
                    entrypoints.append({
                        "name": "DT_FINI_ARRAY",
                        "address": hex(entry.value),
                        "type": "fini_array_ptr",
                        "description": "Pointer to .fini_array section"
                    })
        
        # 4. 解析 .init_array 和 .fini_array 段中的函数指针
        array_sections = [
            (".init_array", "constructor", "Constructor function"),
            (".fini_array", "destructor", "Destructor function"),
            (".preinit_array", "preinit", "Pre-initialization function"),
            (".ctors", "ctor", "C++ constructor"),
            (".dtors", "dtor", "C++ destructor"),
        ]
        
        ptr_size = 8 if binary.header.identity_class == lief.ELF.Header.CLASS.ELF64 else 4
        ptr_format = '<Q' if ptr_size == 8 else '<I'
        
        for section_name, entry_type, desc in array_sections:
            section = None
            for sec in binary.sections:
                if sec.name == section_name:
                    section = sec
                    break
            
            if section and section.size > 0:
                section_data = bytes(section.content)
                
                for i in range(0, len(section_data), ptr_size):
                    if i + ptr_size <= len(section_data):
                        ptr = struct.unpack(ptr_format, section_data[i:i+ptr_size])[0]
                        if ptr != 0 and ptr != 0xFFFFFFFFFFFFFFFF:
                            # 查找函数名
                            func_name = None
                            for name, addr in exported_funcs.items():
                                if addr == ptr:
                                    func_name = name
                                    break
                            
                            entrypoints.append({
                                "name": func_name if func_name else f"{entry_type}_{i//ptr_size}",
                                "address": hex(ptr),
                                "type": entry_type,
                                "description": desc,
                                "source_section": section_name,
                                "array_index": i // ptr_size
                            })
        
        # 5. 查找符号表中的特殊函数
        try:
            for symbol in binary.symbols:
                if symbol.type == lief.ELF.Symbol.TYPE.FUNC and symbol.value != 0:
                    name = symbol.name
                    if any(name.startswith(prefix) for prefix in ['__cxa_', '__do_global_', '__libc_start']):
                        entrypoints.append({
                            "name": name,
                            "address": hex(symbol.value),
                            "type": "runtime_entry",
                            "description": "Runtime initialization/cleanup function"
                        })
        except:
            pass
        
        # 去重
        seen = set()
        unique_entries = []
        for ep in entrypoints:
            key = (ep["address"], ep["type"])
            if key not in seen:
                seen.add(key)
                unique_entries.append(ep)
        
        # 按地址排序
        unique_entries.sort(key=lambda x: int(x["address"], 16))
        
        # 生成摘要
        summary = {
            "total": len(unique_entries),
            "by_type": {}
        }
        for ep in unique_entries:
            t = ep["type"]
            summary["by_type"][t] = summary["by_type"].get(t, 0) + 1
        
        return {
            "success": True,
            "entrypoints": unique_entries,
            "summary": summary,
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "entrypoints": [], "error": f"{str(e)}\n{traceback.format_exc()}"}


def list_globals(so_path: str, search: str = "", limit: int = 500,
                 include_rodata: bool = True, min_size: int = 0) -> dict:
    """
    列出全局变量（类似IDA Pro的list_globals功能）
    
    分析以下段中的数据:
    1. .data - 已初始化的全局变量
    2. .bss - 未初始化的全局变量
    3. .rodata - 只读数据（字符串常量等）
    4. .got / .got.plt - 全局偏移表
    
    Args:
        so_path: SO文件路径
        search: 搜索过滤（支持名称或地址）
        limit: 最大返回数量
        include_rodata: 是否包含只读数据段
        min_size: 最小变量大小过滤
    
    Returns:
        dict: {
            "success": bool,
            "globals": [
                {"name": str, "address": str, "size": int, "section": str, 
                 "type": str, "value_preview": str}
            ],
            "summary": dict
        }
    """
    if not LIEF_AVAILABLE:
        return {"success": False, "globals": [], "error": "lief not available"}
    
    if not os.path.exists(so_path):
        return {"success": False, "globals": [], "error": f"File not found: {so_path}"}
    
    try:
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "globals": [], "error": "Failed to parse SO file"}
        
        globals_list = []
        ptr_size = 8 if binary.header.identity_class == lief.ELF.Header.CLASS.ELF64 else 4
        
        # 要分析的段
        data_sections = [
            (".data", "initialized_data", "Initialized global data"),
            (".bss", "uninitialized_data", "Uninitialized global data (zero-filled)"),
            (".got", "got_entry", "Global Offset Table entry"),
            (".got.plt", "got_plt_entry", "GOT entry for PLT"),
        ]
        
        if include_rodata:
            data_sections.append((".rodata", "read_only_data", "Read-only data (constants)"))
            data_sections.append((".data.rel.ro", "relro_data", "Read-only after relocation"))
        
        # 1. 从符号表收集全局变量
        symbol_globals = {}  # address -> symbol info
        try:
            for symbol in binary.symbols:
                if symbol.value != 0:
                    if symbol.type in [lief.ELF.Symbol.TYPE.OBJECT, lief.ELF.Symbol.TYPE.NOTYPE]:
                        if symbol.binding in [lief.ELF.Symbol.BINDING.GLOBAL, lief.ELF.Symbol.BINDING.WEAK]:
                            symbol_globals[symbol.value] = {
                                "name": symbol.name,
                                "size": symbol.size,
                                "binding": str(symbol.binding).split('.')[-1],
                            }
        except:
            pass
        
        # 2. 分析每个数据段
        for section_name, var_type, description in data_sections:
            section = None
            for sec in binary.sections:
                if sec.name == section_name:
                    section = sec
                    break
            
            if not section:
                continue
            
            section_vaddr = section.virtual_address
            section_size = section.size
            section_offset = section.file_offset
            is_bss = section_name == ".bss"
            
            if not is_bss and section_size > 0:
                section_data = bytes(section.content)
            else:
                section_data = b'\x00' * min(section_size, 1024)
            
            # 查找该段中的符号
            section_symbols = []
            for addr, sym_info in symbol_globals.items():
                if section_vaddr <= addr < section_vaddr + section_size:
                    section_symbols.append((addr, sym_info))
            
            section_symbols.sort(key=lambda x: x[0])
            
            for i, (addr, sym_info) in enumerate(section_symbols):
                name = sym_info["name"]
                size = sym_info["size"]
                
                if size == 0:
                    if i + 1 < len(section_symbols):
                        size = section_symbols[i + 1][0] - addr
                    else:
                        size = section_vaddr + section_size - addr
                    size = min(size, 1024)
                
                if min_size > 0 and size < min_size:
                    continue
                
                if search and search.lower() not in name.lower() and search not in hex(addr):
                    continue
                
                # 获取值预览
                value_preview = ""
                inferred_type = "unknown"
                
                if not is_bss and size > 0:
                    offset_in_section = addr - section_vaddr
                    if 0 <= offset_in_section < len(section_data):
                        preview_bytes = section_data[offset_in_section:offset_in_section + min(size, 64)]
                        
                        if size == ptr_size and len(preview_bytes) >= ptr_size:
                            ptr_fmt = '<Q' if ptr_size == 8 else '<I'
                            ptr_val = struct.unpack(ptr_fmt, preview_bytes[:ptr_size])[0]
                            value_preview = hex(ptr_val)
                            inferred_type = "pointer" if ptr_val > 0x1000 else "integer"
                        elif size == 4 and len(preview_bytes) >= 4:
                            int_val = struct.unpack('<I', preview_bytes[:4])[0]
                            value_preview = f"{int_val} (0x{int_val:x})"
                            inferred_type = "int32"
                        elif size == 1 and len(preview_bytes) >= 1:
                            value_preview = f"{preview_bytes[0]} (0x{preview_bytes[0]:02x})"
                            inferred_type = "byte"
                        else:
                            # 检查是否是字符串
                            try:
                                if b'\x00' in preview_bytes:
                                    null_idx = preview_bytes.index(b'\x00')
                                    str_val = preview_bytes[:null_idx].decode('utf-8', errors='ignore')
                                    if str_val and len(str_val) > 1 and all(c.isprintable() or c in '\t\n\r' for c in str_val):
                                        value_preview = f'"{str_val[:50]}"'
                                        inferred_type = "string"
                                    else:
                                        value_preview = preview_bytes[:32].hex()
                                        inferred_type = "bytes"
                                else:
                                    value_preview = preview_bytes[:32].hex()
                                    inferred_type = "bytes"
                            except:
                                value_preview = preview_bytes[:32].hex() if preview_bytes else ""
                                inferred_type = "bytes"
                elif is_bss:
                    value_preview = "(uninitialized)"
                    inferred_type = "bss"
                
                globals_list.append({
                    "name": name,
                    "address": hex(addr),
                    "file_offset": hex(section_offset + (addr - section_vaddr)),
                    "size": size,
                    "section": section_name,
                    "type": var_type,
                    "inferred_type": inferred_type,
                    "binding": sym_info["binding"],
                    "value_preview": value_preview,
                    "description": description
                })
                
                if len(globals_list) >= limit:
                    break
            
            if len(globals_list) >= limit:
                break
        
        # 3. GOT 表项
        try:
            for reloc in binary.pltgot_relocations:
                if len(globals_list) >= limit:
                    break
                if reloc.has_symbol:
                    name = reloc.symbol.name
                    addr = reloc.address
                    
                    if search and search.lower() not in name.lower() and search not in hex(addr):
                        continue
                    
                    globals_list.append({
                        "name": f"GOT[{name}]",
                        "address": hex(addr),
                        "file_offset": "N/A",
                        "size": ptr_size,
                        "section": ".got.plt",
                        "type": "got_reloc",
                        "inferred_type": "function_pointer",
                        "binding": "GLOBAL",
                        "value_preview": f"-> {name}",
                        "description": "GOT entry for PLT relocation"
                    })
        except:
            pass
        
        # 按地址排序
        globals_list.sort(key=lambda x: int(x["address"], 16))
        
        # 生成摘要
        summary = {
            "total": len(globals_list),
            "by_section": {},
            "by_type": {}
        }
        for g in globals_list:
            sec = g["section"]
            t = g.get("inferred_type", "unknown")
            summary["by_section"][sec] = summary["by_section"].get(sec, 0) + 1
            summary["by_type"][t] = summary["by_type"].get(t, 0) + 1
        
        return {
            "success": True,
            "globals": globals_list,
            "summary": summary,
            "truncated": len(globals_list) >= limit,
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "globals": [], "error": f"{str(e)}\n{traceback.format_exc()}"}
