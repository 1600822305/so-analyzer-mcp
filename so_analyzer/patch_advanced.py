"""高级Patch工具 - 用于APK/SO修改"""
import os
import struct
import shutil
from typing import Optional, List, Dict, Union

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


# ==================== ARM64 Patch 代码库 ====================

# 返回值修改
PATCH_RETURN = {
    # MOV W0, #N; RET (8 bytes)
    "return_0": bytes.fromhex("00008052C0035FD6"),      # MOV W0, #0; RET
    "return_1": bytes.fromhex("20008052C0035FD6"),      # MOV W0, #1; RET
    "return_true": bytes.fromhex("20008052C0035FD6"),   # MOV W0, #1; RET (alias)
    "return_false": bytes.fromhex("00008052C0035FD6"),  # MOV W0, #0; RET (alias)
    
    # MOV X0, #N; RET (8 bytes) - 64位版本
    "return_0_x64": bytes.fromhex("000080D2C0035FD6"),  # MOV X0, #0; RET
    "return_1_x64": bytes.fromhex("200080D2C0035FD6"),  # MOV X0, #1; RET
    
    # 返回特殊值
    "return_neg1": bytes.fromhex("00008012C0035FD6"),   # MOV W0, #-1; RET
    "return_max": bytes.fromhex("E0031F32C0035FD6"),    # MOV W0, #0x7FFFFFFF; RET (高值)
}

# NOP指令
PATCH_NOP = {
    "nop": bytes.fromhex("1F2003D5"),           # NOP (4 bytes)
    "nop_2": bytes.fromhex("1F2003D51F2003D5"), # NOP; NOP (8 bytes)
    "nop_4": bytes.fromhex("1F2003D51F2003D51F2003D51F2003D5"),  # 4x NOP (16 bytes)
}

# 跳转修改
PATCH_BRANCH = {
    # 条件跳转改为无条件
    "b_always": bytes.fromhex("00000014"),      # B (无条件跳转，需要计算偏移)
    
    # 条件跳转相关 (需要根据原指令修改)
    "cbz_to_cbnz": None,   # CBZ -> CBNZ (翻转第24位)
    "cbnz_to_cbz": None,   # CBNZ -> CBZ
    "beq_to_bne": None,    # B.EQ -> B.NE
    "bne_to_beq": None,    # B.NE -> B.EQ
}

# 常用VIP/会员检测关键词
VIP_KEYWORDS = [
    # 会员相关
    "vip", "VIP", "Vip",
    "premium", "Premium", "PREMIUM",
    "member", "Member", "MEMBER",
    "pro", "Pro", "PRO",
    "subscribe", "Subscribe", "subscription",
    "license", "License", "LICENSE",
    "paid", "Paid", "PAID",
    "unlock", "Unlock", "UNLOCK",
    
    # 验证相关
    "isVip", "IsVip", "is_vip",
    "isPremium", "IsPremium", "is_premium", 
    "isMember", "IsMember", "is_member",
    "isPro", "IsPro", "is_pro",
    "isSubscribed", "IsSubscribed",
    "isLicensed", "IsLicensed",
    "isPaid", "IsPaid", "is_paid",
    "isUnlocked", "IsUnlocked",
    "checkVip", "CheckVip", "check_vip",
    "checkLicense", "CheckLicense",
    "checkPremium", "CheckPremium",
    "validateLicense", "ValidateLicense",
    "verifyLicense", "VerifyLicense",
    
    # 试用相关
    "trial", "Trial", "TRIAL",
    "expire", "Expire", "expired",
    "isTrial", "IsTrial", "is_trial",
    "isExpired", "IsExpired", "is_expired",
    
    # 广告相关
    "ad", "Ad", "AD", "ads", "Ads",
    "showAd", "ShowAd", "show_ad",
    "isAdFree", "IsAdFree", "is_ad_free",
    "removeAd", "RemoveAd", "remove_ad",
    
    # 功能限制
    "limit", "Limit", "LIMITED",
    "isLimited", "IsLimited", "is_limited",
    "checkLimit", "CheckLimit",
]


def patch_return_value(so_path: str, address: int, return_value: Union[int, str] = 1,
                       output_path: Optional[str] = None, backup: bool = True) -> dict:
    """
    修改函数使其直接返回指定值
    
    Args:
        so_path: SO文件路径
        address: 函数地址（虚拟地址）
        return_value: 返回值 (0, 1, -1, "true", "false", "max", 或具体数字)
        output_path: 输出路径（可选）
        backup: 是否备份原文件
    
    Returns:
        dict: {"success": bool, "output_path": str, "patch_info": dict}
    """
    if not os.path.exists(so_path):
        return {"success": False, "error": f"File not found: {so_path}"}
    
    try:
        # 确定patch字节
        if isinstance(return_value, str):
            return_value = return_value.lower()
            if return_value in ["true", "1", "yes"]:
                patch_bytes = PATCH_RETURN["return_1"]
            elif return_value in ["false", "0", "no"]:
                patch_bytes = PATCH_RETURN["return_0"]
            elif return_value in ["-1", "neg1", "negative"]:
                patch_bytes = PATCH_RETURN["return_neg1"]
            elif return_value in ["max", "high", "maximum"]:
                patch_bytes = PATCH_RETURN["return_max"]
            else:
                return {"success": False, "error": f"Unknown return value: {return_value}"}
        elif isinstance(return_value, int):
            if return_value == 0:
                patch_bytes = PATCH_RETURN["return_0"]
            elif return_value == 1:
                patch_bytes = PATCH_RETURN["return_1"]
            elif return_value == -1:
                patch_bytes = PATCH_RETURN["return_neg1"]
            elif 0 <= return_value <= 0xFFFF:
                # 自定义值: MOV W0, #value; RET
                # MOV W0, #imm16 编码: 0x52800000 | (imm16 << 5)
                mov_insn = 0x52800000 | ((return_value & 0xFFFF) << 5)
                ret_insn = 0xD65F03C0
                patch_bytes = struct.pack("<II", mov_insn, ret_insn)
            else:
                return {"success": False, "error": f"Return value out of range (0-65535): {return_value}"}
        else:
            return {"success": False, "error": f"Invalid return value type: {type(return_value)}"}
        
        # 读取文件
        with open(so_path, 'rb') as f:
            data = bytearray(f.read())
        
        # 计算文件偏移
        if LIEF_AVAILABLE:
            binary = lief.parse(so_path)
            if binary:
                # 虚拟地址转文件偏移
                file_offset = None
                for seg in binary.segments:
                    if seg.virtual_address <= address < seg.virtual_address + seg.virtual_size:
                        file_offset = seg.file_offset + (address - seg.virtual_address)
                        break
                
                if file_offset is None:
                    return {"success": False, "error": f"Address 0x{address:x} not in any segment"}
            else:
                file_offset = address
        else:
            file_offset = address
        
        # 验证偏移
        if file_offset + len(patch_bytes) > len(data):
            return {"success": False, "error": "Offset out of bounds"}
        
        # 保存原始字节
        original_bytes = bytes(data[file_offset:file_offset + len(patch_bytes)])
        
        # 备份
        if backup and not output_path:
            backup_path = so_path + ".bak"
            if not os.path.exists(backup_path):
                shutil.copy2(so_path, backup_path)
        
        # 应用patch
        data[file_offset:file_offset + len(patch_bytes)] = patch_bytes
        
        # 输出路径
        if not output_path:
            output_path = so_path
        
        # 写入文件
        with open(output_path, 'wb') as f:
            f.write(data)
        
        return {
            "success": True,
            "output_path": output_path,
            "patch_info": {
                "virtual_address": hex(address),
                "file_offset": hex(file_offset),
                "original_bytes": original_bytes.hex(),
                "patched_bytes": patch_bytes.hex(),
                "return_value": return_value,
                "description": f"Function now returns {return_value}"
            },
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}


def patch_nop(so_path: str, address: int, count: int = 1,
              output_path: Optional[str] = None, backup: bool = True) -> dict:
    """
    将指令替换为NOP
    
    Args:
        so_path: SO文件路径
        address: 起始地址（虚拟地址）
        count: NOP数量（每个4字节）
        output_path: 输出路径
        backup: 是否备份
    
    Returns:
        dict: {"success": bool, "output_path": str, "patch_info": dict}
    """
    if not os.path.exists(so_path):
        return {"success": False, "error": f"File not found: {so_path}"}
    
    if count < 1 or count > 100:
        return {"success": False, "error": f"Invalid NOP count: {count} (1-100)"}
    
    try:
        # 生成NOP序列
        nop_bytes = PATCH_NOP["nop"] * count
        
        # 读取文件
        with open(so_path, 'rb') as f:
            data = bytearray(f.read())
        
        # 计算文件偏移
        if LIEF_AVAILABLE:
            binary = lief.parse(so_path)
            if binary:
                file_offset = None
                for seg in binary.segments:
                    if seg.virtual_address <= address < seg.virtual_address + seg.virtual_size:
                        file_offset = seg.file_offset + (address - seg.virtual_address)
                        break
                
                if file_offset is None:
                    return {"success": False, "error": f"Address 0x{address:x} not in any segment"}
            else:
                file_offset = address
        else:
            file_offset = address
        
        # 验证偏移
        if file_offset + len(nop_bytes) > len(data):
            return {"success": False, "error": "Offset out of bounds"}
        
        # 保存原始字节
        original_bytes = bytes(data[file_offset:file_offset + len(nop_bytes)])
        
        # 备份
        if backup and not output_path:
            backup_path = so_path + ".bak"
            if not os.path.exists(backup_path):
                shutil.copy2(so_path, backup_path)
        
        # 应用patch
        data[file_offset:file_offset + len(nop_bytes)] = nop_bytes
        
        # 输出路径
        if not output_path:
            output_path = so_path
        
        # 写入文件
        with open(output_path, 'wb') as f:
            f.write(data)
        
        return {
            "success": True,
            "output_path": output_path,
            "patch_info": {
                "virtual_address": hex(address),
                "file_offset": hex(file_offset),
                "original_bytes": original_bytes.hex(),
                "patched_bytes": nop_bytes.hex(),
                "nop_count": count,
                "bytes_modified": count * 4,
                "description": f"Replaced {count} instruction(s) with NOP"
            },
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}


def patch_branch(so_path: str, address: int, patch_type: str = "force_jump",
                 output_path: Optional[str] = None, backup: bool = True) -> dict:
    """
    修改分支指令
    
    Args:
        so_path: SO文件路径
        address: 分支指令地址
        patch_type: 修改类型
            - "force_jump": 条件跳转 -> 无条件跳转
            - "no_jump": 跳转 -> NOP
            - "invert": 反转条件 (B.EQ -> B.NE)
        output_path: 输出路径
        backup: 是否备份
    
    Returns:
        dict: {"success": bool, "output_path": str, "patch_info": dict}
    """
    if not LIEF_AVAILABLE or not CAPSTONE_AVAILABLE:
        return {"success": False, "error": "lief and capstone required"}
    
    if not os.path.exists(so_path):
        return {"success": False, "error": f"File not found: {so_path}"}
    
    try:
        # 读取文件
        with open(so_path, 'rb') as f:
            data = bytearray(f.read())
        
        binary = lief.parse(so_path)
        if not binary:
            return {"success": False, "error": "Failed to parse binary"}
        
        # 计算文件偏移
        file_offset = None
        for seg in binary.segments:
            if seg.virtual_address <= address < seg.virtual_address + seg.virtual_size:
                file_offset = seg.file_offset + (address - seg.virtual_address)
                break
        
        if file_offset is None:
            return {"success": False, "error": f"Address 0x{address:x} not in any segment"}
        
        # 读取原始指令
        original_bytes = bytes(data[file_offset:file_offset + 4])
        original_insn = struct.unpack("<I", original_bytes)[0]
        
        # 反汇编原始指令
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        insns = list(md.disasm(original_bytes, address))
        
        if not insns:
            return {"success": False, "error": "Failed to disassemble instruction"}
        
        insn = insns[0]
        mnem = insn.mnemonic.lower()
        
        # 根据类型修改
        if patch_type == "no_jump":
            # 替换为NOP
            patch_bytes = PATCH_NOP["nop"]
            description = f"Replaced {insn.mnemonic} with NOP"
        
        elif patch_type == "force_jump":
            # 条件跳转 -> 无条件跳转
            if mnem.startswith("b."):
                # B.cond -> B (保持相同偏移)
                # 提取偏移
                imm19 = (original_insn >> 5) & 0x7FFFF
                # 构建无条件跳转 B
                new_insn = 0x14000000 | (imm19 << 0)
                patch_bytes = struct.pack("<I", new_insn)
                description = f"Changed {insn.mnemonic} to unconditional B"
            elif mnem in ["cbz", "cbnz"]:
                # CBZ/CBNZ -> B
                imm19 = (original_insn >> 5) & 0x7FFFF
                new_insn = 0x14000000 | (imm19 << 0)
                patch_bytes = struct.pack("<I", new_insn)
                description = f"Changed {insn.mnemonic} to unconditional B"
            elif mnem in ["tbz", "tbnz"]:
                # TBZ/TBNZ -> B
                imm14 = (original_insn >> 5) & 0x3FFF
                new_insn = 0x14000000 | (imm14 << 0)
                patch_bytes = struct.pack("<I", new_insn)
                description = f"Changed {insn.mnemonic} to unconditional B"
            else:
                return {"success": False, "error": f"Not a conditional branch: {insn.mnemonic}"}
        
        elif patch_type == "invert":
            # 反转条件
            if mnem.startswith("b."):
                # 反转条件码 (bit 0)
                new_insn = original_insn ^ 0x1
                patch_bytes = struct.pack("<I", new_insn)
                description = f"Inverted condition of {insn.mnemonic}"
            elif mnem == "cbz":
                # CBZ -> CBNZ (bit 24)
                new_insn = original_insn | 0x01000000
                patch_bytes = struct.pack("<I", new_insn)
                description = "Changed CBZ to CBNZ"
            elif mnem == "cbnz":
                # CBNZ -> CBZ (bit 24)
                new_insn = original_insn & ~0x01000000
                patch_bytes = struct.pack("<I", new_insn)
                description = "Changed CBNZ to CBZ"
            elif mnem == "tbz":
                # TBZ -> TBNZ (bit 24)
                new_insn = original_insn | 0x01000000
                patch_bytes = struct.pack("<I", new_insn)
                description = "Changed TBZ to TBNZ"
            elif mnem == "tbnz":
                # TBNZ -> TBZ (bit 24)
                new_insn = original_insn & ~0x01000000
                patch_bytes = struct.pack("<I", new_insn)
                description = "Changed TBNZ to TBZ"
            else:
                return {"success": False, "error": f"Cannot invert: {insn.mnemonic}"}
        
        else:
            return {"success": False, "error": f"Unknown patch type: {patch_type}"}
        
        # 备份
        if backup and not output_path:
            backup_path = so_path + ".bak"
            if not os.path.exists(backup_path):
                shutil.copy2(so_path, backup_path)
        
        # 应用patch
        data[file_offset:file_offset + len(patch_bytes)] = patch_bytes
        
        # 输出路径
        if not output_path:
            output_path = so_path
        
        # 写入文件
        with open(output_path, 'wb') as f:
            f.write(data)
        
        return {
            "success": True,
            "output_path": output_path,
            "patch_info": {
                "virtual_address": hex(address),
                "file_offset": hex(file_offset),
                "original_instruction": f"{insn.mnemonic} {insn.op_str}",
                "original_bytes": original_bytes.hex(),
                "patched_bytes": patch_bytes.hex(),
                "patch_type": patch_type,
                "description": description
            },
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}


def patch_custom(so_path: str, address: int, hex_bytes: str,
                 output_path: Optional[str] = None, backup: bool = True) -> dict:
    """
    自定义Patch - 直接写入十六进制字节
    
    Args:
        so_path: SO文件路径
        address: 目标地址（虚拟地址）
        hex_bytes: 要写入的十六进制字节（如 "20008052C0035FD6"）
        output_path: 输出路径
        backup: 是否备份
    
    Returns:
        dict: {"success": bool, "output_path": str, "patch_info": dict}
    """
    if not os.path.exists(so_path):
        return {"success": False, "error": f"File not found: {so_path}"}
    
    try:
        # 解析十六进制
        hex_bytes = hex_bytes.replace(" ", "").replace("0x", "")
        try:
            patch_bytes = bytes.fromhex(hex_bytes)
        except ValueError as e:
            return {"success": False, "error": f"Invalid hex string: {e}"}
        
        if len(patch_bytes) == 0:
            return {"success": False, "error": "Empty hex bytes"}
        
        if len(patch_bytes) % 4 != 0:
            return {"success": False, "error": "Hex bytes must be multiple of 4 (ARM64 instruction size)"}
        
        # 读取文件
        with open(so_path, 'rb') as f:
            data = bytearray(f.read())
        
        # 计算文件偏移
        if LIEF_AVAILABLE:
            binary = lief.parse(so_path)
            if binary:
                file_offset = None
                for seg in binary.segments:
                    if seg.virtual_address <= address < seg.virtual_address + seg.virtual_size:
                        file_offset = seg.file_offset + (address - seg.virtual_address)
                        break
                
                if file_offset is None:
                    return {"success": False, "error": f"Address 0x{address:x} not in any segment"}
            else:
                file_offset = address
        else:
            file_offset = address
        
        # 验证偏移
        if file_offset + len(patch_bytes) > len(data):
            return {"success": False, "error": "Offset out of bounds"}
        
        # 保存原始字节
        original_bytes = bytes(data[file_offset:file_offset + len(patch_bytes)])
        
        # 反汇编原始和新指令（如果可能）
        disasm_info = {}
        if CAPSTONE_AVAILABLE:
            md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
            
            orig_insns = list(md.disasm(original_bytes, address))
            disasm_info["original_disasm"] = [
                f"{insn.mnemonic} {insn.op_str}" for insn in orig_insns
            ]
            
            new_insns = list(md.disasm(patch_bytes, address))
            disasm_info["patched_disasm"] = [
                f"{insn.mnemonic} {insn.op_str}" for insn in new_insns
            ]
        
        # 备份
        if backup and not output_path:
            backup_path = so_path + ".bak"
            if not os.path.exists(backup_path):
                shutil.copy2(so_path, backup_path)
        
        # 应用patch
        data[file_offset:file_offset + len(patch_bytes)] = patch_bytes
        
        # 输出路径
        if not output_path:
            output_path = so_path
        
        # 写入文件
        with open(output_path, 'wb') as f:
            f.write(data)
        
        return {
            "success": True,
            "output_path": output_path,
            "patch_info": {
                "virtual_address": hex(address),
                "file_offset": hex(file_offset),
                "original_bytes": original_bytes.hex(),
                "patched_bytes": patch_bytes.hex(),
                "bytes_modified": len(patch_bytes),
                **disasm_info
            },
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}


def find_vip_functions(so_path: str, keywords: Optional[List[str]] = None,
                       limit: int = 50) -> dict:
    """
    自动查找VIP/会员验证相关函数
    
    Args:
        so_path: SO文件路径
        keywords: 自定义关键词列表（可选，默认使用内置列表）
        limit: 最大返回数量
    
    Returns:
        dict: {"success": bool, "functions": list, "count": int}
    """
    if not LIEF_AVAILABLE:
        return {"success": False, "error": "lief not available"}
    
    if not os.path.exists(so_path):
        return {"success": False, "error": f"File not found: {so_path}"}
    
    try:
        binary = lief.parse(so_path)
        if not binary:
            return {"success": False, "error": "Failed to parse binary"}
        
        # 使用关键词
        search_keywords = keywords if keywords else VIP_KEYWORDS
        
        found_functions = []
        
        # 搜索导出符号
        for sym in binary.exported_symbols:
            if not sym.name:
                continue
            
            for keyword in search_keywords:
                if keyword in sym.name:
                    # 判断可能的修改建议
                    suggestion = "return_1"  # 默认返回true
                    if any(k in sym.name.lower() for k in ["expired", "limit", "ad", "trial"]):
                        suggestion = "return_0"  # 返回false更合适
                    
                    found_functions.append({
                        "name": sym.name,
                        "address": hex(sym.value),
                        "matched_keyword": keyword,
                        "type": "exported",
                        "suggestion": suggestion,
                        "patch_command": f'so_patch_return(so_path, {hex(sym.value)}, "{suggestion}")'
                    })
                    break
            
            if len(found_functions) >= limit:
                break
        
        # 搜索导入符号
        for sym in binary.imported_symbols:
            if not sym.name:
                continue
            
            for keyword in search_keywords:
                if keyword in sym.name:
                    found_functions.append({
                        "name": sym.name,
                        "address": "N/A (imported)",
                        "matched_keyword": keyword,
                        "type": "imported",
                        "suggestion": "Hook with Frida",
                        "note": "Cannot patch directly, use Frida hook"
                    })
                    break
            
            if len(found_functions) >= limit:
                break
        
        # 搜索字符串引用
        # (可以在未来添加)
        
        return {
            "success": True,
            "functions": found_functions,
            "count": len(found_functions),
            "keywords_used": len(search_keywords),
            "note": "Use so_patch_return to patch exported functions",
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}


def generate_patch_script(patches: List[dict], output_format: str = "python") -> dict:
    """
    生成批量Patch脚本
    
    Args:
        patches: Patch列表，每项包含 {address, type, value}
        output_format: 输出格式 ("python", "frida", "hex")
    
    Returns:
        dict: {"success": bool, "script": str}
    """
    try:
        if output_format == "python":
            script_lines = [
                "# Auto-generated patch script",
                "# Usage: python patch_script.py <input.so> <output.so>",
                "",
                "import sys",
                "",
                "patches = ["
            ]
            
            for p in patches:
                addr = p.get("address", 0)
                ptype = p.get("type", "return_1")
                script_lines.append(f"    {{'address': {addr}, 'type': '{ptype}'}},")
            
            script_lines.extend([
                "]",
                "",
                "# Patch bytes lookup",
                "PATCH_BYTES = {",
                '    "return_0": bytes.fromhex("00008052C0035FD6"),',
                '    "return_1": bytes.fromhex("20008052C0035FD6"),',
                '    "nop": bytes.fromhex("1F2003D5"),',
                "}",
                "",
                "def apply_patches(input_path, output_path):",
                "    with open(input_path, 'rb') as f:",
                "        data = bytearray(f.read())",
                "    ",
                "    for p in patches:",
                "        offset = p['address']  # Adjust if using virtual address",
                "        patch = PATCH_BYTES.get(p['type'], PATCH_BYTES['nop'])",
                "        data[offset:offset+len(patch)] = patch",
                "        print(f'Patched 0x{offset:x} with {p[\"type\"]}')",
                "    ",
                "    with open(output_path, 'wb') as f:",
                "        f.write(data)",
                "    print(f'Saved to {output_path}')",
                "",
                "if __name__ == '__main__':",
                "    if len(sys.argv) < 3:",
                "        print('Usage: python patch_script.py <input.so> <output.so>')",
                "        sys.exit(1)",
                "    apply_patches(sys.argv[1], sys.argv[2])",
            ])
            
            script = "\n".join(script_lines)
        
        elif output_format == "frida":
            script_lines = [
                "// Auto-generated Frida hook script",
                "",
            ]
            
            for i, p in enumerate(patches):
                addr = p.get("address", 0)
                ptype = p.get("type", "return_1")
                ret_val = "1" if "1" in ptype or "true" in ptype.lower() else "0"
                
                script_lines.extend([
                    f"// Patch {i+1}",
                    f"Interceptor.attach(ptr({addr}), {{",
                    "    onEnter: function(args) {",
                    "        // console.log('Called');",
                    "    },",
                    "    onLeave: function(retval) {",
                    f"        retval.replace({ret_val});",
                    "    }",
                    "});",
                    "",
                ])
            
            script = "\n".join(script_lines)
        
        elif output_format == "hex":
            lines = ["# Patch list (offset: hex_bytes)", ""]
            for p in patches:
                addr = p.get("address", 0)
                ptype = p.get("type", "return_1")
                
                if "return_1" in ptype or "true" in ptype.lower():
                    hex_bytes = "20008052C0035FD6"
                elif "return_0" in ptype or "false" in ptype.lower():
                    hex_bytes = "00008052C0035FD6"
                elif "nop" in ptype.lower():
                    hex_bytes = "1F2003D5"
                else:
                    hex_bytes = "1F2003D5"
                
                lines.append(f"0x{addr:08X}: {hex_bytes}")
            
            script = "\n".join(lines)
        
        else:
            return {"success": False, "error": f"Unknown format: {output_format}"}
        
        return {
            "success": True,
            "script": script,
            "format": output_format,
            "patch_count": len(patches),
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}


# 预设Patch模板
PATCH_TEMPLATES = {
    "return_true": {
        "description": "函数直接返回 true (1)",
        "bytes": "20008052C0035FD6",
        "asm": "MOV W0, #1; RET"
    },
    "return_false": {
        "description": "函数直接返回 false (0)",
        "bytes": "00008052C0035FD6",
        "asm": "MOV W0, #0; RET"
    },
    "return_neg1": {
        "description": "函数直接返回 -1",
        "bytes": "00008012C0035FD6",
        "asm": "MOV W0, #-1; RET"
    },
    "nop": {
        "description": "空操作 (跳过指令)",
        "bytes": "1F2003D5",
        "asm": "NOP"
    },
    "nop_8": {
        "description": "8字节 NOP (跳过2条指令)",
        "bytes": "1F2003D51F2003D5",
        "asm": "NOP; NOP"
    },
    "bypass_check": {
        "description": "绕过检查 (直接返回成功)",
        "bytes": "20008052C0035FD6",
        "asm": "MOV W0, #1; RET"
    },
    "infinite_value": {
        "description": "返回最大值 (用于金币/钻石等)",
        "bytes": "E0FFBF52E0FF9F72C0035FD6",
        "asm": "MOV W0, #0x7FFFFFFF; RET"
    }
}


def get_patch_templates() -> dict:
    """获取所有预设Patch模板"""
    return {
        "success": True,
        "templates": PATCH_TEMPLATES,
        "error": ""
    }
