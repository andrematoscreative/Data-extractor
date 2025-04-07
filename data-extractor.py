import os
import re
import hashlib
import json
import magic
import pefile
import lief
from datetime import datetime, timezone
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

def extract_file_info(file_path: str, json_path: str):
    file_path = Path(file_path)
    
    name = file_path.name
    
    sha256_hash = compute_sha256(file_path)
    
    file_extension = file_path.suffix

    modified_date = datetime.fromtimestamp(file_path.stat().st_mtime, timezone.utc)

    suspicious_strings = check_suspicious_strings(file_path, json_path)

    encoding_detected = check_encoding(file_path)

    num_text_sections, num_custom_sections = analyze_pe_file(file_path)

    disasm_info = disassemble_pe(file_path)  # Call once, store the full result
    opcode_counts = disasm_info["opcode_counts"]
    arch_info = disasm_info["arch"]



    return {
        "name": name,
        "sha256": sha256_hash,
        "extension": file_extension,
        "modified_date": modified_date,
        "suspicious_strings": suspicious_strings,
        "encoding": encoding_detected,
        "encoding_detected": encoding_detected,
        "num_text_sections": num_text_sections,
        "num_custom_sections": num_custom_sections,
        "arch": arch_info,
        "opcode_counts": opcode_counts
    }

def compute_sha256(file_path: Path) -> str:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def load_suspicious_strings(json_path: str) -> list:
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("patterns", [])
    except (json.JSONDecodeError, FileNotFoundError):
        return []

def check_suspicious_strings(file_path: Path, json_path: str) -> bool:
    suspicious_patterns = load_suspicious_strings(json_path)
    compiled_patterns = [re.compile(pattern.encode(), re.IGNORECASE) for pattern in suspicious_patterns]

    with open(file_path, "rb") as f:
        content = f.read()
        return any(pattern.search(content) for pattern in compiled_patterns)

def check_encoding(file_path: Path) -> bool: #verificar encoding do ficheiro ou se enconding suspeito, mostrar?
    try:
        mime_type = magic.from_file(str(file_path), mime=True)
        return mime_type.startswith("text/")
    except Exception:
        return False


def analyze_pe_file(file_path: Path):
    try:
        pe = pefile.PE(str(file_path))
        text_sections = 0
        custom_sections = 0
        for section in pe.sections:
            if b'.text' in section.Name:
                text_sections += 1
            elif not section.Name.startswith(b'.'):
                custom_sections += 1
        return text_sections, custom_sections
    except pefile.PEFormatError:
        return 0, 0 

def disassemble_pe(file_path: Path):
    try:
        binary = lief.parse(str(file_path))

        if not binary or not isinstance(binary, lief.PE.Binary):
            return {"opcode_counts": {}, "arch": "not_pe"}

        entrypoint_rva = binary.entrypoint - binary.optional_header.imagebase

        section = next(
            (s for s in binary.sections if s.virtual_address <= entrypoint_rva < s.virtual_address + max(s.virtual_size, s.size)),
            None
        )

        if not section:
            return {"opcode_counts": {}, "arch": "no_entry_section"}

        data = section.content
        offset = entrypoint_rva - section.virtual_address
        code = bytes(data[offset:offset+1000]) if offset < len(data) else b""

        # Use raw machine type value
        machine_type = binary.header.machine
        mode = CS_MODE_32 if machine_type == 0x014c else CS_MODE_64

        md = Cs(CS_ARCH_X86, mode)

        opcodes = {}
        for instr in md.disasm(code, 0x0):
            op = instr.mnemonic
            opcodes[op] = opcodes.get(op, 0) + 1

        return {
            "opcode_counts": opcodes,
            "arch": "x86_64" if mode == CS_MODE_64 else "x86"
        }

    except Exception as e:
        print(f"Disassembly error on {file_path}: {e}")
        return {"opcode_counts": {}, "arch": "error"}

    
def disassemble_pe_debug(file_path: Path):
    try:
        binary = lief.parse(str(file_path))

        if not binary or not isinstance(binary, lief.PE.Binary):
            print(f"{file_path.name}: Not a PE binary")
            return {"opcode_counts": {}, "arch": "not_pe"}

        print(f"\n>>> {file_path.name}")
        print(f"Entry point: 0x{binary.entrypoint:X}")

        for section in binary.sections:
            print(f"  Section: {section.name}")
            print(f"    VA: 0x{section.virtual_address:X}")
            print(f"    VSIZE: 0x{section.virtual_size:X}")
            print(f"    SIZE: 0x{section.size:X}")

        entrypoint_rva = binary.entrypoint

        section = next(
            (s for s in binary.sections if s.virtual_address <= entrypoint_rva < s.virtual_address + s.virtual_size),
            None
        )

        if not section:
            print("  ⚠️ Could not find entry section!")
            return {"opcode_counts": {}, "arch": "no_entry_section"}

        print(f"  ✅ Matched Section: {section.name}")

        data = section.content
        offset = entrypoint_rva - section.virtual_address
        code = bytes(data[offset:offset+1000])

        mode = CS_MODE_32 if binary.header.machine == lief.PE.MACHINE_TYPES.I386 else CS_MODE_64
        md = Cs(CS_ARCH_X86, mode)

        opcodes = {}
        for instr in md.disasm(code, 0x0):
            op = instr.mnemonic
            opcodes[op] = opcodes.get(op, 0) + 1

        return {
            "opcode_counts": opcodes,
            "arch": "x86_64" if mode == CS_MODE_64 else "x86"
        }

    except Exception as e:
        print(f"Disassembly error on {file_path}: {e}")
        return {"opcode_counts": {}, "arch": "error"}

def process_files_in_folder(folder_path: str, json_path: str):
    folder_path = Path(folder_path)
    results = []

    for file_path in folder_path.rglob('*'):  
        if file_path.is_file():  
            file_info = extract_file_info(file_path, json_path)
            results.append(file_info)
    return results

def get_file_metadata(file_path: str):
    file_path = Path(file_path)
    
    if not file_path.exists():
        raise FileNotFoundError(f"File {file_path} does not exist.")
    
    metadata = {
        "name": file_path.name,
        "size": file_path.stat().st_size,
        "modified_date": datetime.fromtimestamp(file_path.stat().st_mtime, timezone.utc),
        "created_date": datetime.fromtimestamp(file_path.stat().st_ctime, timezone.utc),
        "accessed_date": datetime.fromtimestamp(file_path.stat().st_atime, timezone.utc)
    }
    
    return metadata

def output_csv(file_info_list, output_file):
    import csv
    keys = file_info_list[0].keys()
    with open(output_file, 'w', newline='', encoding='utf-8') as output_csv:
        dict_writer = csv.DictWriter(output_csv, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(file_info_list)

# Exemplo de uso
folder_path = "Test-subjects/Benignos"
json_path = "suspicious_strings.json"

# Process all files in the folder
all_file_info = process_files_in_folder(folder_path, json_path)

# Exibir resultados
for file_info in all_file_info:
    print(file_info)

output_csv(all_file_info, "output.csv")
