import os
import re
import hashlib
import json
import magic
import pefile
import pandas as pd
from datetime import datetime, timezone
from pathlib import Path

def extract_file_info(file_path: str, json_path: str):
    file_path = Path(file_path)

    name = file_path.name
    sha256_hash = compute_sha256(file_path)
    file_extension = file_path.suffix
    modified_date = datetime.fromtimestamp(file_path.stat().st_mtime, timezone.utc)

    suspicious_strings = check_suspicious_strings(file_path, json_path)
    encoding_detected = check_encoding(file_path)
    num_text_sections, num_custom_sections = analyze_pe_file(file_path)

    return {
        "name": name,
        "sha256": sha256_hash,
        "extension": file_extension,
        "modified_date": modified_date,
        "suspicious_strings": suspicious_strings,
        "encoding": encoding_detected,
        "num_text_sections": num_text_sections,
        "num_custom_sections": num_custom_sections
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

def check_encoding(file_path: Path) -> bool:
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

def process_files_in_folder(folder_path: str, json_path: str):
    folder_path = Path(folder_path)
    results = []

    for file_path in folder_path.rglob('*'):
        if file_path.is_file():
            file_info = extract_file_info(file_path, json_path)
            results.append(file_info)
    return results

# --- EXECUÇÃO ---

folder_path = "Test-subjects/Benignos"  # <- AJUSTA conforme tua pasta real
json_path = "suspicious-strings.json"

all_file_info = process_files_in_folder(folder_path, json_path)

print(f"\n🔍 Nº de ficheiros processados: {len(all_file_info)}")

# Validar se há dados
if not all_file_info:
    print("⚠️ Nenhum ficheiro encontrado ou analisado. Verifica o caminho e o conteúdo da pasta.")
else:
    # Format data
    for item in all_file_info:
        if isinstance(item["modified_date"], datetime):
            item["modified_date"] = item["modified_date"].strftime("%Y-%m-%d %H:%M:%S")
        item["suspicious_strings"] = int(item["suspicious_strings"])
        item["encoding"] = int(item["encoding"])

    df = pd.DataFrame(all_file_info)

    expected_cols = [
        "name", "sha256", "extension", "modified_date", "suspicious_strings",
        "encoding", "num_text_sections", "num_custom_sections"
    ]

    # Reordenar colunas se possível
    if all(col in df.columns for col in expected_cols):
        df = df[expected_cols]
    else:
        print("⚠️ As colunas esperadas não foram todas encontradas. Usando ordem original.")
        print("Colunas disponíveis:", df.columns.tolist())

    # Exportar para CSV
    output_csv_path = "output_dataset.csv"
    df.to_csv(output_csv_path, index=False)
    print(f"\n✅ Dataset exportado com sucesso para '{output_csv_path}'")
