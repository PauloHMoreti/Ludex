"""
platforms.py - Motor de identificação e desambiguação de plataformas/consoles.
Combina mapeamento de extensões, leitura de cabeçalhos binários (magic numbers),
inspeção interna de arquivos compactados e heurísticas de diretórios ancestrais.
"""

from __future__ import annotations

import os
import re
import struct
import zipfile
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from config import (
    AMBIGUOUS_EXTENSIONS,
    ARCHIVE_EXTENSIONS,
    EXCLUSIVE_EXTENSION_TO_PLATFORM,
    FOLDER_PLATFORM_ALIASES,
    to_long_path,
)

# Importações opcionais para inspeção de listas de arquivos em .7z e .rar
try:
    import py7zr
except ImportError:
    py7zr = None  # type: ignore

try:
    import rarfile
except ImportError:
    rarfile = None  # type: ignore


# Regex para códigos de série da Sony (PS1, PS2, PSP, PS3) em nomes de arquivos/pastas
SONY_SERIAL_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # PSP: ULUS, ULES, ULJM, UCUS, UCES, UCJS, NPJH, NPUH, NPEH
    (re.compile(r"\b(?:ULUS|ULES|ULJM|ULAS|UCUS|UCES|UCJS|UCAS|NPJH|NPUH|NPEH)[-_ ]?\d{5}\b", re.I), "PSP"),
    # PS3: BLUS, BLES, BCUS, BCES, BLJM, BLAS, NPUA, NPEA, NPUB, NPEB
    (re.compile(r"\b(?:BLUS|BLES|BCUS|BCES|BLJM|BLAS|NPUA|NPEA|NPUB|NPEB)[-_ ]?\d{5}\b", re.I), "PS3"),
    # PS2: SLUS-2xxxx, SLES-5xxxx, SCUS-97xxx, SCES-5xxxx, SLPM-6xxxx
    (re.compile(r"\b(?:SLUS[-_ ]?2|SLES[-_ ]?5|SCUS[-_ ]?97|SCES[-_ ]?5|SLPM[-_ ]?6|SLPS[-_ ]?2)\d{3,4}\b", re.I), "PS2"),
    # PS1: SLUS-0xxxx, SLES-0xxxx, SCUS-94xxx, SCES-0xxxx, SLPS-0xxxx
    (re.compile(r"\b(?:SLUS[-_ ]?[089]|SLES[-_ ]?[01]|SCUS[-_ ]?94|SCES[-_ ]?0|SLPS[-_ ]?0)\d{3,4}\b", re.I), "PS1"),
]


def infer_platform_from_serial(text: str) -> Optional[str]:
    """Verifica códigos de catálogo (ex: SLUS-20062, ULUS-10041, BLUS-30443) no texto."""
    for pattern, platform in SONY_SERIAL_PATTERNS:
        if pattern.search(text):
            return platform
    return None


def infer_platform_from_path(
    target_path: Path,
    root_path: Optional[Path] = None,
) -> Optional[str]:
    """
    Infere a plataforma analisando os nomes das pastas ancestrais (da mais próxima
    até a raiz da varredura) e o próprio nome do arquivo/pasta.
    """
    # 1. Checar código serial explícito no nome do arquivo ou pasta pai
    serial_hit = infer_platform_from_serial(str(target_path))
    if serial_hit:
        return serial_hit

    # Coleta componentes do caminho (do item até a pasta raiz da varredura)
    parts_to_check: List[str] = [target_path.stem]
    try:
        current = target_path.parent
        stop_at = root_path.resolve() if root_path else None
        depth = 0
        while current and depth < 12:
            parts_to_check.append(current.name)
            if stop_at and current.resolve() == stop_at:
                break
            if current.parent == current:
                break
            current = current.parent
            depth += 1
    except OSError:
        pass

    # Percorre primeiro as pastas pais imediatas (mais confiáveis para organização por console)
    # e por último o nome do próprio arquivo
    ordered_parts = parts_to_check[1:] + [parts_to_check[0]]

    for part in ordered_parts:
        normalized = re.sub(r"[_\-\.\(\)\[\]]+", " ", part.lower()).strip()
        padded = f" {normalized} "
        for platform, aliases in FOLDER_PLATFORM_ALIASES:
            for alias in aliases:
                # Verifica correspondência exata da pasta ou token delimitado por espaços
                if normalized == alias or f" {alias} " in padded:
                    return platform

    return None


def detect_platform_by_magic(file_path: Path, file_size: int = 0) -> Optional[str]:
    """
    Lê cabeçalhos binários (magic numbers) e setores de volume (ISO 9660 / headers de ROM)
    para desambiguar arquivos como .iso, .chd, .bin, .pbp, .cso, .rvz, .ciso.
    """
    ext = file_path.suffix.lower()
    long_p = to_long_path(file_path)

    try:
        with open(long_p, "rb") as fp:
            header = fp.read(1024)
            if not header:
                return None

            # ------------------------------------------------------------------
            # 1. Verificações diretas de assinatura nos primeiros bytes
            # ------------------------------------------------------------------
            # RVZ / WIA (Dolphin GameCube / Wii)
            if header[:4] in (b"RVZ\x01", b"WIA\x01") and len(header) >= 76:
                console_type = struct.unpack(">I", header[0x48:0x4C])[0]
                if console_type == 1:
                    return "GameCube"
                if console_type == 2:
                    return "Wii"
                return "Wii"

            # WBFS (Wii Backup File System)
            if header[:4] == b"WBFS":
                return "Wii"

            # GameCube ISO / GCM (Magic word 0xC2339F3D no offset 0x1C)
            if len(header) >= 0x20 and header[0x1C:0x20] == b"\xc2\x33\x9f\x3d":
                return "GameCube"

            # Wii ISO (Magic word 0x5D1C9EA3 no offset 0x18)
            if len(header) >= 0x1C and header[0x18:0x1C] == b"\x5d\x1c\x9e\xa3":
                return "Wii"

            # CISO / CSO (Compressed ISO usado em PSP, PS2 e GameCube)
            if header[:4] == b"CISO":
                # No CISO de GameCube, o header de 32KB é seguido pelo disco GC
                if file_size > 0x8020:
                    fp.seek(0x801C)
                    gc_check = fp.read(4)
                    if gc_check == b"\xc2\x33\x9f\x3d":
                        return "GameCube"
                if ext == ".cso":
                    # UMD de PSP tem no máximo ~1.8 GB descomprimido
                    return "PSP" if file_size < 1_900_000_000 else "PS2"

            # PBP (EBOOT.PBP de PSP ou PS1 Classics)
            if header[:4] == b"\x00PBP":
                # Procura assinatura PSISOIMG0000 ou PSTITLEIMG0000 típica de PS1 no PSP
                fp.seek(0)
                sample = fp.read(262144)
                if b"PSISOIMG" in sample or b"PSTITLEIMG" in sample:
                    return "PS1"
                return "PSP"

            # PKG (PlayStation 3 Package)
            if header[:4] == b"\x7fPKG":
                return "PS3"

            # Switch XCI / NSP
            if len(header) >= 0x104 and header[0x100:0x104] == b"HEAD":
                return "Switch"
            if header[:4] == b"PFS0":
                return "Switch"

            # 3DS NCSD / NCCH
            if len(header) >= 0x104 and header[0x100:0x104] in (b"NCSD", b"NCCH"):
                return "3DS"

            # NES (iNES / FDS)
            if header[:4] in (b"NES\x1a", b"FDS\x1a"):
                return "NES"

            # N64 (Big-endian, Byte-swapped, Little-endian)
            if header[:4] in (b"\x80\x37\x12\x40", b"\x37\x80\x40\x12", b"\x40\x12\x37\x80"):
                return "N64"

            # Executável Windows / DOS (MZ)
            if header[:2] == b"MZ":
                return "PC"

            # Headers Sega no início da imagem (.bin / .iso)
            header_upper = header[:512].upper()
            if b"SEGA SEGAKATANA" in header_upper:
                return "Dreamcast"
            if b"SEGA SEGASATURN" in header_upper:
                return "Saturn"
            if b"SEGADISCSYSTEM" in header_upper:
                return "Sega CD"
            if b"SEGA MEGA DRIVE" in header_upper or b"SEGA GENESIS" in header_upper:
                return "Mega Drive"

            # CHD (MAME Compressed Hunks of Data v1-v5)
            if header[:8] == b"MComprHD":
                fp.seek(0)
                chd_sample = fp.read(65536)
                if b"GDTR" in chd_sample or b"SEGA SEGAKATANA" in chd_sample:
                    return "Dreamcast"
                if b"DVD " in chd_sample:
                    return "PS2"
                # Heurística de tamanho: CDs comprimidos em CHD raramente passam de 750 MB;
                # DVDs de PS2 costumam ser maiores que 800 MB.
                if file_size > 850_000_000:
                    return "PS2"
                return None

            # ------------------------------------------------------------------
            # 2. Inspeção de Volume ISO 9660 / Raw CD (Setor 16)
            # ------------------------------------------------------------------
            if ext in (".iso", ".bin", ".mdf", ".img") and file_size >= 0x9400:
                # Testa offset de setor 2048 bytes (0x8000) e setor raw CD 2352 bytes (0x9318)
                for pvd_offset in (0x8000, 0x9318, 0x8008):
                    if file_size <= pvd_offset + 2048:
                        continue
                    fp.seek(pvd_offset)
                    pvd = fp.read(2048)
                    if len(pvd) < 128 or pvd[1:6] != b"CD001":
                        continue

                    sys_id = pvd[8:40].decode("latin-1", errors="ignore").upper()
                    vol_id = pvd[40:72].decode("latin-1", errors="ignore").upper()

                    # Lê janela adicional (setores de diretório raiz da ISO) para achar arquivos-chave
                    fp.seek(pvd_offset)
                    iso_window = fp.read(131072).upper()

                    if "PSP GAME" in sys_id or b"PSP_GAME" in iso_window or b"UMD_DATA.BIN" in iso_window:
                        return "PSP"

                    if "PS3VOLUME" in sys_id or "PS3VOLUME" in vol_id or b"PS3_GAME" in iso_window or b"PS3_DISC.SFB" in iso_window:
                        return "PS3"

                    if "PLAYSTATION" in sys_id:
                        # PS2 possui BOOT2 no SYSTEM.CNF ou mídia DVD (> 850 MB)
                        if b"BOOT2" in iso_window or pvd_offset == 0x8000 and file_size > 850_000_000:
                            return "PS2"
                        if pvd_offset == 0x9318:
                            return "PS1"
                        return "PS2" if file_size > 800_000_000 else "PS1"

                    if b"SEGA SEGASATURN" in iso_window:
                        return "Saturn"
                    if b"SEGA SEGAKATANA" in iso_window:
                        return "Dreamcast"
                    if b"SEGADISCSYSTEM" in iso_window:
                        return "Sega CD"

                    # Indicadores fortes de ISO de instalação de PC
                    pc_iso_markers = (
                        b"AUTORUN.INF",
                        b"SETUP.EXE",
                        b"INSTALL.EXE",
                        b"DIRECTX",
                        b"VCREDIST",
                        b".MSI",
                        b"BOOTMGR",
                    )
                    if any(marker in iso_window for marker in pc_iso_markers):
                        return "PC"

    except (OSError, PermissionError, struct.error):
        return None

    return None


def inspect_cue_or_gdi_platform(file_path: Path, root_path: Optional[Path] = None) -> Tuple[str, List[Path]]:
    """
    Analisa um arquivo .cue ou .gdi, retornando a plataforma inferida e a lista
    de arquivos .bin/.raw/.iso referenciados por ele (para evitar duplicidade na varredura).
    """
    referenced_files: List[Path] = []
    ext = file_path.suffix.lower()
    parent = file_path.parent

    try:
        with open(to_long_path(file_path), "r", encoding="utf-8", errors="ignore") as fp:
            content = fp.read(65536)

        if ext == ".cue":
            # Extrai FILE "nome.bin" BINARY
            for match in re.finditer(r'FILE\s+(?:"([^"]+)"|(\S+))', content, re.I):
                fname = match.group(1) or match.group(2)
                if fname:
                    candidate = parent / fname
                    referenced_files.append(candidate)
        elif ext == ".gdi":
            # Formato GDI Dreamcast: linhas de track com nome do arquivo
            for line in content.splitlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 5:
                    # O nome pode estar entre aspas ou ser a 5ª coluna
                    q_match = re.search(r'"([^"]+)"', line)
                    fname = q_match.group(1) if q_match else parts[4]
                    referenced_files.append(parent / fname)
            return "Dreamcast", referenced_files
    except OSError:
        pass

    # Tenta descobrir a plataforma pelas pastas ancestrais
    path_plat = infer_platform_from_path(file_path, root_path)
    if path_plat:
        return path_plat, referenced_files

    # Se houver uma faixa .bin/.iso referenciada existente, inspeciona o magic number dela
    for ref in referenced_files:
        try:
            if os.path.exists(to_long_path(ref)):
                size = os.path.getsize(to_long_path(ref))
                magic_plat = detect_platform_by_magic(ref, size)
                if magic_plat:
                    return magic_plat, referenced_files
        except OSError:
            continue

    return "PS1", referenced_files


def list_archive_entries(archive_path: Path) -> List[str]:
    """
    Retorna a lista de nomes de arquivos contidos em um .zip, .7z ou .rar
    sem extrair o conteúdo para o disco.
    """
    ext = archive_path.suffix.lower()
    long_p = to_long_path(archive_path)

    try:
        if ext == ".zip":
            with zipfile.ZipFile(long_p, "r") as zf:
                return zf.namelist()
        elif ext == ".7z" and py7zr is not None:
            with py7zr.SevenZipFile(long_p, "r") as sz:
                return sz.getnames()
        elif ext == ".rar" and rarfile is not None:
            with rarfile.RarFile(long_p, "r") as rf:
                return rf.namelist()
    except Exception:
        return []
    return []


def infer_platform_from_archive_entries(
    entries: Iterable[str],
    archive_path: Path,
    root_path: Optional[Path] = None,
) -> Optional[str]:
    """
    Determina a plataforma de um arquivo compactado (.zip, .7z, .rar) analisando
    as extensões e estruturas dos arquivos em seu interior.
    """
    entry_list = list(entries)
    if not entry_list:
        return infer_platform_from_path(archive_path, root_path)

    lower_entries = [e.lower().replace("\\", "/") for e in entry_list]

    # 1. Verifica estruturas de pastas exclusivas dentro do arquivo compactado
    if any("ps3_game/" in e or e.endswith("ps3_disc.sfb") for e in lower_entries):
        return "PS3"
    if any("psp_game/" in e or e.endswith("umd_data.bin") for e in lower_entries):
        return "PSP"

    # 2. Verifica extensões exclusivas dentro do arquivo compactado
    for entry in lower_entries:
        ext = os.path.splitext(entry)[1]
        if ext in EXCLUSIVE_EXTENSION_TO_PLATFORM and ext not in (".exe", ".msi"):
            return EXCLUSIVE_EXTENSION_TO_PLATFORM[ext]

    # 3. Verifica se é um jogo/instalador de PC compactado
    has_exe = any(e.endswith((".exe", ".msi")) for e in lower_entries)
    has_pc_files = any(
        e.endswith((".dll", ".pak", ".pck", ".ini", ".bat"))
        or "steam_api" in e
        or "goggame" in e
        for e in lower_entries
    )
    if has_exe and (has_pc_files or len(lower_entries) >= 1):
        # Confere se o diretório ancestral não força um console (ex: ferramenta junto à ROM)
        ancestral = infer_platform_from_path(archive_path, root_path)
        if ancestral and ancestral != "PC":
            return ancestral
        return "PC"

    # 4. Verifica extensões ambíguas (.iso, .chd, .bin, .cue, etc.) combinadas com caminho ancestral
    ancestral = infer_platform_from_path(archive_path, root_path)
    if ancestral:
        return ancestral

    for entry in lower_entries:
        serial_hit = infer_platform_from_serial(entry)
        if serial_hit:
            return serial_hit
        ext = os.path.splitext(entry)[1]
        if ext in AMBIGUOUS_EXTENSIONS:
            return AMBIGUOUS_EXTENSIONS[ext][0]

    return None


def classify_file_platform(
    file_path: Path,
    root_path: Optional[Path] = None,
    file_size: Optional[int] = None,
    archive_entries: Optional[List[str]] = None,
) -> str:
    """
    Classifica a plataforma de um arquivo de jogo resolvendo qualquer ambiguidade
    na seguinte ordem de prioridade:
      1. Extensões exclusivas (ex: .sfc -> SNES, .gba -> GBA, .xci -> Switch, .wbfs -> Wii)
      2. Inspeção de conteúdo interno para arquivos compactados (.zip, .7z, .rar)
      3. Cabeçalhos binários / Magic Numbers (ex: GameCube vs Wii vs PS2 vs PSP vs PC em .iso)
      4. Nome de pasta ancestral ou código serial Sony (ex: pasta 'PS2', 'GameCube', 'SLUS-20062')
      5. Heurística de tamanho (ex: .iso / .chd > 850 MB -> PS2 vs CD <= 850 MB -> PS1)
    """
    ext = file_path.suffix.lower()

    if file_size is None:
        try:
            file_size = os.path.getsize(to_long_path(file_path))
        except OSError:
            file_size = 0

    # 1. Extensão exclusiva
    if ext in EXCLUSIVE_EXTENSION_TO_PLATFORM:
        return EXCLUSIVE_EXTENSION_TO_PLATFORM[ext]

    # 2. Arquivos compactados (.zip, .7z, .rar)
    if ext in ARCHIVE_EXTENSIONS:
        entries = archive_entries if archive_entries is not None else list_archive_entries(file_path)
        arch_plat = infer_platform_from_archive_entries(entries, file_path, root_path)
        if arch_plat:
            return arch_plat
        return infer_platform_from_path(file_path, root_path) or "Desconhecida (Arquivo Compactado)"

    # 3. Arquivos .cue ou .gdi
    if ext in (".cue", ".gdi"):
        cue_plat, _ = inspect_cue_or_gdi_platform(file_path, root_path)
        return cue_plat

    # 4. Magic Numbers / Cabeçalho binário
    magic_plat = detect_platform_by_magic(file_path, file_size)
    if magic_plat:
        return magic_plat

    # 5. Caminho ancestral / Serial no nome
    path_plat = infer_platform_from_path(file_path, root_path)
    if path_plat:
        # Se a extensão é compatível ou genérica, retorna a plataforma da pasta ancestral
        return path_plat

    # 6. Heurísticas de desempate por tamanho para extensões ambíguas (.iso, .chd, .bin, .cso)
    if ext in (".iso", ".chd"):
        if file_size > 850_000_000:
            return "PS2"
        return "PS1"
    if ext == ".bin":
        if file_size <= 12 * 1024 * 1024:
            return "Mega Drive"
        return "PS1"
    if ext in AMBIGUOUS_EXTENSIONS:
        return AMBIGUOUS_EXTENSIONS[ext][0]

    return "Desconhecida"
