"""
integrity.py - Verificação de integridade e detecção de corrupção em arquivos
compactados (.zip, .7z, .rar com fallback gracioso), ROMs, ISOs e pastas de jogos.
"""

from __future__ import annotations

import os
import re
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from config import (
    ARCHIVE_EXTENSIONS,
    INTEGRITY_SAMPLE_BYTES,
    MIN_VALID_SIZE_BYTES,
    to_long_path,
)

# Importações opcionais com fallback gracioso
try:
    import py7zr
except ImportError:
    py7zr = None  # type: ignore

try:
    import rarfile
except ImportError:
    rarfile = None  # type: ignore


@dataclass
class IntegrityResult:
    """Resultado consolidado da auditoria de integridade de um jogo/arquivo."""

    is_corrupted: bool
    status_label: str  # "Sim (Corrompido)" ou "Não"
    notes: List[str] = field(default_factory=list)
    archive_entries: List[str] = field(default_factory=list)

    @classmethod
    def ok(
        cls,
        notes: Optional[List[str]] = None,
        archive_entries: Optional[List[str]] = None,
    ) -> "IntegrityResult":
        return cls(
            is_corrupted=False,
            status_label="Não",
            notes=notes or [],
            archive_entries=archive_entries or [],
        )

    @classmethod
    def corrupted(
        cls,
        reason: str,
        archive_entries: Optional[List[str]] = None,
    ) -> "IntegrityResult":
        return cls(
            is_corrupted=True,
            status_label="Sim (Corrompido)",
            notes=[reason],
            archive_entries=archive_entries or [],
        )


# Assinaturas mágicas estritas para formatos que obrigatoriamente começam com bytes fixos
STRICT_MAGIC_SIGNATURES = {
    ".wbfs": (b"WBFS",),
    ".rvz": (b"RVZ\x01", b"WIA\x01"),
    ".wia": (b"WIA\x01", b"RVZ\x01"),
    ".chd": (b"MComprHD",),
    ".pbp": (b"\x00PBP",),
    ".pkg": (b"\x7fPKG",),
    ".cso": (b"CISO", b"ZISO"),
    ".exe": (b"MZ", b"ZM"),
}


def check_raw_bytes_integrity(file_path: Path, file_size: Optional[int] = None) -> IntegrityResult:
    """
    Valida tamanho mínimo, leitura física dos bytes iniciais e finais (64 KB),
    detecção de arquivos inteiramente zerados (dummy/corrompidos) e cabeçalhos mágicos.
    """
    ext = file_path.suffix.lower()
    long_p = to_long_path(file_path)

    try:
        if file_size is None:
            file_size = os.path.getsize(long_p)
    except PermissionError:
        return IntegrityResult.corrupted("Permissão negada ao acessar o arquivo")
    except FileNotFoundError:
        return IntegrityResult.corrupted("Arquivo não encontrado ou link quebrado")
    except OSError as exc:
        return IntegrityResult.corrupted(f"Erro de sistema ao ler metadados: {exc}")

    if file_size <= 0:
        return IntegrityResult.corrupted("Arquivo vazio (0 bytes)")

    min_size = MIN_VALID_SIZE_BYTES.get(ext, 16)
    if file_size < min_size:
        return IntegrityResult.corrupted(
            f"Tamanho inválido/truncado ({file_size} B < mínimo de {min_size} B para {ext or 'arquivo'})"
        )

    try:
        with open(long_p, "rb") as fp:
            head_len = min(INTEGRITY_SAMPLE_BYTES, file_size)
            head_bytes = fp.read(head_len)
            if len(head_bytes) < head_len:
                return IntegrityResult.corrupted("Falha ao ler os bytes iniciais (EOF prematuro)")

            # Se o arquivo é maior que a janela inicial, testa leitura dos bytes finais
            tail_bytes = b""
            if file_size > INTEGRITY_SAMPLE_BYTES:
                tail_offset = max(0, file_size - INTEGRITY_SAMPLE_BYTES)
                fp.seek(tail_offset)
                tail_len = file_size - tail_offset
                tail_bytes = fp.read(tail_len)
                if len(tail_bytes) < tail_len:
                    return IntegrityResult.corrupted("Falha ao ler os bytes finais do arquivo (truncado)")

            # Verifica se o arquivo inteiro (ou amostras de início e fim) contém apenas zeros (0x00)
            if ext not in (".cue", ".gdi") and file_size >= 1024:
                if head_bytes.count(0) == len(head_bytes) and (
                    not tail_bytes or tail_bytes.count(0) == len(tail_bytes)
                ):
                    return IntegrityResult.corrupted("Cabeçalho e final compostos apenas por bytes nulos (0x00)")

            # Verifica assinatura mágica estrita quando aplicável
            if ext in STRICT_MAGIC_SIGNATURES:
                valid_prefixes = STRICT_MAGIC_SIGNATURES[ext]
                if not any(head_bytes.startswith(prefix) for prefix in valid_prefixes):
                    return IntegrityResult.corrupted(
                        f"Cabeçalho binário inválido para a extensão {ext}"
                    )

            # Verificação específica para GameCube .gcm
            if ext == ".gcm" and len(head_bytes) >= 0x20:
                if head_bytes[0x1C:0x20] != b"\xc2\x33\x9f\x3d":
                    return IntegrityResult.corrupted(
                        "Magic word de GameCube (0xC2339F3D) ausente no cabeçalho .gcm"
                    )

    except PermissionError:
        return IntegrityResult.corrupted("Arquivo bloqueado ou sem permissão de leitura")
    except OSError as exc:
        return IntegrityResult.corrupted(f"Erro de I/O na leitura de bytes: {exc}")

    return IntegrityResult.ok()


def check_zip_integrity(file_path: Path, deep_crc: bool = True) -> IntegrityResult:
    """
    Testa a integridade interna de um arquivo .zip usando zipfile.
    Verifica cabeçalho PK, diretório central e CRC-32 dos arquivos internos.
    """
    raw_check = check_raw_bytes_integrity(file_path)
    if raw_check.is_corrupted:
        return raw_check

    long_p = to_long_path(file_path)
    try:
        if not zipfile.is_zipfile(long_p):
            return IntegrityResult.corrupted("Assinatura ZIP inválida ou Central Directory corrompido")

        with zipfile.ZipFile(long_p, "r") as zf:
            entries = zf.namelist()
            if not entries:
                return IntegrityResult.corrupted("Arquivo .zip vazio (sem arquivos internos)")

            if deep_crc:
                try:
                    bad_member = zf.testzip()
                    if bad_member is not None:
                        return IntegrityResult.corrupted(
                            f"Falha de CRC no arquivo interno: {bad_member}",
                            archive_entries=entries,
                        )
                except RuntimeError as exc:
                    # Arquivos protegidos por senha lançam RuntimeError no testzip()
                    msg = str(exc).lower()
                    if "encrypted" in msg or "password" in msg:
                        return IntegrityResult.ok(
                            notes=["Arquivo .zip protegido por senha (estrutura de catálogo íntegra)"],
                            archive_entries=entries,
                        )
                    return IntegrityResult.corrupted(f"Erro em runtime ao validar ZIP: {exc}", entries)

            return IntegrityResult.ok(archive_entries=entries)

    except (zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error, EOFError) as exc:
        return IntegrityResult.corrupted(f"ZIP corrompido: {exc}")
    except PermissionError:
        return IntegrityResult.corrupted("Permissão negada ao abrir arquivo .zip")
    except OSError as exc:
        return IntegrityResult.corrupted(f"Erro de I/O ao testar .zip: {exc}")


def _check_7z_signature_fallback(file_path: Path) -> IntegrityResult:
    """
    Valida a estrutura do SignatureHeader de 32 bytes do formato 7z (incluindo CRC32 do StartHeader)
    caso a biblioteca py7zr não esteja instalada ou use um filtro externo não suportado.
    """
    long_p = to_long_path(file_path)
    try:
        with open(long_p, "rb") as fp:
            sig_header = fp.read(32)
            if len(sig_header) < 32 or sig_header[:6] != b"7z\xbc\xaf\x27\x1c":
                return IntegrityResult.corrupted("Assinatura mágica 7z inválida")

            # Bytes 8..12: CRC32 dos próximos 20 bytes (StartHeader: NextHeaderOffset, NextHeaderSize, NextHeaderCRC)
            expected_crc = struct.unpack("<I", sig_header[8:12])[0]
            start_header = sig_header[12:32]
            actual_crc = zlib.crc32(start_header) & 0xFFFFFFFF
            if expected_crc != actual_crc:
                return IntegrityResult.corrupted("CRC do cabeçalho inicial 7z inválido")

            next_offset, next_size, _ = struct.unpack("<QQI", start_header)
            file_size = os.path.getsize(long_p)
            if 32 + next_offset + next_size > file_size:
                return IntegrityResult.corrupted("Arquivo .7z truncado (NextHeader além do fim do arquivo)")

    except OSError as exc:
        return IntegrityResult.corrupted(f"Erro ao validar cabeçalho .7z: {exc}")

    return IntegrityResult.ok(notes=["Integridade .7z validada via SignatureHeader CRC"])


def check_7z_integrity(file_path: Path, deep_crc: bool = True) -> IntegrityResult:
    """
    Testa a integridade interna de um arquivo .7z usando py7zr, com fallback
    de verificação estrutural de cabeçalho/CRC caso py7zr não esteja disponível.
    """
    raw_check = check_raw_bytes_integrity(file_path)
    if raw_check.is_corrupted:
        return raw_check

    # Verifica assinatura mágica 7z (37 7A BC AF 27 1C)
    sig_check = _check_7z_signature_fallback(file_path)
    if sig_check.is_corrupted:
        return sig_check

    if py7zr is None:
        return sig_check

    long_p = to_long_path(file_path)
    try:
        with py7zr.SevenZipFile(long_p, mode="r") as sz:
            entries = sz.getnames()
            if not entries:
                return IntegrityResult.corrupted("Arquivo .7z vazio")
            if deep_crc:
                ok_test = sz.test()
                if ok_test is False:
                    return IntegrityResult.corrupted("Falha na verificação interna de CRC do .7z", entries)
            return IntegrityResult.ok(archive_entries=entries)
    except Exception as exc:
        exc_name = type(exc).__name__
        msg = str(exc)
        if "PasswordRequired" in exc_name or "password" in msg.lower():
            return IntegrityResult.ok(notes=["Arquivo .7z protegido por senha"])
        if "UnsupportedCompressionMethod" in exc_name:
            return IntegrityResult.ok(
                notes=["Método de compressão 7z específico (cabeçalho validado com sucesso)"]
            )
        return IntegrityResult.corrupted(f"Arquivo .7z corrompido ({exc_name}: {msg})")


def _check_rar_signature_fallback(file_path: Path, note_reason: str) -> IntegrityResult:
    """
    Fallback gracioso para arquivos .rar quando o utilitário externo unrar não está instalado.
    Verifica assinaturas RAR 4.x (Rar!\\x1a\\x07\\x00) e RAR 5.0 (Rar!\\x1a\\x07\\x01\\x00)
    e leitura das extremidades do arquivo.
    """
    long_p = to_long_path(file_path)
    try:
        with open(long_p, "rb") as fp:
            magic = fp.read(8)
            is_rar4 = magic.startswith(b"Rar!\x1a\x07\x00")
            is_rar5 = magic.startswith(b"Rar!\x1a\x07\x01\x00")
            if not (is_rar4 or is_rar5):
                return IntegrityResult.corrupted("Assinatura mágica RAR4/RAR5 inválida")
    except OSError as exc:
        return IntegrityResult.corrupted(f"Erro de leitura no arquivo .rar: {exc}")

    return IntegrityResult.ok(notes=[note_reason])


def check_rar_integrity(file_path: Path, deep_crc: bool = True) -> IntegrityResult:
    """
    Testa a integridade interna de um arquivo .rar usando rarfile.
    Possui fallback gracioso automático caso o binário 'unrar' não esteja instalado no sistema.
    """
    raw_check = check_raw_bytes_integrity(file_path)
    if raw_check.is_corrupted:
        return raw_check

    # Valida assinatura RAR antes de invocar rarfile
    sig_res = _check_rar_signature_fallback(
        file_path,
        "Integridade RAR validada por assinatura/bytes (binário unrar não encontrado para teste profundo)",
    )
    if sig_res.is_corrupted:
        return sig_res

    if rarfile is None:
        return sig_res

    long_p = to_long_path(file_path)
    try:
        with rarfile.RarFile(long_p, "r") as rf:
            entries = rf.namelist()
            if not entries:
                return IntegrityResult.corrupted("Arquivo .rar sem conteúdo interno")
            if deep_crc:
                rf.testrar()
            return IntegrityResult.ok(archive_entries=entries)
    except Exception as exc:
        exc_name = type(exc).__name__
        msg = str(exc)
        # Fallback gracioso caso o binário unrar/unar/bsdtar não esteja instalado no sistema
        if "RarCannotExec" in exc_name or "cannot find working tool" in msg.lower() or "unrar" in msg.lower():
            return sig_res
        if "Password" in exc_name or "password" in msg.lower() or "encrypted" in msg.lower():
            return IntegrityResult.ok(notes=["Arquivo .rar protegido por senha"])
        return IntegrityResult.corrupted(f"Arquivo .rar corrompido ({exc_name}: {msg})")


def check_cue_or_gdi_integrity(descriptor_path: Path) -> IntegrityResult:
    """
    Verifica a integridade de um arquivo .cue ou .gdi e valida se todos os arquivos
    de faixa (.bin, .iso, .raw, .wav) referenciados existem e são íntegros.
    """
    raw_res = check_raw_bytes_integrity(descriptor_path, file_size=None)
    if raw_res.is_corrupted:
        return raw_res

    ext = descriptor_path.suffix.lower()
    parent = descriptor_path.parent
    referenced: List[Path] = []

    try:
        with open(to_long_path(descriptor_path), "r", encoding="utf-8", errors="ignore") as fp:
            content = fp.read(65536)

        if ext == ".cue":
            for match in re.finditer(r'FILE\s+(?:"([^"]+)"|(\S+))', content, re.I):
                fname = match.group(1) or match.group(2)
                if fname:
                    referenced.append(parent / fname)
        elif ext == ".gdi":
            for line in content.splitlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 5:
                    q_match = re.search(r'"([^"]+)"', line)
                    fname = q_match.group(1) if q_match else parts[4]
                    referenced.append(parent / fname)
    except OSError as exc:
        return IntegrityResult.corrupted(f"Erro ao ler descritor {ext}: {exc}")

    if not referenced:
        return IntegrityResult.corrupted(f"Descritor {ext} não referencia nenhuma faixa de dados válida")

    for track_path in referenced:
        if not os.path.exists(to_long_path(track_path)):
            return IntegrityResult.corrupted(f"Faixa ausente referenciada pelo {ext}: {track_path.name}")
        track_check = check_raw_bytes_integrity(track_path)
        if track_check.is_corrupted:
            return IntegrityResult.corrupted(
                f"Faixa '{track_path.name}' corrompida: {'; '.join(track_check.notes)}"
            )

    return IntegrityResult.ok(notes=[f"Descritor {ext} e {len(referenced)} faixa(s) validados"])


def check_item_integrity(
    target_path: Path,
    is_directory: bool = False,
    primary_files: Optional[List[Path]] = None,
    deep_archive_check: bool = True,
) -> IntegrityResult:
    """
    Ponto de entrada unificado para auditar a integridade de qualquer item da biblioteca:
    - Arquivos compactados (.zip, .7z, .rar)
    - Descritores multi-faixa (.cue, .gdi)
    - ROMs e ISOs avulsas
    - Pastas de jogos (PC, PS3, Wii U) através de seus binários principais
    """
    if not is_directory:
        ext = target_path.suffix.lower()
        if ext == ".zip":
            return check_zip_integrity(target_path, deep_crc=deep_archive_check)
        if ext == ".7z":
            return check_7z_integrity(target_path, deep_crc=deep_archive_check)
        if ext == ".rar":
            return check_rar_integrity(target_path, deep_crc=deep_archive_check)
        if ext in (".cue", ".gdi"):
            return check_cue_or_gdi_integrity(target_path)
        return check_raw_bytes_integrity(target_path)

    # Caso seja um diretório de jogo (ex: pasta de jogo de PC, PS3_GAME ou Wii U)
    files_to_test = primary_files or []
    if not files_to_test:
        return IntegrityResult.corrupted("Diretório do jogo não contém binários/arquivos principais válidos")

    notes: List[str] = []
    for pf in files_to_test[:5]:  # Testa até 5 binários principais da pasta do jogo
        res = check_item_integrity(pf, is_directory=False, deep_archive_check=deep_archive_check)
        if res.is_corrupted:
            return IntegrityResult.corrupted(f"Binário '{pf.name}': {'; '.join(res.notes)}")
        notes.extend(res.notes)

    return IntegrityResult.ok(notes=notes)
