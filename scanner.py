"""
scanner.py - Varredura recursiva de diretórios, identificação de entidades de jogos
(arquivos avulsos, imagens multi-faixa e pastas estruturadas de PC/PS3/WiiU),
detecção de Crack/DRM, detecção de Tradução/Localização e Deduplicação inteligente
(agrupamento por tamanho exato em bytes + SHA-256 em chunks de 64KB + assinatura normalizada).
"""

from __future__ import annotations

import hashlib
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from config import (
    ALL_GAME_FILE_EXTENSIONS,
    ARCHIVE_EXTENSIONS,
    HASH_CHUNK_SIZE,
    NATIVE_PTBR_KEYWORDS,
    PC_SCENE_AND_CRACK_INDICATORS,
    PC_STORE_DRM_INDICATORS,
    PC_UTILITY_EXE_PATTERNS,
    TRANSLATION_MOD_KEYWORDS,
    TRANSLATION_ROM_KEYWORDS,
    clean_display_path,
    to_long_path,
)
from integrity import IntegrityResult, check_item_integrity
from metadata import MetadataEnricher, normalize_signature_key, sanitize_game_name
from platforms import (
    classify_file_platform,
    infer_platform_from_path,
    inspect_cue_or_gdi_platform,
)


@dataclass
class GameRecord:
    """Representa uma unidade/jogo catalogada e auditada na biblioteca."""

    raw_name: str
    target_path: Path
    display_path: str
    is_directory: bool
    platform: str
    size_bytes: int = 0
    primary_files: List[Path] = field(default_factory=list)
    auxiliary_names: List[str] = field(default_factory=list)

    # Campos enriquecidos e auditados para exportação
    official_name: str = ""
    release_year: str = "N/D"
    genre: str = "N/D"
    official_language: str = "Inglês / Padrão"
    translation_status: str = "Não detectada"  # "Mod Local", "ROM Traduzida", "Nativo PT-BR", "Não detectada"
    crack_drm_status: str = "N/A (Console)"
    duplicate_status: str = "Não"              # "Sim (X cópias)" ou "Não"
    corrupted_status: str = "Não"              # "Sim (Corrompido)" ou "Não"
    is_corrupted: bool = False
    is_duplicate: bool = False
    sha256_hash: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    @property
    def observations_text(self) -> str:
        """Retorna todas as observações consolidadas e sem duplicatas para a planilha."""
        seen: Set[str] = set()
        unique_notes: List[str] = []
        for note in self.notes:
            cleaned = note.strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                unique_notes.append(cleaned)
        return " | ".join(unique_notes) if unique_notes else "OK"


# Subpastas internas comuns de um único jogo de PC instalado (não são jogos separados)
PC_INTERNAL_SUBFOLDER_NAMES: Set[str] = {
    "bin",
    "binaries",
    "x64",
    "x86",
    "win64",
    "win32",
    "engine",
    "data",
    "gamedata",
    "content",
    "paks",
    "pak",
    "monobleedingedge",
    "mono",
    "redist",
    "_commonredist",
    "directx",
    "vcredist",
    "support",
    "crack",
    "codex",
    "flt",
    "rune",
    "tenoke",
    "razor1911",
    "reloaded",
    "skidrow",
    "plaza",
    "hoodlum",
    "empress",
    "cpy",
    "goldberg",
    "no-cd",
    "nocd",
    "nodvd",
    "patch",
    "update",
    "dlc",
    "mods",
    "traducao",
    "tradução",
    "soundtrack",
    "ost",
    "bonus",
    "manual",
    "docs",
    "save",
    "saves",
    "profiles",
    " logs",
    "shaders",
    "movies",
    "video",
    "videos",
    "audio",
    "sound",
    "sounds",
    "music",
    "textures",
    "levels",
    "maps",
    "scripts",
    "plugins",
    "locales",
    "localization",
    "lang",
    "languages",
}


def compute_sha256(file_path: Path) -> Optional[str]:
    """
    Calcula o hash SHA-256 de um arquivo lendo em blocos de 64 KB (HASH_CHUNK_SIZE).
    Resiliente a caminhos longos do Windows e bloqueios de permissão.
    """
    long_p = to_long_path(file_path)
    hasher = hashlib.sha256()
    try:
        with open(long_p, "rb") as fp:
            while True:
                chunk = fp.read(HASH_CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except OSError:
        return None


def is_utility_executable(file_name: str) -> bool:
    """Retorna True se o .exe for um desinstalador, redistribuível ou crash handler."""
    lower = file_name.lower()
    return any(pat in lower for pat in PC_UTILITY_EXE_PATTERNS)


def detect_crack_drm(
    platform: str,
    raw_name: str,
    auxiliary_names: Iterable[str],
) -> Tuple[str, List[str]]:
    """
    Detecta Crack / DRM para jogos classificados como 'PC'.
    Para consoles/emuladores, retorna obrigatoriamente 'N/A (Console)'.
    """
    if platform != "PC":
        return "N/A (Console)", []

    corpus = [raw_name.lower()] + [a.lower() for a in auxiliary_names]
    joined_corpus = " | ".join(corpus)

    detected_cracks: List[str] = []
    detected_stores: List[str] = []
    notes: List[str] = []

    # 1. Verifica indicadores de Crack / Grupos de Cena / Emuladores de Steam
    for token, label in PC_SCENE_AND_CRACK_INDICATORS.items():
        # Para siglas curtas (ex: flt, cpy, cdx), exige fronteira de palavra ou nome de arquivo
        if len(token) <= 4 and "." not in token:
            pattern = rf"\b{re.escape(token)}\b"
            if re.search(pattern, joined_corpus):
                if label not in detected_cracks:
                    detected_cracks.append(label)
        else:
            if token in joined_corpus:
                if label not in detected_cracks:
                    detected_cracks.append(label)

    # 2. Verifica indicadores de Loja / DRM (steam_api.dll, GOG, Epic, Ubisoft)
    for token, label in PC_STORE_DRM_INDICATORS.items():
        if len(token) <= 4 and "." not in token:
            if re.search(rf"\b{re.escape(token)}\b", joined_corpus):
                if label not in detected_stores:
                    detected_stores.append(label)
        else:
            if token in joined_corpus:
                if label not in detected_stores:
                    detected_stores.append(label)

    if detected_cracks:
        primary_crack = detected_cracks[0]
        if any("steam_api" in s.lower() for s in detected_stores):
            notes.append("Detectado steam_api.dll junto a arquivos/assinatura de cena")
            return f"{primary_crack} + steam_api.dll", notes
        return primary_crack, notes

    if detected_stores:
        return detected_stores[0], notes

    return "Não detectado / Binário Padrão", notes


def detect_translation_status(
    platform: str,
    raw_name: str,
    auxiliary_names: Iterable[str],
    api_supported_languages: str = "",
) -> Tuple[str, Optional[str]]:
    """
    Detecta o status de tradução/localização PT-BR do jogo e classifica como:
    - 'Mod Local' (patches GameVicio, Tribo Gamer, pasta/instalador de tradução)
    - 'ROM Traduzida' (tags [T-Por], [PT-BR] em ROMs/ISOs ou patches .ips/.bps/.xdelta)
    - 'Nativo PT-BR' (suporte nativo detectado nos arquivos de localização ou API)
    - 'Não detectada'
    """
    aux_lower = [a.lower() for a in auxiliary_names]
    raw_lower = raw_name.lower()
    all_text = " | ".join([raw_lower] + aux_lower)

    # 1. Verifica Mod Local (GameVicio, Tribo Gamer, pasta/arquivo 'traducao', etc.)
    for kw in TRANSLATION_MOD_KEYWORDS:
        if kw in all_text:
            return "Mod Local", f"Indicador de tradução local detectado ('{kw}')"

    # Verifica arquivos de patch de tradução soltos (.ips, .bps, .xdelta, .ppf)
    if any(a.endswith((".ips", ".bps", ".xdelta", ".ups", ".ppf")) for a in aux_lower):
        if platform == "PC":
            return "Mod Local", "Arquivo de patch local (.ips/.bps/.xdelta) encontrado"
        return "ROM Traduzida", "Patch de ROM (.ips/.bps/.xdelta/.ppf) encontrado"

    # 2. Verifica ROM Traduzida (tags como [T-Por], [PT-BR], Traduzido em ROMs de console)
    for kw in TRANSLATION_ROM_KEYWORDS:
        if kw in all_text:
            if platform == "PC":
                return "Mod Local", f"Tag de tradução detectada ('{kw}')"
            return "ROM Traduzida", f"Tag de ROM traduzida detectada ('{kw}')"

    # Se é console clássico e possui "pt-br" explícito no nome do arquivo da ROM
    if platform not in ("PC", "PS3", "Switch") and any(
        k in raw_lower for k in ("pt-br", "pt_br", "ptbr", "portugues", "português")
    ):
        return "ROM Traduzida", "Indicador PT-BR no nome da ROM"

    # 3. Verifica Nativo PT-BR (arquivos de idioma nativos ou metadados da API)
    for kw in NATIVE_PTBR_KEYWORDS:
        if kw in all_text:
            return "Nativo PT-BR", f"Localização PT-BR nativa detectada ('{kw}')"

    api_lang_lower = api_supported_languages.lower()
    if any(k in api_lang_lower for k in ("portuguese", "português", "portugues", "pt-br", "brazil")):
        return "Nativo PT-BR", "Suporte oficial ao idioma Português confirmado via metadados"

    return "Não detectada", None


def _collect_directory_summary(
    dir_path: Path,
    max_files: int = 2500,
) -> Tuple[int, List[Path], List[str], List[str]]:
    """
    Percorre um diretório de jogo (ex: pasta de jogo de PC, PS3 ou Wii U) para calcular
    o tamanho total em bytes, localizar os executáveis/binários principais e coletar
    nomes de arquivos/pastas auxiliares (para detecção de Crack/DRM e Tradução).
    """
    total_size = 0
    primary_executables: List[Path] = []
    utility_executables: List[Path] = []
    auxiliary_names: List[str] = []
    notes: List[str] = []
    files_seen = 0

    stack: List[Path] = [dir_path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(to_long_path(current)) as it:
                for entry in it:
                    try:
                        name = entry.name
                        auxiliary_names.append(name)
                        entry_path = current / name

                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry_path)
                        elif entry.is_file(follow_symlinks=False):
                            files_seen += 1
                            st = entry.stat(follow_symlinks=False)
                            total_size += st.st_size
                            lower_name = name.lower()

                            if lower_name.endswith((".exe", ".msi", ".rpx")) or lower_name in (
                                "eboot.bin",
                                "param.sfo",
                            ):
                                if is_utility_executable(lower_name):
                                    utility_executables.append(entry_path)
                                else:
                                    primary_executables.append(entry_path)
                    except PermissionError:
                        notes.append(f"Permissão negada em '{entry.name}'")
                    except OSError:
                        continue
        except PermissionError:
            notes.append(f"Permissão negada ao abrir subpasta '{current.name}'")
        except OSError as exc:
            notes.append(f"Erro de acesso em '{current.name}': {exc}")

        if files_seen >= max_files:
            break

    # Ordena executáveis principais por tamanho decrescente (o binário principal do jogo costuma ser o maior)
    primary_executables.sort(
        key=lambda p: os.path.getsize(to_long_path(p)) if os.path.exists(to_long_path(p)) else 0,
        reverse=True,
    )
    chosen_bins = primary_executables if primary_executables else utility_executables
    return total_size, chosen_bins, auxiliary_names, notes


def _inspect_directory_as_game_unit(
    dir_path: Path,
    root_path: Path,
) -> Optional[Tuple[str, List[Path]]]:
    """
    Avalia se `dir_path` deve ser tratado como uma única unidade/entidade de jogo
    (ex: pasta de jogo de PC, pasta PS3_GAME, pasta Wii U com .rpx) em vez de uma
    pasta organizacional de categorias/consoles.
    Retorna `(plataforma, lista_de_arquivos_principais_imediatos)` ou `None`.
    """
    if dir_path.resolve() == root_path.resolve():
        return None

    try:
        entries = list(os.scandir(to_long_path(dir_path)))
    except OSError:
        return None

    subdirs: List[os.DirEntry] = []
    files: List[os.DirEntry] = []
    for e in entries:
        try:
            if e.is_dir(follow_symlinks=False):
                subdirs.append(e)
            elif e.is_file(follow_symlinks=False):
                files.append(e)
        except OSError:
            continue

    file_names_lower = {f.name.lower() for f in files}
    subdir_names_lower = {d.name.lower() for d in subdirs}

    # 1. Pasta estruturada de PS3 (contém pasta PS3_GAME ou é a própria pasta com PARAM.SFO / EBOOT.BIN)
    if (
        "ps3_game" in subdir_names_lower
        or "ps3_disc.sfb" in file_names_lower
        or ("param.sfo" in file_names_lower and "usrdir" in subdir_names_lower)
    ):
        return "PS3", []

    # 2. Pasta estruturada de Wii U (contém code/content/meta ou arquivo .rpx)
    if any(fn.endswith(".rpx") for fn in file_names_lower) or (
        {"code", "content", "meta"}.issubset(subdir_names_lower)
    ):
        return "Wii U", []

    # 3. Verifica se a pasta contém ROMs de consoles exclusivas soltas:
    # Se contiver múltiplas ROMs de console (ex: vários .sfc, .nes, .gba, .iso), é pasta organizacional!
    non_pc_rom_files = [
        f for f in files
        if os.path.splitext(f.name.lower())[1] in (ALL_GAME_FILE_EXTENSIONS - {".exe", ".msi", ".bin", ".iso", ".zip", ".7z", ".rar"})
    ]
    if len(non_pc_rom_files) >= 2:
        return None

    # 4. Verifica se é uma pasta de um Jogo de PC:
    # - Possui .exe/.msi diretamente na raiz da pasta do jogo, OU
    # - Possui DLLs/arquivos marcadores de PC (steam_api.dll, steam_api64.dll, goggame*, UnityPlayer.dll, autorun.inf), OU
    # - Possui subpastas típicas de motor de jogo de PC (Binaries, Engine, Data, MonoBleedingEdge, Crack, etc.) com .exe lá dentro.
    direct_exes = [
        dir_path / f.name
        for f in files
        if f.name.lower().endswith((".exe", ".msi"))
    ]
    has_pc_marker_file = any(
        fn in ("steam_api.dll", "steam_api64.dll", "unityplayer.dll", "autorun.inf", "dosbox.conf", "steam_appid.txt")
        or fn.startswith("goggame-")
        for fn in file_names_lower
    )

    if direct_exes or has_pc_marker_file:
        return "PC", direct_exes

    # Verifica se as subpastas imediatas são subpastas internas de um único jogo de PC (ex: Binaries/Win64/*.exe, bin/x64/*.exe)
    if subdir_names_lower and subdir_names_lower.issubset(PC_INTERNAL_SUBFOLDER_NAMES):
        # Procura .exe até 2 níveis abaixo
        nested_exes: List[Path] = []
        for sd in subdirs:
            sd_path = dir_path / sd.name
            try:
                for sub_e in os.scandir(to_long_path(sd_path)):
                    if sub_e.is_file(follow_symlinks=False) and sub_e.name.lower().endswith((".exe", ".msi")):
                        nested_exes.append(sd_path / sub_e.name)
                    elif sub_e.is_dir(follow_symlinks=False) and sub_e.name.lower() in PC_INTERNAL_SUBFOLDER_NAMES:
                        for sub2_e in os.scandir(to_long_path(sd_path / sub_e.name)):
                            if sub2_e.is_file(follow_symlinks=False) and sub2_e.name.lower().endswith((".exe", ".msi")):
                                nested_exes.append(sd_path / sub_e.name / sub2_e.name)
            except OSError:
                continue
        if nested_exes:
            return "PC", nested_exes

    return None


class LibraryScanner:
    """
    Motor de varredura recursiva, auditoria de integridade, detecção de DRM/Tradução,
    enriquecimento de metadados e deduplicação da biblioteca de jogos.
    """

    def __init__(
        self,
        root_dir: Path,
        enricher: Optional[MetadataEnricher] = None,
        deep_archive_check: bool = True,
        hash_all_files: bool = False,
    ) -> None:
        self.root_dir = Path(clean_display_path(root_dir)).resolve()
        self.enricher = enricher or MetadataEnricher(offline_mode=True)
        self.deep_archive_check = deep_archive_check
        self.hash_all_files = hash_all_files
        self.scan_errors: List[str] = []

    def discover_candidates(self) -> List[GameRecord]:
        """
        Fase 1: Inspeciona recursivamente o diretório raiz e identifica todas as
        unidades/entidades de jogos (pastas de jogos estruturadas e arquivos/ROMs/ISOs).
        """
        candidates: List[GameRecord] = []
        claimed_track_paths: Set[str] = set()

        def _walk(current_dir: Path) -> None:
            # Verifica se `current_dir` inteiro é uma unidade de jogo (PC, PS3, Wii U)
            unit_info = _inspect_directory_as_game_unit(current_dir, self.root_dir)
            if unit_info is not None:
                platform, immediate_bins = unit_info
                total_size, chosen_bins, aux_names, dir_notes = _collect_directory_summary(current_dir)
                bins_to_use = chosen_bins if chosen_bins else immediate_bins
                record = GameRecord(
                    raw_name=current_dir.name,
                    target_path=current_dir,
                    display_path=clean_display_path(current_dir),
                    is_directory=True,
                    platform=platform,
                    size_bytes=total_size,
                    primary_files=bins_to_use,
                    auxiliary_names=aux_names,
                    notes=dir_notes,
                )
                candidates.append(record)
                return

            # Caso seja um diretório organizacional, lista arquivos e subpastas
            try:
                entries = list(os.scandir(to_long_path(current_dir)))
            except PermissionError:
                self.scan_errors.append(f"Permissão negada ao acessar diretório: {clean_display_path(current_dir)}")
                return
            except OSError as exc:
                self.scan_errors.append(f"Erro ao ler diretório {clean_display_path(current_dir)}: {exc}")
                return

            subdirs: List[Path] = []
            files: List[Path] = []
            aux_in_folder: List[str] = []

            for entry in entries:
                try:
                    aux_in_folder.append(entry.name)
                    if entry.is_dir(follow_symlinks=False):
                        subdirs.append(current_dir / entry.name)
                    elif entry.is_file(follow_symlinks=False):
                        files.append(current_dir / entry.name)
                except OSError:
                    continue

            # Processa primeiro descritores .cue e .gdi para registrar suas faixas .bin/.raw/.iso
            # e evitar que cada Track XX.bin seja listada como um jogo separado
            files.sort(key=lambda p: (0 if p.suffix.lower() in (".cue", ".gdi") else 1, p.name.lower()))

            for file_path in files:
                norm_file_key = os.path.normcase(os.path.abspath(to_long_path(file_path)))
                if norm_file_key in claimed_track_paths:
                    continue

                ext = file_path.suffix.lower()
                if ext not in ALL_GAME_FILE_EXTENSIONS:
                    continue

                try:
                    fsize = os.path.getsize(to_long_path(file_path))
                except OSError:
                    fsize = 0

                primary_tracks: List[Path] = [file_path]
                extra_notes: List[str] = []

                if ext in (".cue", ".gdi"):
                    plat, ref_tracks = inspect_cue_or_gdi_platform(file_path, self.root_dir)
                    for rt in ref_tracks:
                        rt_key = os.path.normcase(os.path.abspath(to_long_path(rt)))
                        claimed_track_paths.add(rt_key)
                        try:
                            if os.path.exists(to_long_path(rt)):
                                fsize += os.path.getsize(to_long_path(rt))
                                primary_tracks.append(rt)
                        except OSError:
                            pass
                else:
                    plat = classify_file_platform(file_path, self.root_dir, file_size=fsize)

                # Se o arquivo tem nome genérico (ex: EBOOT.PBP, disc.iso, game.iso) e está numa subpasta dedicada,
                # usa o nome da pasta pai como título bruto do jogo
                raw_title = file_path.name
                if file_path.stem.lower() in ("eboot", "game", "disc", "disk", "rom", "iso", "setup", "install") and current_dir != self.root_dir:
                    raw_title = current_dir.name
                    extra_notes.append(f"Arquivo base: {file_path.name}")

                candidates.append(
                    GameRecord(
                        raw_name=raw_title,
                        target_path=file_path,
                        display_path=clean_display_path(file_path),
                        is_directory=False,
                        platform=plat,
                        size_bytes=fsize,
                        primary_files=primary_tracks,
                        auxiliary_names=list(aux_in_folder),
                        notes=extra_notes,
                    )
                )

            # Continua recursão nas subpastas ordenadas alfabeticamente
            for sd in sorted(subdirs, key=lambda p: p.name.lower()):
                _walk(sd)

        _walk(self.root_dir)
        return candidates

    def audit_and_enrich_record(self, record: GameRecord) -> None:
        """
        Fase 2: Executa teste de integridade, reclassificação por conteúdo interno de arquivo
        compactado (se aplicável), detecção de Crack/DRM, detecção de Tradução e enriquecimento via API.
        """
        # 1. Teste de integridade (ZIP, 7Z, RAR, CUE/GDI, ROMs/ISOs ou pasta de jogo)
        integrity_res: IntegrityResult = check_item_integrity(
            target_path=record.target_path,
            is_directory=record.is_directory,
            primary_files=record.primary_files,
            deep_archive_check=self.deep_archive_check,
        )
        record.is_corrupted = integrity_res.is_corrupted
        record.corrupted_status = integrity_res.status_label
        record.notes.extend(integrity_res.notes)

        # Se for arquivo compactado e o teste de integridade listou as entradas internas,
        # refina a plataforma e adiciona as entradas aos nomes auxiliares (para detectar Crack/Tradução dentro do .zip/.7z/.rar!)
        if integrity_res.archive_entries:
            record.auxiliary_names.extend(integrity_res.archive_entries)
            if not record.is_directory and record.target_path.suffix.lower() in ARCHIVE_EXTENSIONS:
                refined_plat = classify_file_platform(
                    record.target_path,
                    self.root_dir,
                    file_size=record.size_bytes,
                    archive_entries=integrity_res.archive_entries,
                )
                if refined_plat:
                    record.platform = refined_plat

        # 2. Enriquecimento de metadados (Regex + IGDB/RAWG API ou Heurística Local)
        meta = self.enricher.enrich(record.raw_name, record.platform)
        record.official_name = meta.official_name
        record.release_year = meta.release_year
        record.genre = meta.genre
        record.official_language = meta.supported_languages
        if meta.source != "Heurística Local":
            record.notes.append(f"Metadados: {meta.source}")

        # 3. Detecção de Crack / DRM (Exclusivo PC; Consoles recebem "N/A (Console)")
        drm_label, drm_notes = detect_crack_drm(
            platform=record.platform,
            raw_name=record.raw_name,
            auxiliary_names=record.auxiliary_names,
        )
        record.crack_drm_status = drm_label
        record.notes.extend(drm_notes)

        # 4. Detecção de Tradução / Localização ("Mod Local", "ROM Traduzida", "Nativo PT-BR", "Não detectada")
        trans_label, trans_note = detect_translation_status(
            platform=record.platform,
            raw_name=record.raw_name,
            auxiliary_names=record.auxiliary_names,
            api_supported_languages=record.official_language,
        )
        record.translation_status = trans_label
        if trans_note:
            record.notes.append(trans_note)

    def deduplicate_records(self, records: List[GameRecord]) -> None:
        """
        Fase 3: Deduplicação Inteligente em duas camadas:
        1. Arquivos de ROMs/ISOs/Zips: agrupa primeiro por tamanho exato em bytes e depois
           valida por SHA-256 (lendo em chunks de 64KB).
        2. Jogos em pastas (e títulos homônimos na mesma plataforma): compara assinatura
           normalizada de nome + plataforma.
        Preenche 'Duplicado' com 'Sim (X cópias)' ou 'Não'.
        """
        # Camada 1: Agrupamento de arquivos por tamanho exato em bytes
        by_size: Dict[int, List[GameRecord]] = defaultdict(list)
        for rec in records:
            if not rec.is_directory and rec.size_bytes > 0:
                by_size[rec.size_bytes].append(rec)

        for size_bytes, same_size_group in by_size.items():
            # Calcula SHA-256 se houver colisão de tamanho exato OU se hash_all_files estiver ativo
            if len(same_size_group) > 1 or self.hash_all_files:
                for rec in same_size_group:
                    rec.sha256_hash = compute_sha256(rec.target_path)

        # Agrupa por hash SHA-256 idêntico (arquivos binariamente idênticos)
        by_hash: Dict[str, List[GameRecord]] = defaultdict(list)
        for rec in records:
            if rec.sha256_hash:
                by_hash[rec.sha256_hash].append(rec)

        # Camada 2: Agrupamento por assinatura normalizada (nome sanitizado + plataforma)
        by_signature: Dict[str, List[GameRecord]] = defaultdict(list)
        for rec in records:
            sig = normalize_signature_key(rec.official_name or rec.raw_name, rec.platform)
            by_signature[sig].append(rec)

        # Consolida conjuntos de duplicatas (união de grupos por SHA-256 exato e grupos por assinatura Nome+Plataforma)
        processed_ids: Set[int] = set()

        # Primeiro marca duplicatas exatas por SHA-256
        for sha_digest, group in by_hash.items():
            if len(group) > 1:
                count = len(group)
                short_hash = sha_digest[:12]
                for rec in group:
                    rec.is_duplicate = True
                    rec.duplicate_status = f"Sim ({count} cópias)"
                    others = [r.target_path.name for r in group if r is not rec]
                    rec.notes.append(
                        f"Duplicata exata SHA-256 ({short_hash}...) de: {', '.join(others[:3])}"
                    )
                    processed_ids.add(id(rec))

        # Depois marca duplicatas por assinatura normalizada (pastas ou arquivos de mesmo jogo + plataforma)
        for sig, group in by_signature.items():
            if len(group) > 1:
                count = len(group)
                for rec in group:
                    rec.is_duplicate = True
                    rec.duplicate_status = f"Sim ({count} cópias)"
                    if id(rec) not in processed_ids:
                        others = [r.target_path.name for r in group if r is not rec]
                        rec.notes.append(
                            f"Mesma assinatura Nome+Plataforma encontrada em: {', '.join(others[:3])}"
                        )

    def run_full_scan(
        self,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> List[GameRecord]:
        """
        Executa o pipeline completo: descoberta recursiva -> auditoria/enriquecimento -> deduplicação.
        """
        records = self.discover_candidates()
        total = len(records)

        for idx, rec in enumerate(records, start=1):
            if progress_callback:
                progress_callback(idx, total, rec.raw_name)
            self.audit_and_enrich_record(rec)

        self.deduplicate_records(records)
        self.enricher.save_cache()

        # Ordena por Plataforma e depois por Nome Oficial do Jogo
        records.sort(key=lambda r: (r.platform.lower(), (r.official_name or r.raw_name).lower()))
        return records
