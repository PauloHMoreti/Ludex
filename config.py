"""
config.py - Configurações globais, mapeamentos de plataformas, extensões,
indicadores de DRM/Tradução, credenciais de API e utilitários de sistema.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

# Tenta carregar variáveis de ambiente de um arquivo .env local, se disponível
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


# ==============================================================================
# 1. CREDENCIAIS E CONFIGURAÇÕES DE API (IGDB / RAWG)
# ==============================================================================
RAWG_API_KEY: str = os.getenv("RAWG_API_KEY", "").strip()
IGDB_CLIENT_ID: str = os.getenv("IGDB_CLIENT_ID", "").strip()
IGDB_CLIENT_SECRET: str = os.getenv("IGDB_CLIENT_SECRET", "").strip()
IGDB_ACCESS_TOKEN: str = os.getenv("IGDB_ACCESS_TOKEN", "").strip()

API_TIMEOUT_SECONDS: int = int(os.getenv("LUDEX_API_TIMEOUT", "8"))
DEFAULT_CACHE_FILE: str = os.getenv("LUDEX_CACHE_FILE", ".ludex_metadata_cache.json")

# Tamanho do bloco de leitura para cálculo de hash SHA-256 (64 KB conforme especificação)
HASH_CHUNK_SIZE: int = 65536

# Quantidade de bytes lidos no início e fim de arquivos para teste de integridade rápida
INTEGRITY_SAMPLE_BYTES: int = 65536


# ==============================================================================
# 2. MAPEAMENTO EXTENSÍVEL DE EXTENSÕES POR CONSOLE / SISTEMA
# ==============================================================================
# Dicionário principal organizado por Fabricante -> Console -> Lista de extensões
CONSOLE_EXTENSION_CATALOG: Dict[str, Dict[str, List[str]]] = {
    "Nintendo": {
        "NES": [".nes", ".fds", ".unf", ".nez"],
        "SNES": [".sfc", ".smc", ".fig", ".swc"],
        "N64": [".z64", ".n64", ".v64", ".ndd"],
        "GameCube": [".gcm", ".ciso", ".gcz", ".iso", ".rvz"],
        "Wii": [".wbfs", ".rvz", ".wad", ".wia", ".iso"],
        "Wii U": [".wua", ".rpx", ".wud", ".wux"],
        "Switch": [".xci", ".nsp", ".nsz", ".xcz"],
        "Game Boy": [".gb", ".sgb"],
        "Game Boy Color": [".gbc"],
        "GBA": [".gba", ".agb"],
        "NDS": [".nds", ".dsi", ".ids"],
        "3DS": [".3ds", ".cia", ".3dsx", ".cci"],
    },
    "Sony": {
        "PS1": [".cue", ".bin", ".pbp", ".chd", ".ecm", ".mdf", ".img"],
        "PS2": [".iso", ".cso", ".chd", ".zso", ".bin"],
        "PSP": [".iso", ".cso", ".pbp", ".chd", ".dax"],
        "PS3": [".pkg", ".iso"],  # Além de pastas estruturadas contendo PS3_GAME
    },
    "Sega": {
        "Mega Drive": [".smd", ".gen", ".md", ".32x", ".bin"],
        "Master System": [".sms"],
        "Game Gear": [".gg"],
        "Dreamcast": [".cdi", ".gdi", ".chd"],
        "Saturn": [".cue", ".iso", ".chd", ".mdf"],
        "Sega CD": [".cue", ".iso", ".chd", ".bin"],
    },
    "PC": {
        "PC": [".exe", ".msi", ".iso", ".bin"],
    },
}

# Extensões que pertencem exclusivamente a uma única plataforma (sem ambiguidade)
EXCLUSIVE_EXTENSION_TO_PLATFORM: Dict[str, str] = {
    # Nintendo
    ".nes": "NES",
    ".fds": "NES",
    ".unf": "NES",
    ".nez": "NES",
    ".sfc": "SNES",
    ".smc": "SNES",
    ".fig": "SNES",
    ".swc": "SNES",
    ".z64": "N64",
    ".n64": "N64",
    ".v64": "N64",
    ".ndd": "N64",
    ".gcm": "GameCube",
    ".gcz": "GameCube",
    ".wbfs": "Wii",
    ".wad": "Wii",
    ".wia": "Wii",
    ".wua": "Wii U",
    ".rpx": "Wii U",
    ".wud": "Wii U",
    ".wux": "Wii U",
    ".xci": "Switch",
    ".nsp": "Switch",
    ".nsz": "Switch",
    ".xcz": "Switch",
    ".gb": "Game Boy",
    ".sgb": "Game Boy",
    ".gbc": "Game Boy Color",
    ".gba": "GBA",
    ".agb": "GBA",
    ".nds": "NDS",
    ".dsi": "NDS",
    ".ids": "NDS",
    ".3ds": "3DS",
    ".cia": "3DS",
    ".3dsx": "3DS",
    ".cci": "3DS",
    # Sony
    ".pkg": "PS3",
    ".ecm": "PS1",
    ".zso": "PS2",
    ".dax": "PSP",
    # Sega
    ".smd": "Mega Drive",
    ".gen": "Mega Drive",
    ".md": "Mega Drive",
    ".32x": "Mega Drive",
    ".sms": "Master System",
    ".gg": "Game Gear",
    ".cdi": "Dreamcast",
    ".gdi": "Dreamcast",
    # PC
    ".exe": "PC",
    ".msi": "PC",
}

# Extensões compartilhadas por múltiplos sistemas que exigem desambiguação
# por magic numbers/cabeçalho, nome de pasta ancestral ou metadados
AMBIGUOUS_EXTENSIONS: Dict[str, List[str]] = {
    ".iso": ["PS2", "PSP", "GameCube", "Wii", "PC", "Saturn", "Sega CD", "PS3", "PS1"],
    ".chd": ["PS1", "PS2", "PSP", "Dreamcast", "Saturn", "Sega CD"],
    ".cue": ["PS1", "Saturn", "Sega CD", "PC"],
    ".bin": ["PS1", "Mega Drive", "Sega CD", "Saturn", "PS2", "PC"],
    ".pbp": ["PSP", "PS1"],
    ".cso": ["PSP", "PS2"],
    ".ciso": ["GameCube", "PSP", "Wii"],
    ".rvz": ["GameCube", "Wii"],
    ".mdf": ["PS1", "Saturn", "PC"],
    ".img": ["PS1", "PC"],
}

# Arquivos compactados suportados para auditoria e inspeção interna
ARCHIVE_EXTENSIONS: Set[str] = {".zip", ".7z", ".rar"}

# Todas as extensões reconhecidas como imagens/ROMs/arquivos de jogos
ALL_GAME_FILE_EXTENSIONS: Set[str] = (
    set(EXCLUSIVE_EXTENSION_TO_PLATFORM.keys())
    | set(AMBIGUOUS_EXTENSIONS.keys())
    | ARCHIVE_EXTENSIONS
)

# Tamanho mínimo aceitável (em bytes) por extensão para evitar falsos positivos/truncados
MIN_VALID_SIZE_BYTES: Dict[str, int] = {
    ".nes": 16,           # Header iNES tem 16 bytes + PRG
    ".fds": 65500,
    ".sfc": 32768,        # 32 KB mín
    ".smc": 32768,
    ".z64": 1048576,      # 1 MB mín para N64
    ".n64": 1048576,
    ".v64": 1048576,
    ".gb": 16384,         # 16 KB
    ".gbc": 16384,
    ".gba": 32768,
    ".nds": 131072,
    ".3ds": 524288,
    ".cia": 65536,
    ".gcm": 1048576,
    ".iso": 32768,        # 32 KB (16 setores de 2048 bytes para PVD ISO9660)
    ".wbfs": 512,
    ".rvz": 128,
    ".wad": 64,
    ".wua": 64,
    ".rpx": 64,
    ".xci": 512,
    ".nsp": 64,
    ".nsz": 64,
    ".chd": 128,
    ".pbp": 40,
    ".pkg": 128,
    ".cso": 24,
    ".ciso": 32,
    ".cdi": 1024,
    ".gdi": 16,
    ".cue": 16,
    ".bin": 1024,
    ".smd": 16384,
    ".gen": 16384,
    ".md": 16384,
    ".exe": 64,           # Header MZ DOS/PE
    ".msi": 512,
    ".zip": 22,           # End of Central Directory mínimo = 22 bytes
    ".7z": 32,            # SignatureHeader 7z = 32 bytes
    ".rar": 20,           # RAR header mínimo
}


# ==============================================================================
# 3. ALIASES DE PASTAS ANCESTRAIS PARA DESAMBIGUAÇÃO DE PLATAFORMA
# ==============================================================================
# Ordem importa para termos mais específicos antes dos genéricos (ex: "wii u" antes de "wii")
FOLDER_PLATFORM_ALIASES: List[Tuple[str, List[str]]] = [
    ("Wii U", ["wii u", "wiiu", "nintendo wii u", "cemu"]),
    ("Wii", ["wii", "nintendo wii"]),
    ("GameCube", ["gamecube", "game cube", "ngc", "gcn", "gc", "nintendo gamecube"]),
    ("Switch", ["switch", "nsw", "nintendo switch", "yuzu", "ryujinx"]),
    ("3DS", ["3ds", "nintendo 3ds", "n3ds", "citra"]),
    ("NDS", ["nds", "nintendo ds", "ds", "melonds", "desmume"]),
    ("GBA", ["gba", "game boy advance", "gameboy advance"]),
    ("Game Boy Color", ["gbc", "game boy color", "gameboy color"]),
    ("Game Boy", ["gb", "game boy", "gameboy"]),
    ("SNES", ["snes", "super nintendo", "super nes", "super famicom", "sfc"]),
    ("NES", ["nes", "nintendo entertainment system", "famicom", "fc", "nintendinho"]),
    ("N64", ["n64", "nintendo 64", "ultra 64"]),
    ("PS3", ["ps3", "playstation 3", "ps3_game", "rpcs3", "sony ps3"]),
    ("PS2", ["ps2", "playstation 2", "pcsx2", "sony ps2"]),
    ("PSP", ["psp", "playstation portable", "ppsspp", "sony psp"]),
    ("PS1", ["ps1", "psx", "playstation 1", "playstation", "psone", "duckstation", "epsxe"]),
    ("Dreamcast", ["dreamcast", "sega dreamcast", "dc", "flycast", "redream"]),
    ("Saturn", ["saturn", "sega saturn", "ss"]),
    ("Sega CD", ["sega cd", "segacd", "mega cd", "megacd", "scd", "mcd"]),
    ("Mega Drive", ["mega drive", "megadrive", "genesis", "sega genesis", "md", "32x"]),
    ("Master System", ["master system", "sms", "sega master system"]),
    ("Game Gear", ["game gear", "gamegear", "gg"]),
    ("PC", ["pc", "windows", "dos", "ms-dos", "pc games", "jogos pc", "jogos de pc", "gog", "steam"]),
]


# ==============================================================================
# 4. MAPEAMENTO DE PLATAFORMAS PARA IDs DAS APIs (IGDB & RAWG)
# ==============================================================================
# IDs oficiais da IGDB (https://api-docs.igdb.com/#platform)
IGDB_PLATFORM_IDS: Dict[str, List[int]] = {
    "PC": [6, 13, 14, 3],         # PC (Microsoft Windows), DOS, Mac, Linux
    "NES": [18, 99, 51],          # NES, Family Computer, Famicom Disk System
    "SNES": [19, 58],             # Super Nintendo, Super Famicom
    "N64": [4, 416],              # Nintendo 64, 64DD
    "GameCube": [21],             # Nintendo GameCube
    "Wii": [5, 56],               # Wii, WiiWare
    "Wii U": [41],                # Wii U
    "Switch": [130],              # Nintendo Switch
    "Game Boy": [33],             # Game Boy
    "Game Boy Color": [22],       # Game Boy Color
    "GBA": [24],                  # Game Boy Advance
    "NDS": [20, 159],             # Nintendo DS, Nintendo DSi
    "3DS": [37, 137],             # Nintendo 3DS, New Nintendo 3DS
    "PS1": [7],                   # PlayStation
    "PS2": [8],                   # PlayStation 2
    "PSP": [38],                  # PlayStation Portable
    "PS3": [9],                   # PlayStation 3
    "Mega Drive": [29, 30],       # Sega Mega Drive/Genesis, Sega 32X
    "Master System": [64],        # Sega Master System/Mark III
    "Game Gear": [35],            # Sega Game Gear
    "Dreamcast": [23],            # Dreamcast
    "Saturn": [32],               # Sega Saturn
    "Sega CD": [78],              # Sega CD
}

# IDs oficiais da RAWG API (https://api.rawg.io/docs/#operation/platforms_list)
RAWG_PLATFORM_IDS: Dict[str, List[int]] = {
    "PC": [4],                    # PC
    "NES": [49],                  # NES
    "SNES": [79],                 # SNES
    "N64": [83],                  # Nintendo 64
    "GameCube": [105],            # GameCube
    "Wii": [11],                  # Wii
    "Wii U": [10],                # Wii U
    "Switch": [7],                # Nintendo Switch
    "Game Boy": [26],             # Game Boy
    "Game Boy Color": [43],       # Game Boy Color
    "GBA": [24],                  # Game Boy Advance
    "NDS": [9],                   # Nintendo DS
    "3DS": [8],                   # Nintendo 3DS
    "PS1": [27],                  # PlayStation
    "PS2": [15],                  # PlayStation 2
    "PSP": [17],                  # PSP
    "PS3": [16],                  # PlayStation 3
    "Mega Drive": [167],          # Genesis / Mega Drive
    "Master System": [74],        # SEGA Master System
    "Game Gear": [77],            # Game Gear
    "Dreamcast": [106],           # Dreamcast
    "Saturn": [107],              # SEGA Saturn
    "Sega CD": [119],             # SEGA CD
}


# ==============================================================================
# 5. HEURÍSTICAS DE DETECÇÃO DE CRACK / DRM (PC) E TRADUÇÃO / LOCALIZAÇÃO
# ==============================================================================
# Grupos de cena, emuladores de DRM e indicadores de Crack conhecidos no PC
PC_SCENE_AND_CRACK_INDICATORS: Dict[str, str] = {
    "codex": "Crack / Scene (CODEX)",
    "cdx": "Crack / Scene (CODEX)",
    "flt": "Crack / Scene (FLT)",
    "fairlight": "Crack / Scene (FLT)",
    "rune": "Crack / Scene (RUNE)",
    "tenoke": "Crack / Scene (TENOKE)",
    "razor1911": "Crack / Scene (Razor1911)",
    "razor": "Crack / Scene (Razor1911)",
    "reloaded": "Crack / Scene (RELOADED)",
    "rld!": "Crack / Scene (RELOADED)",
    "skidrow": "Crack / Scene (SKIDROW)",
    "plaza": "Crack / Scene (PLAZA)",
    "hoodlum": "Crack / Scene (HOODLUM)",
    "empress": "Crack / Scene (EMPRESS)",
    "cpy": "Crack / Scene (CPY)",
    "steampunks": "Crack / Scene (STEAMPUNKS)",
    "prophet": "Crack / Scene (PROPHET)",
    "ali213": "Crack / Emu (ALI213)",
    "3dmgame": "Crack / Emu (3DM)",
    "goldberg": "Crack / Emu (Goldberg SteamEmu)",
    "smartsteamemu": "Crack / Emu (SmartSteamEmu)",
    "creamapi": "Crack / Unlocker (CreamAPI)",
    "greenluma": "Crack / Unlocker (GreenLuma)",
    "steam_emu.ini": "Crack / SteamEmu (steam_emu.ini)",
    "valve.ini": "Crack / SteamEmu (valve.ini)",
    "codex.ini": "Crack / Scene (CODEX)",
    "tenoke.ini": "Crack / Scene (TENOKE)",
    "flt.ini": "Crack / Scene (FLT)",
    "rune.ini": "Crack / Scene (RUNE)",
    "cpy.ini": "Crack / Scene (CPY)",
    "fitgirl": "Repack / Crack (FitGirl)",
    "dodi": "Repack / Crack (DODI)",
    "elamigos": "Repack / Crack (ElAmigos)",
    "kaos": "Repack / Crack (KaOs)",
    "no-cd": "Crack (No-CD)",
    "nocd": "Crack (No-CD)",
    "nodvd": "Crack (No-DVD)",
    "no-dvd": "Crack (No-DVD)",
    "crack": "Crack (Pasta/Arquivo Local)",
}

# Indicadores de lojas / DRM legítimo ou DRM-Free no PC
PC_STORE_DRM_INDICATORS: Dict[str, str] = {
    "goggame": "DRM-Free (GOG)",
    "gog.ico": "DRM-Free (GOG)",
    "gog": "DRM-Free (GOG)",
    "steam_api64.dll": "Steam (steam_api64.dll)",
    "steam_api.dll": "Steam (steam_api.dll)",
    "steam_appid.txt": "Steam (steam_appid.txt)",
    "eossdk-win64-shipping.dll": "Epic Games (EOS SDK)",
    "eossdk-win32-shipping.dll": "Epic Games (EOS SDK)",
    "uplay_r1_loader64.dll": "Ubisoft Connect (Uplay)",
    "uplay_r1_loader.dll": "Ubisoft Connect (Uplay)",
    "upc_r2_loader64.dll": "Ubisoft Connect",
    "activation64.dll": "EA / Origin DRM",
}

# Executáveis utilitários comuns dentro de pastas de jogos de PC que NÃO são jogos independentes
PC_UTILITY_EXE_PATTERNS: Tuple[str, ...] = (
    "unins",
    "uninstall",
    "vcredist",
    "dxsetup",
    "directx",
    "dotnet",
    "crashhandler",
    "unitycrashhandler",
    "crashreport",
    "crashsender",
    "cefprocess",
    "redist",
    "prereq",
    "physx",
    "oalinst",
    "easyanticheat",
    "battleye",
    "benchmark",
    "config.exe",
    "settings.exe",
    "updater.exe",
)

# Indicadores de Tradução via Mod Local (PC / Consoles)
TRANSLATION_MOD_KEYWORDS: Tuple[str, ...] = (
    "gamevicio",
    "game vicio",
    "tribo gamer",
    "tribogamer",
    "central de traducoes",
    "central de traduções",
    "traducao",
    "tradução",
    "patch pt-br",
    "patch_ptbr",
    "patch ptbr",
    "mod pt-br",
    "dublagem pt-br",
    "legendas pt-br",
    "instalador_traducao",
)

# Indicadores de ROM Traduzida (Consoles / Portáteis)
TRANSLATION_ROM_KEYWORDS: Tuple[str, ...] = (
    "[t-por",
    "[t+por",
    "[t-br",
    "[t+br",
    "[pt-br]",
    "[ptbr]",
    "[pt_br]",
    "(pt-br)",
    "(ptbr)",
    "[traduzido",
    "(traduzido",
    "traduzido pt",
    "portugues-br",
)

# Indicadores de suporte Nativo PT-BR em arquivos/nomes
NATIVE_PTBR_KEYWORDS: Tuple[str, ...] = (
    "pt-br",
    "pt_br",
    "ptbr",
    "brazilian",
    "portuguese (brazil)",
    "português (brasil)",
    "portugues (brasil)",
    "dublado pt",
    "multi-ptbr",
    "(brazil)",
    "(brasil)",
)


# ==============================================================================
# 6. CONFIGURAÇÕES DE ESTILO DO EXCEL (.XLSX)
# ==============================================================================
EXCEL_HEADERS_LIBRARY: List[str] = [
    "Plataforma",
    "Nome do Jogo",
    "Ano de Lançamento",
    "Gênero",
    "Idioma Oficial",
    "Tradução",
    "Crack / DRM",
    "Duplicado",
    "Arquivos / Localização",
    "Corrompido",
    "Observações",
]

EXCEL_THEME: Dict[str, str] = {
    "header_bg": "1F2937",          # Cabeçalho escuro (#1F2937)
    "header_fg": "FFFFFF",          # Tipografia branca (#FFFFFF)
    "zebra_even": "F9FAFB",         # Linha zebrada discreta (#F9FAFB)
    "zebra_odd": "FFFFFF",          # Linha branca (#FFFFFF)
    "border_color": "E5E7EB",       # Cinza claro de borda
    "corrupt_bg": "FEE2E2",         # Vermelho claro (#FEE2E2)
    "corrupt_fg": "991B1B",         # Vermelho escuro (#991B1B)
    "duplicate_bg": "DBEAFE",       # Azul suave (#DBEAFE)
    "duplicate_fg": "1E40AF",       # Azul escuro (#1E40AF)
    "translation_bg": "DCFCE7",     # Verde claro (#DCFCE7)
    "translation_fg": "166534",     # Verde escuro (#166534)
    "accent_primary": "2563EB",     # Azul executivo para o Dashboard
    "kpi_card_bg": "F3F4F6",        # Fundo de cards do Dashboard
}


# ==============================================================================
# 7. UTILITÁRIOS DE CAMINHOS LONGOS (WINDOWS \\?\) E RESILIÊNCIA DE SISTEMA
# ==============================================================================
def to_long_path(path: str | Path) -> str:
    """
    Converte um caminho em caminho estendido do Windows (prefixo \\\\?\\)
    para evitar erros de MAX_PATH (260 caracteres) em estruturas profundas de ROMs/PC.
    Em sistemas POSIX, retorna o caminho absoluto padrão.
    """
    raw = str(path)
    if os.name != "nt":
        return os.path.abspath(raw)

    if raw.startswith("\\\\?\\"):
        return raw

    abs_path = os.path.abspath(raw)
    if abs_path.startswith("\\\\"):
        # Caminho de rede UNC: \\servidor\pasta -> \\?\UNC\servidor\pasta
        return "\\\\?\\UNC\\" + abs_path[2:]
    return "\\\\?\\" + abs_path


def clean_display_path(path: str | Path) -> str:
    """
    Remove o prefixo técnico \\\\?\\ do Windows para exibição limpa no Excel e logs.
    """
    raw = str(path)
    if raw.startswith("\\\\?\\UNC\\"):
        return "\\\\" + raw[8:]
    if raw.startswith("\\\\?\\"):
        return raw[4:]
    return raw
