"""
metadata.py - Sanitização de títulos via Regex, extração heurística local de
metadados (ano, idiomas, região) e enriquecimento via APIs públicas (IGDB / RAWG)
com filtragem por plataforma e cache persistente em disco.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    requests = None  # type: ignore

from config import (
    API_TIMEOUT_SECONDS,
    DEFAULT_CACHE_FILE,
    IGDB_ACCESS_TOKEN,
    IGDB_CLIENT_ID,
    IGDB_CLIENT_SECRET,
    IGDB_PLATFORM_IDS,
    RAWG_API_KEY,
    RAWG_PLATFORM_IDS,
)


@dataclass
class GameMetadata:
    """Metadados consolidados de um jogo (via API ou fallback heurístico local)."""

    official_name: str
    official_platform: str
    release_year: str
    genre: str
    supported_languages: str
    source: str = "Heurística Local"  # "IGDB API", "RAWG API", "Cache API" ou "Heurística Local"


# ==============================================================================
# 1. EXPRESSÕES REGULARES PARA SANITIZAÇÃO DE NOMES DE ROMS E RELEASES DE CENA
# ==============================================================================
# Numeração inicial de ROM-sets (ex: "0042 - ", "1234. ")
RE_ROMSET_PREFIX = re.compile(r"^\s*\d{3,4}\s*[-_.]\s*")

# Códigos de catálogo Sony/Nintendo no início ou meio (ex: "SLUS-20062", "BLES-00123")
RE_CATALOG_CODE = re.compile(
    r"\b(?:SLUS|SCUS|SLES|SCES|SLPS|SLPM|ULUS|ULES|ULJM|UCUS|UCES|BLUS|BLES|BCUS|BCES|NPUA|NPEA|NPUB|NPEB)[-_ ]?\d{4,5}\b",
    re.I,
)

# Extração de ano explícito entre parênteses ou colchetes antes da limpeza (ex: "(1998)", "[2020]")
RE_YEAR_TOKEN = re.compile(r"[\(\[\b](19[7-9]\d|20[0-2]\d)[\)\]\b]")

# Qualquer conteúdo entre colchetes: [!], [T-Por], [b1], [a1], [FitGirl Repack], [GOG], [NTSC]
RE_BRACKET_TAGS = re.compile(r"\[[^\]]*\]")

# Qualquer conteúdo entre parênteses: (USA), (En,Fr,De), (v1.0), (Rev 1), (Disc 1), (ISO)
RE_PAREN_TAGS = re.compile(r"\([^\)]*\)")

# Versões e builds soltas no nome: v1.0, v1.04.2b, Build 12345, Rev A
RE_VERSION_TOKENS = re.compile(
    r"\b(?:v\d+(?:\.\d+)*[a-z]?|ver\.?\s*\d+(?:\.\d+)*|build[._ -]?\d+|rev[._ -]?[a-z0-9]+|patch[._ -]?\d+(?:\.\d+)*)\b",
    re.I,
)

# Termos de cena, repacks, arquiteturas e formatos no sufixo
RE_SCENE_TERMS = re.compile(
    r"\b(?:"
    r"repack|fitgirl|dodi|elamigos|kaos|xatab|rg[._ -]?mechanics|"
    r"multi\d*|proper|readnfo|internal|rip|unpacked|cracked|portable|"
    r"setup|installer|install|goty[._ -]?edition|complete[._ -]?edition|"
    r"deluxe[._ -]?edition|ultimate[._ -]?edition|definitive[._ -]?edition|"
    r"remastered|directors[._ -]?cut|digital[._ -]?deluxe|"
    r"x64|x86|win64|win32|amd64|gog|steamrip| preload|"
    r"disc[._ -]?\d+|cd[._ -]?\d+|dvd[._ -]?\d+|track[._ -]?\d+"
    r")\b",
    re.I,
)

# Grupos de cena conhecidos no final do nome (precedidos por hífen, espaço ou ponto)
RE_SCENE_GROUPS_SUFFIX = re.compile(
    r"[-_. ]+(?:"
    r"CODEX|FLT|FAIRLIGHT|RUNE|TENOKE|RAZOR1911|RELOADED|SKIDROW|PLAZA|"
    r"HOODLUM|EMPRESS|CPY|STEAMPUNKS|PROPHET|ALI213|3DM|3DMGAME|GOLDBERG|"
    r"GOG|FITGIRL|DODI|ELAMIGOS|KAOS|DUPLEX|VENOM|PS3|EUR|USA|JPN|NTSC|PAL"
    r")\s*$",
    re.I,
)

# Mapa de códigos ISO de idioma comuns em No-Intro / Redump ex: (En,Fr,De,Es,It,Pt)
LANG_CODE_MAP: Dict[str, str] = {
    "en": "Inglês",
    "fr": "Francês",
    "de": "Alemão",
    "es": "Espanhol",
    "it": "Italiano",
    "pt": "Português",
    "pt-br": "Português (Brasil)",
    "ja": "Japonês",
    "jp": "Japonês",
    "ru": "Russo",
    "zh": "Chinês",
    "ko": "Coreano",
    "nl": "Holandês",
    "sv": "Sueco",
    "pl": "Polonês",
}


def sanitize_game_name(raw_name: str) -> str:
    """
    Limpa o nome de um arquivo ou diretório de jogo, removendo extensões,
    tags de dump ([!], (USA), (En,Fr,De)), versões (v1.0), grupos de cena (-CODEX, -FLT)
    e normalizando separadores (pontos e underscores).
    """
    name = raw_name.strip()

    # Remove extensão de arquivo se ainda estiver presente
    stem, ext = os.path.splitext(name)
    if ext.lower() in (
        ".iso", ".zip", ".7z", ".rar", ".chd", ".nes", ".fds", ".sfc", ".smc",
        ".z64", ".n64", ".v64", ".gcm", ".ciso", ".wbfs", ".rvz", ".wad",
        ".wua", ".rpx", ".xci", ".nsp", ".nsz", ".gb", ".gbc", ".gba", ".nds",
        ".3ds", ".cia", ".cue", ".bin", ".pbp", ".cso", ".pkg", ".smd", ".gen",
        ".md", ".cdi", ".gdi", ".exe", ".msi", ".mdf", ".img", ".zso", ".dax",
    ):
        name = stem

    # 1. Remove prefixo numérico de ROM-sets (ex: "0123 - ")
    name = RE_ROMSET_PREFIX.sub("", name)

    # 2. Remove códigos de catálogo (SLUS-20062, etc.)
    name = RE_CATALOG_CODE.sub(" ", name)

    # 3. Remove tags entre colchetes [...] e parênteses (...)
    name = RE_BRACKET_TAGS.sub(" ", name)
    name = RE_PAREN_TAGS.sub(" ", name)

    # 4. Substitui pontos e underscores por espaços quando funcionam como separadores de cena
    # Ex: "God.of.War.II" ou "Super_Mario_World"
    name = name.replace("_", " ")
    if "." in name:
        # Substitui pontos entre palavras, mantendo abreviações curtas se apropriado
        name = re.sub(r"(?<=\w)\.(?=\w)", " ", name)

    # 5. Remove sufixos de grupos de cena (ex: "-CODEX", "-FLT", "-RUNE")
    prev = None
    while prev != name:
        prev = name
        name = RE_SCENE_GROUPS_SUFFIX.sub("", name).strip()

    # 6. Remove versões (v1.04, Build 1234) e termos de cena/repack (Repack, MULTi10, etc.)
    name = RE_VERSION_TOKENS.sub(" ", name)
    name = RE_SCENE_TERMS.sub(" ", name)

    # 7. Remove hifens ou pontuações órfãs nas extremidades e colapsa múltiplos espaços
    name = re.sub(r"\s+-\s*$", "", name)
    name = re.sub(r"^\s*-\s+", "", name)
    name = re.sub(r"\s{2,}", " ", name).strip(" -_.,;:")

    # Fallback caso o nome inteiro fosse composto apenas por tags
    if not name:
        return raw_name.strip()

    return name


def normalize_signature_key(game_name: str, platform: str) -> str:
    """
    Gera assinatura alfanumérica normalizada (nome + plataforma) para deduplicação
    de jogos em pastas ou formatos equivalentes.
    """
    clean = sanitize_game_name(game_name).lower()
    alnum_name = re.sub(r"[^a-z0-9]+", "", clean)
    alnum_plat = re.sub(r"[^a-z0-9]+", "", platform.lower())
    return f"{alnum_plat}::{alnum_name}"


def extract_local_metadata_hints(raw_name: str, platform: str) -> Tuple[str, str, str]:
    """
    Extrai Ano de Lançamento, Idioma Oficial e Gênero estimado diretamente
    das tags presentes no nome original do arquivo/pasta como heurística local.
    Retorna: (ano, idioma_oficial, genero_heuristico)
    """
    # 1. Ano de Lançamento no nome (ex: "(1998)")
    year_match = RE_YEAR_TOKEN.search(raw_name)
    year = year_match.group(1) if year_match else "N/D"

    # 2. Idioma Oficial a partir de tags No-Intro (En,Fr,De,Es,It,Pt) ou Região
    languages: List[str] = []
    paren_matches = re.findall(r"\(([^\)]+)\)", raw_name)
    for token in paren_matches:
        parts = [p.strip().lower() for p in token.split(",")]
        if parts and all(p in LANG_CODE_MAP for p in parts):
            for p in parts:
                lang_label = LANG_CODE_MAP[p]
                if lang_label not in languages:
                    languages.append(lang_label)

    lower_raw = raw_name.lower()
    if not languages:
        multi_match = re.search(r"\b(multi\d*)\b", lower_raw)
        if multi_match:
            languages.append(f"Multi-idioma ({multi_match.group(1).upper()})")
        if any(tag in lower_raw for tag in ("(brazil)", "(brasil)", "pt-br", "ptbr")):
            languages.append("Português (Brasil)")
        if any(tag in lower_raw for tag in ("(usa)", "(u)", "(world)", "(en)", "(uk)")):
            languages.append("Inglês")
        if any(tag in lower_raw for tag in ("(europe)", "(e)", "(eur)", "pal")):
            languages.append("Multi-idioma (Europa)")
        if any(tag in lower_raw for tag in ("(japan)", "(j)", "(jpn)")):
            languages.append("Japonês")

    official_lang = ", ".join(languages) if languages else "Inglês / Padrão"

    # 3. Heurística leve de Gênero por palavras-chave / séries conhecidas (para modo Offline)
    genre = _infer_genre_from_title(raw_name, platform)

    return year, official_lang, genre


def _infer_genre_from_title(title: str, platform: str) -> str:
    """Infere gênero aproximado por palavras-chave quando a API não está ativa."""
    t = title.lower()
    keyword_genres: List[Tuple[Tuple[str, ...], str]] = [
        (("zelda", "final fantasy", "chrono", "dragon quest", "pokemon", "pokémon", "persona", "witcher", "elder scrolls", "skyrim", "fallout", "diablo", "baldur", "elden ring", "dark souls", "fire emblem", "xenoblade", "tales of", "breath of fire", "suikoden", "kingdom hearts"), "RPG / Aventura"),
        (("mario kart", "gran turismo", "forza", "need for speed", "burnout", "f-zero", "top gear", "dirt", "grid", "f1 ", "assetto", "outrun", "crash team racing"), "Corrida"),
        (("street fighter", "mortal kombat", "tekken", "king of fighters", "kof", "guilty gear", "soulcalibur", "smash bros", "dragon ball z budokai", "marvel vs", "dead or alive", "killer instinct"), "Luta"),
        (("fifa", "pes ", "pro evolution", "winning eleven", "nba ", "madden", "tony hawk", "skate", "tennis", "golf"), "Esportes"),
        (("resident evil", "silent hill", "alone in the dark", "dead space", "outlast", "amnesia", "fatal frame", "alan wake"), "Survival Horror / Ação"),
        (("call of duty", "battlefield", "doom", "quake", "halo", "half-life", "half life", "counter-strike", "medal of honor", "goldeneye", "perfect dark", "metroid prime", "bioshock", "far cry", "crysis", "wolfenstein", "borderlands"), "FPS / Tiro"),
        (("metal gear", "splinter cell", "hitman", "dishonored", "thief", "assassins creed", "assassin's creed"), "Stealth / Ação-Aventura"),
        (("age of empires", "starcraft", "warcraft", "civilization", "command & conquer", "total war", "company of heroes", "simcity", "cities skylines", "tropico", "anno ", "factorio", "pikmin", "advance wars"), "Estratégia / Simulação"),
        (("super mario", "sonic", "donkey kong", "crash bandicoot", "spyro", "rayman", "mega man", "megaman", "castlevania", "metroid", "kirby", "celeste", "hollow knight", "cuphead", "banjo-kazooie", "ratchet", "jak and daxter", "klonoa"), "Plataforma / Ação"),
        (("god of war", "devil may cry", "bayonetta", "ninja gaiden", "grand theft auto", "gta", "red dead", "uncharted", "last of us", "tomb raider", "spider-man", "batman", "monster hunter", "shadow of the colossus", "yakuza"), "Ação / Aventura"),
        (("tetris", "puyo", "lumines", "bust-a-move", "dr. mario", "portal", "baba is you", "professor layton"), "Puzzle"),
    ]
    for keywords, label in keyword_genres:
        if any(k in t for k in keywords):
            return label
    return "Ação / Aventura (Estimado Offline)"


# ==============================================================================
# 2. CLIENTE DE ENRIQUECIMENTO DE METADADOS (IGDB & RAWG) COM CACHE
# ==============================================================================
class MetadataEnricher:
    """
    Cliente unificado para enriquecimento de metadados de jogos via IGDB API (Twitch)
    ou RAWG API, com filtro inteligente por plataforma, cache local em JSON e
    fallback transparente para heurísticas locais.
    """

    def __init__(
        self,
        rawg_api_key: Optional[str] = None,
        igdb_client_id: Optional[str] = None,
        igdb_client_secret: Optional[str] = None,
        igdb_access_token: Optional[str] = None,
        cache_path: Optional[Path] = None,
        offline_mode: bool = False,
    ) -> None:
        self.rawg_api_key = (rawg_api_key if rawg_api_key is not None else RAWG_API_KEY).strip()
        self.igdb_client_id = (igdb_client_id if igdb_client_id is not None else IGDB_CLIENT_ID).strip()
        self.igdb_client_secret = (igdb_client_secret if igdb_client_secret is not None else IGDB_CLIENT_SECRET).strip()
        self.igdb_access_token = (igdb_access_token if igdb_access_token is not None else IGDB_ACCESS_TOKEN).strip()
        self.offline_mode = offline_mode or (requests is None)

        self.cache_path = cache_path or Path(DEFAULT_CACHE_FILE)
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_dirty = False
        self._network_available = True
        self._load_cache()

    def _load_cache(self) -> None:
        """Carrega o cache persistente de metadados se existir."""
        try:
            if self.cache_path.exists():
                with open(self.cache_path, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                    if isinstance(data, dict):
                        self._cache = data
        except Exception:
            self._cache = {}

    def save_cache(self) -> None:
        """Salva o cache atualizado no disco."""
        if not self._cache_dirty:
            return
        try:
            with open(self.cache_path, "w", encoding="utf-8") as fp:
                json.dump(self._cache, fp, ensure_ascii=False, indent=2)
            self._cache_dirty = False
        except Exception:
            pass

    @property
    def is_api_configured(self) -> bool:
        """Retorna True se IGDB ou RAWG estiverem configuradas e modo offline desativado."""
        if self.offline_mode or not self._network_available:
            return False
        has_igdb = bool(self.igdb_client_id and (self.igdb_client_secret or self.igdb_access_token))
        has_rawg = bool(self.rawg_api_key)
        return has_igdb or has_rawg

    def _ensure_igdb_token(self) -> Optional[str]:
        """Obtém um token OAuth2 na Twitch caso apenas Client ID e Secret tenham sido informados."""
        if self.igdb_access_token:
            return self.igdb_access_token
        if not (self.igdb_client_id and self.igdb_client_secret) or requests is None:
            return None

        try:
            resp = requests.post(
                "https://id.twitch.tv/oauth2/token",
                params={
                    "client_id": self.igdb_client_id,
                    "client_secret": self.igdb_client_secret,
                    "grant_type": "client_credentials",
                },
                timeout=API_TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            token = resp.json().get("access_token", "")
            if token:
                self.igdb_access_token = token
                return token
        except Exception:
            self._network_available = False
        return None

    def _query_igdb(self, clean_name: str, local_platform: str) -> Optional[GameMetadata]:
        """Consulta a API da IGDB filtrando pela plataforma identificada localmente."""
        token = self._ensure_igdb_token()
        if not token or requests is None:
            return None

        headers = {
            "Client-ID": self.igdb_client_id,
            "Authorization": f"Bearer {token}",
        }
        escaped_name = clean_name.replace('"', '\\"')
        plat_ids = IGDB_PLATFORM_IDS.get(local_platform, [])

        # Tenta primeiro filtrando pela plataforma exata; se vazio, busca apenas pelo título
        queries: List[str] = []
        if plat_ids:
            ids_str = ",".join(str(i) for i in plat_ids)
            queries.append(
                f'search "{escaped_name}"; '
                f"fields name, first_release_date, genres.name, platforms.name, language_supports.language.name; "
                f"where platforms = ({ids_str}); limit 5;"
            )
        queries.append(
            f'search "{escaped_name}"; '
            f"fields name, first_release_date, genres.name, platforms.name, language_supports.language.name; "
            f"limit 5;"
        )

        for body in queries:
            try:
                resp = requests.post(
                    "https://api.igdb.com/v4/games",
                    headers=headers,
                    data=body.encode("utf-8"),
                    timeout=API_TIMEOUT_SECONDS,
                )
                if resp.status_code != 200:
                    continue
                results = resp.json()
                if not results:
                    continue

                best = results[0]
                official_name = best.get("name") or clean_name

                # Ano de lançamento
                ts = best.get("first_release_date")
                if isinstance(ts, (int, float)):
                    release_year = str(datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).year)
                else:
                    release_year = "N/D"

                # Gêneros
                genres_raw = best.get("genres") or []
                genres = [g.get("name", "") for g in genres_raw if isinstance(g, dict) and g.get("name")]
                genre_str = ", ".join(genres[:3]) if genres else "N/D"

                # Plataformas oficiais
                plats_raw = best.get("platforms") or []
                plat_names = [p.get("name", "") for p in plats_raw if isinstance(p, dict) and p.get("name")]
                official_platform = local_platform if not plat_names else f"{local_platform} ({plat_names[0]})"

                # Idiomas suportados
                lang_raw = best.get("language_supports") or []
                langs: List[str] = []
                for ls in lang_raw:
                    if isinstance(ls, dict) and isinstance(ls.get("language"), dict):
                        lname = ls["language"].get("name", "")
                        if lname and lname not in langs:
                            langs.append(lname)
                lang_str = ", ".join(langs[:5]) if langs else "Inglês / Padrão"

                return GameMetadata(
                    official_name=official_name,
                    official_platform=official_platform,
                    release_year=release_year,
                    genre=genre_str,
                    supported_languages=lang_str,
                    source="IGDB API",
                )
            except requests.RequestException:
                self._network_available = False
                break
            except Exception:
                continue

        return None

    def _query_rawg(self, clean_name: str, local_platform: str) -> Optional[GameMetadata]:
        """Consulta a API da RAWG filtrando pela plataforma identificada localmente."""
        if not self.rawg_api_key or requests is None:
            return None

        plat_ids = RAWG_PLATFORM_IDS.get(local_platform, [])
        attempt_params: List[Dict[str, Any]] = []
        if plat_ids:
            attempt_params.append({
                "key": self.rawg_api_key,
                "search": clean_name,
                "platforms": ",".join(str(i) for i in plat_ids),
                "page_size": 5,
            })
        attempt_params.append({
            "key": self.rawg_api_key,
            "search": clean_name,
            "page_size": 5,
        })

        for params in attempt_params:
            try:
                resp = requests.get(
                    "https://api.rawg.io/api/games",
                    params=params,
                    timeout=API_TIMEOUT_SECONDS,
                )
                if resp.status_code != 200:
                    continue
                payload = resp.json()
                results = payload.get("results") or []
                if not results:
                    continue

                best = results[0]
                official_name = best.get("name") or clean_name
                released = best.get("released") or ""
                release_year = released[:4] if len(released) >= 4 else "N/D"

                genres_raw = best.get("genres") or []
                genres = [g.get("name", "") for g in genres_raw if isinstance(g, dict) and g.get("name")]
                genre_str = ", ".join(genres[:3]) if genres else "N/D"

                plats_raw = best.get("platforms") or []
                plat_names = [
                    p["platform"]["name"]
                    for p in plats_raw
                    if isinstance(p, dict) and isinstance(p.get("platform"), dict) and p["platform"].get("name")
                ]
                official_platform = local_platform if not plat_names else local_platform

                # RAWG tags podem indicar suporte multi-idioma
                tags_raw = best.get("tags") or []
                tag_names = [t.get("name", "") for t in tags_raw if isinstance(t, dict)]
                lang_hints = [
                    t for t in tag_names
                    if any(w in t.lower() for w in ("english", "portuguese", "spanish", "japanese", "multi"))
                ]
                lang_str = ", ".join(lang_hints[:4]) if lang_hints else ""

                return GameMetadata(
                    official_name=official_name,
                    official_platform=official_platform,
                    release_year=release_year,
                    genre=genre_str,
                    supported_languages=lang_str,
                    source="RAWG API",
                )
            except requests.RequestException:
                self._network_available = False
                break
            except Exception:
                continue

        return None

    def enrich(self, raw_name: str, local_platform: str) -> GameMetadata:
        """
        Obtém os metadados enriquecidos de um jogo:
        1. Sanitiza o nome via regex;
        2. Extrai heurísticas locais (ano, idiomas da ROM, gênero estimado);
        3. Consulta cache local ou APIs públicas (IGDB / RAWG) filtrando pela plataforma;
        4. Combina os resultados com fallback gracioso caso offline ou sem API.
        """
        clean_name = sanitize_game_name(raw_name)
        local_year, local_lang, local_genre = extract_local_metadata_hints(raw_name, local_platform)

        cache_key = normalize_signature_key(clean_name, local_platform)
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            return GameMetadata(
                official_name=cached.get("official_name") or clean_name,
                official_platform=cached.get("official_platform") or local_platform,
                release_year=cached.get("release_year") if cached.get("release_year") not in (None, "", "N/D") else local_year,
                genre=cached.get("genre") if cached.get("genre") not in (None, "", "N/D") else local_genre,
                supported_languages=cached.get("supported_languages") or local_lang,
                source="Cache API",
            )

        api_result: Optional[GameMetadata] = None
        if self.is_api_configured:
            # Prioriza IGDB se configurada, caso contrário utiliza RAWG
            if self.igdb_client_id and (self.igdb_client_secret or self.igdb_access_token):
                api_result = self._query_igdb(clean_name, local_platform)
            if api_result is None and self.rawg_api_key:
                api_result = self._query_rawg(clean_name, local_platform)
            # Respeita rate limit gentil entre chamadas de rede
            time.sleep(0.15)

        if api_result is not None:
            # Mescla campos ausentes na API com as heurísticas locais
            if not api_result.release_year or api_result.release_year == "N/D":
                api_result.release_year = local_year
            if not api_result.genre or api_result.genre == "N/D":
                api_result.genre = local_genre
            if not api_result.supported_languages:
                api_result.supported_languages = local_lang

            self._cache[cache_key] = asdict(api_result)
            self._cache_dirty = True
            return api_result

        # Fallback 100% local e resiliente
        return GameMetadata(
            official_name=clean_name,
            official_platform=local_platform,
            release_year=local_year,
            genre=local_genre,
            supported_languages=local_lang,
            source="Heurística Local",
        )
