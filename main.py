"""
main.py - Ponto de entrada CLI do sistema Ludex para catalogação, auditoria de
integridade, detecção de DRM/Tradução, enriquecimento via API (IGDB/RAWG) e
exportação de inventário em Excel (.xlsx).
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import time
import zipfile
from pathlib import Path
from typing import List, Optional

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None  # type: ignore

from config import clean_display_path, to_long_path
from metadata import MetadataEnricher
from report import generate_excel_report
from scanner import GameRecord, LibraryScanner


def create_demo_library(demo_root: Path) -> Path:
    """
    Cria uma biblioteca multimídia de demonstração (ROMs, ISOs com magic headers reais,
    jogos de PC em pastas com Crack/DRM/Tradução, duplicatas binárias e arquivo corrompido)
    para testar e validar imediatamente todos os recursos do sistema.
    """
    demo_root = Path(clean_display_path(demo_root)).resolve()
    demo_root.mkdir(parents=True, exist_ok=True)

    # 1. SNES: Super Mario World (ROM traduzida + duplicata exata)
    snes_dir = demo_root / "SNES"
    snes_dir.mkdir(exist_ok=True)
    smw_payload = b"SNES-ROM-HEADER" + (b"\x42\x99\x13\x37" * 9000)  # ~36 KB (> 32 KB min)
    (snes_dir / "Super Mario World (USA) [T-Por] [PT-BR] [!].sfc").write_bytes(smw_payload)
    (snes_dir / "Super Mario World (Copy Backup).sfc").write_bytes(smw_payload)

    # 2. GBA dentro de .zip íntegro
    gba_dir = demo_root / "GBA"
    gba_dir.mkdir(exist_ok=True)
    with zipfile.ZipFile(to_long_path(gba_dir / "0142 - The Legend of Zelda - The Minish Cap (Europe) (En,Fr,De).zip"), "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Legend of Zelda - The Minish Cap.gba", b"GBA_ROM_DATA" * 4096)

    # 3. GameCube ISO com Magic Number oficial (0xC2339F3D no offset 0x1C)
    gc_dir = demo_root / "Roms_Misturadas"
    gc_dir.mkdir(exist_ok=True)
    gc_buf = bytearray(65536)
    gc_buf[0:6] = b"GZLE01"
    gc_buf[0x1C:0x20] = b"\xc2\x33\x9f\x3d"
    gc_buf[0x20:0x40] = b"The Legend of Zelda Wind Waker"
    (gc_dir / "The Legend of Zelda - The Wind Waker (USA).iso").write_bytes(bytes(gc_buf))

    # 4. PS2 ISO com Primary Volume Descriptor ISO9660 no offset 0x8000
    ps2_dir = demo_root / "PS2"
    ps2_dir.mkdir(exist_ok=True)
    ps2_buf = bytearray(98304)
    ps2_buf[0x8000:0x8006] = b"\x01CD001"
    ps2_buf[0x8008:0x8028] = b"PLAYSTATION                     "
    ps2_buf[0x8200:0x8230] = b"BOOT2 = cdrom0:\\SLUS_211.99;1"
    (ps2_dir / "God of War II (USA) (v1.02) [SLUS-21199].iso").write_bytes(bytes(ps2_buf))

    # 5. PS1 CUE + BIN multi-faixa
    ps1_dir = demo_root / "PS1" / "Castlevania - Symphony of the Night (USA)"
    ps1_dir.mkdir(parents=True, exist_ok=True)
    bin_path = ps1_dir / "Castlevania - SOTN (Track 1).bin"
    bin_path.write_bytes(b"PLAYSTATION_RAW_SECTOR" * 1024)
    cue_content = 'FILE "Castlevania - SOTN (Track 1).bin" BINARY\n  TRACK 01 MODE2/2352\n    INDEX 01 00:00:00\n'
    (ps1_dir / "Castlevania - Symphony of the Night (USA) (1997).cue").write_text(cue_content, encoding="utf-8")

    # 6. PS3 em estrutura de pasta PS3_GAME
    ps3_game_dir = demo_root / "PS3" / "The Last of Us [BCES01584] (PT-BR)" / "PS3_GAME" / "USRDIR"
    ps3_game_dir.mkdir(parents=True, exist_ok=True)
    (ps3_game_dir.parent / "PARAM.SFO").write_bytes(b"\x00PSF" + b"\x01" * 256)
    (ps3_game_dir / "EBOOT.BIN").write_bytes(b"SCE\x00" + b"\x90" * 4096)

    # 7. Jogo de PC em pasta com Crack CODEX + steam_api64.dll + Tradução GameVicio
    pc_game1 = demo_root / "PC" / "The.Witcher.3.Wild.Hunt.v4.04.MULTi15-CODEX"
    (pc_game1 / "bin" / "x64").mkdir(parents=True, exist_ok=True)
    (pc_game1 / "Traducao_GameVicio_PT-BR").mkdir(parents=True, exist_ok=True)
    (pc_game1 / "bin" / "x64" / "witcher3.exe").write_bytes(b"MZ" + b"\x90" * 16384)
    (pc_game1 / "bin" / "x64" / "steam_api64.dll").write_bytes(b"MZ" + b"\x01" * 2048)
    (pc_game1 / "bin" / "x64" / "codex64.dll").write_bytes(b"MZ" + b"\x02" * 2048)
    (pc_game1 / "unins000.exe").write_bytes(b"MZ" + b"\x03" * 1024)

    # 8. Jogo de PC DRM-Free GOG com suporte Nativo PT-BR
    pc_game2 = demo_root / "PC" / "Cyberpunk 2077 (2020) [GOG]"
    pc_game2.mkdir(parents=True, exist_ok=True)
    (pc_game2 / "Cyberpunk2077.exe").write_bytes(b"MZ" + b"\xaa" * 16384)
    (pc_game2 / "goggame-1423049311.info").write_text('{"language": "pt-BR"}', encoding="utf-8")
    (pc_game2 / "lang_pt-br.archive").write_bytes(b"ARCHIVE_PTBR" * 512)

    # 9. Arquivo .zip Corrompido no Nintendo Switch para testar detecção de corrupção
    sw_dir = demo_root / "Switch"
    sw_dir.mkdir(exist_ok=True)
    (sw_dir / "Super Mario Odyssey (World) [Corrupted Dump].zip").write_bytes(b"PK\x03\x04CORRUPTED_TRUNCATED_ZIP_STREAM")

    return demo_root


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ludex",
        description=(
            "Ludex — Sistema Modular de Catalogação, Auditoria de Integridade, "
            "Detecção de DRM/Tradução e Exportação Excel (.xlsx) para Bibliotecas de Jogos."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos de uso:\n"
            "  python main.py \"D:\\Jogos\" -o relatorio_jogos.xlsx\n"
            "  python main.py \"D:\\ROMs\" --rawg-key SUA_CHAVE_RAWG\n"
            "  python main.py ./demo_library --create-demo -o demo_auditoria.xlsx\n"
        ),
    )

    parser.add_argument(
        "root_dir",
        nargs="?",
        default=None,
        help="Diretório raiz da biblioteca de jogos a ser inspecionada recursivamente.",
    )
    parser.add_argument(
        "-i",
        "--input",
        dest="input_dir",
        default=None,
        help="Caminho alternativo para o diretório raiz da biblioteca.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="ludex_inventario.xlsx",
        help="Caminho do arquivo Excel (.xlsx) de saída (padrão: ludex_inventario.xlsx).",
    )
    parser.add_argument(
        "--rawg-key",
        default=None,
        help="Chave da API pública RAWG (sobrescreve a variável de ambiente RAWG_API_KEY).",
    )
    parser.add_argument(
        "--igdb-client-id",
        default=None,
        help="Client ID da Twitch/IGDB (sobrescreve IGDB_CLIENT_ID).",
    )
    parser.add_argument(
        "--igdb-client-secret",
        default=None,
        help="Client Secret da Twitch/IGDB (sobrescreve IGDB_CLIENT_SECRET).",
    )
    parser.add_argument(
        "--igdb-token",
        default=None,
        help="Access Token OAuth2 da IGDB (sobrescreve IGDB_ACCESS_TOKEN).",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Executa 100%% offline utilizando apenas regex e heurísticas locais.",
    )
    parser.add_argument(
        "--fast-archives",
        action="store_true",
        help="Valida apenas cabeçalhos/catálogos de arquivos .zip/.7z/.rar sem descomprimir fluxos CRC longos.",
    )
    parser.add_argument(
        "--hash-all",
        action="store_true",
        help="Calcula SHA-256 para todos os arquivos (por padrão, calcula apenas quando há colisão de tamanho exato).",
    )
    parser.add_argument(
        "--create-demo",
        action="store_true",
        help="Gera uma biblioteca de jogos simulada no diretório informado antes de rodar a auditoria.",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    target_dir_str = args.input_dir or args.root_dir
    if not target_dir_str:
        if args.create_demo:
            target_dir_str = "./demo_library"
        else:
            parser.print_help()
            print("\n[ERRO] Informe o diretório raiz da biblioteca de jogos ou use --create-demo.")
            return 1

    root_path = Path(clean_display_path(target_dir_str)).resolve()

    if args.create_demo:
        print(f"[*] Criando biblioteca de demonstração em: {root_path}")
        create_demo_library(root_path)

    if not os.path.exists(to_long_path(root_path)) or not os.path.isdir(to_long_path(root_path)):
        print(f"[ERRO] O diretório informado não existe ou não é válido: {root_path}")
        return 1

    start_time = time.time()
    print("=" * 72)
    print(" LUDEX — AUDITORIA E CATALOGAÇÃO DE BIBLIOTECA MULTIMÍDIA DE JOGOS")
    print("=" * 72)
    print(f" Diretório Raiz : {clean_display_path(root_path)}")
    print(f" Planilha Saída : {clean_display_path(Path(args.output).resolve())}")

    enricher = MetadataEnricher(
        rawg_api_key=args.rawg_key,
        igdb_client_id=args.igdb_client_id,
        igdb_client_secret=args.igdb_client_secret,
        igdb_access_token=args.igdb_token,
        offline_mode=args.offline,
    )

    api_status = "Ativa (Online)" if enricher.is_api_configured else "Desativada / Fallback Heurístico Local"
    print(f" Integração API : {api_status}")
    print("-" * 72)

    scanner = LibraryScanner(
        root_dir=root_path,
        enricher=enricher,
        deep_archive_check=not args.fast_archives,
        hash_all_files=args.hash_all,
    )

    print("[1/3] Inspecionando estrutura de diretórios e mapeando entidades...")
    candidates = scanner.discover_candidates()
    total = len(candidates)

    if total == 0:
        print("[!] Nenhum jogo ou ROM reconhecida foi encontrada no diretório especificado.")
        return 0

    print(f"[2/3] Auditando integridade, DRM/Tradução e enriquecendo {total} jogo(s)...")
    if tqdm is not None:
        with tqdm(total=total, desc="Auditando Jogos", unit="jogo", ncols=90) as pbar:
            for rec in candidates:
                pbar.set_postfix_str(rec.raw_name[:28], refresh=False)
                scanner.audit_and_enrich_record(rec)
                pbar.update(1)
    else:
        for idx, rec in enumerate(candidates, start=1):
            print(f"  -> [{idx}/{total}] {rec.platform}: {rec.raw_name}")
            scanner.audit_and_enrich_record(rec)

    print("[3/3] Executando deduplicação inteligente (Tamanho + SHA-256 64KB + Assinatura)...")
    scanner.deduplicate_records(candidates)
    enricher.save_cache()

    candidates.sort(key=lambda r: (r.platform.lower(), (r.official_name or r.raw_name).lower()))

    output_file = generate_excel_report(
        records=candidates,
        output_path=Path(args.output),
        scanned_root=root_path,
    )

    elapsed = time.time() - start_time
    corrupted_count = sum(1 for r in candidates if r.is_corrupted)
    duplicate_count = sum(1 for r in candidates if r.is_duplicate)
    translated_count = sum(
        1 for r in candidates
        if any(k in r.translation_status for k in ("PT-BR", "Mod Local", "ROM Traduzida"))
    )

    print("=" * 72)
    print(" RESUMO DA AUDITORIA CONCLUÍDA")
    print("=" * 72)
    print(f" Total de Jogos Catalogados : {total}")
    print(f" Jogos Íntegros             : {total - corrupted_count}")
    print(f" Jogos Corrompidos          : {corrupted_count}")
    print(f" Jogos Duplicados           : {duplicate_count}")
    print(f" Jogos com PT-BR / Tradução : {translated_count}")
    print(f" Tempo de Processamento     : {elapsed:.2f}s")
    print(f" Relatório Excel Gerado     : {clean_display_path(output_file)}")
    print("=" * 72)

    if scanner.scan_errors:
        print(f"[!] Avisos de permissão/sistema durante a varredura ({len(scanner.scan_errors)}):")
        for err in scanner.scan_errors[:5]:
            print(f"    - {err}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
