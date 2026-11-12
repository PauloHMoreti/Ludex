"""
report.py - Exportador Excel (.xlsx) de alto padrão executivo utilizando openpyxl.
Gera pasta de trabalho com as abas 'Dashboard' e 'Biblioteca Geral', estilização
profissional, congelamento de painéis, autofiltro, auto-ajuste de colunas e
formatação condicional obrigatória.
"""

from __future__ import annotations

import datetime
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

from openpyxl import Workbook
from openpyxl.chart import BarChart, Reference
from openpyxl.formatting.rule import FormulaRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from config import EXCEL_HEADERS_LIBRARY, EXCEL_THEME, clean_display_path, to_long_path
from scanner import GameRecord


def _format_size(size_bytes: int) -> str:
    """Converte tamanho em bytes para representação legível (KB, MB, GB)."""
    if size_bytes <= 0:
        return "0 MB"
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size_bytes)
    idx = 0
    while value >= 1024.0 and idx < len(units) - 1:
        value /= 1024.0
        idx += 1
    if idx <= 1:
        return f"{value:.0f} {units[idx]}"
    return f"{value:.2f} {units[idx]}"


def _auto_adjust_column_widths(
    ws,
    min_width: int = 12,
    max_width: int = 68,
    safety_padding: int = 5,
) -> None:
    """
    Calcula e aplica automaticamente a largura ideal de cada coluna da planilha
    com espaçamento de segurança para evitar textos truncados.
    """
    for col in ws.columns:
        first_cell = col[0]
        col_letter = get_column_letter(first_cell.column)
        max_len = 0
        for cell in col:
            # Ignora células de banner mescladas na primeira linha do Dashboard
            if cell.coordinate in ws.merged_cells and cell.row <= 3:
                continue
            val_str = str(cell.value or "")
            # Se tiver quebras de linha, considera a maior linha
            lines = val_str.splitlines() or [""]
            cell_len = max(len(line) for line in lines)
            if cell_len > max_len:
                max_len = cell_len

        adjusted = max(min_width, min(max_len + safety_padding, max_width))
        ws.column_dimensions[col_letter].width = adjusted


def _build_dashboard_sheet(
    ws,
    records: List[GameRecord],
    scanned_root: Optional[Path] = None,
) -> None:
    """Constrói a aba executiva 'Dashboard' com KPIs, tabela por plataforma e gráfico."""
    ws.views.sheetView[0].showGridLines = True

    font_family = "Segoe UI"
    header_fill = PatternFill(start_color=EXCEL_THEME["header_bg"], end_color=EXCEL_THEME["header_bg"], fill_type="solid")
    accent_fill = PatternFill(start_color=EXCEL_THEME["accent_primary"], end_color=EXCEL_THEME["accent_primary"], fill_type="solid")
    zebra_even_fill = PatternFill(start_color=EXCEL_THEME["zebra_even"], end_color=EXCEL_THEME["zebra_even"], fill_type="solid")
    zebra_odd_fill = PatternFill(start_color=EXCEL_THEME["zebra_odd"], end_color=EXCEL_THEME["zebra_odd"], fill_type="solid")
    card_fill = PatternFill(start_color=EXCEL_THEME["kpi_card_bg"], end_color=EXCEL_THEME["kpi_card_bg"], fill_type="solid")

    corrupt_fill = PatternFill(start_color=EXCEL_THEME["corrupt_bg"], end_color=EXCEL_THEME["corrupt_bg"], fill_type="solid")
    dup_fill = PatternFill(start_color=EXCEL_THEME["duplicate_bg"], end_color=EXCEL_THEME["duplicate_bg"], fill_type="solid")
    trans_fill = PatternFill(start_color=EXCEL_THEME["translation_bg"], end_color=EXCEL_THEME["translation_bg"], fill_type="solid")

    thin_side = Side(border_style="thin", color=EXCEL_THEME["border_color"])
    thin_border = Border(left=thin_side, right=thin_side, top=thin_side, bottom=thin_side)

    # 1. Banner Executivo
    ws.merge_cells("A1:G1")
    title_cell = ws["A1"]
    title_cell.value = "LUDEX — RELATÓRIO EXECUTIVO DE AUDITORIA E CATÁLOGO DE JOGOS"
    title_cell.font = Font(name=font_family, size=15, bold=True, color=EXCEL_THEME["header_fg"])
    title_cell.fill = header_fill
    title_cell.alignment = Alignment(horizontal="left", vertical="center", indent=1)
    ws.row_dimensions[1].height = 36

    ws.merge_cells("A2:G2")
    sub_cell = ws["A2"]
    now_str = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    root_str = clean_display_path(scanned_root) if scanned_root else "Biblioteca Consolidada"
    sub_cell.value = f"Gerado em: {now_str}   |   Diretório Raiz: {root_str}"
    sub_cell.font = Font(name=font_family, size=10, italic=True, color="374151")
    sub_cell.fill = zebra_even_fill
    sub_cell.alignment = Alignment(horizontal="left", vertical="center", indent=1)
    ws.row_dimensions[2].height = 22

    # 2. Métricas Globais (KPIs)
    total_games = len(records)
    total_corrupted = sum(1 for r in records if "sim" in r.corrupted_status.lower())
    total_duplicates = sum(1 for r in records if "sim" in r.duplicate_status.lower())
    total_translated = sum(
        1 for r in records
        if any(k in r.translation_status.lower() for k in ("pt-br", "mod local", "rom traduzida"))
    )
    total_size_bytes = sum(r.size_bytes for r in records)
    unique_platforms = len({r.platform for r in records})

    kpis = [
        ("Total de Jogos", total_games, card_fill, "111827"),
        ("Plataformas Mapeadas", unique_platforms, card_fill, "1E3A8A"),
        ("Jogos Corrompidos", total_corrupted, corrupt_fill if total_corrupted > 0 else card_fill, EXCEL_THEME["corrupt_fg"] if total_corrupted > 0 else "166534"),
        ("Jogos Duplicados", total_duplicates, dup_fill if total_duplicates > 0 else card_fill, EXCEL_THEME["duplicate_fg"] if total_duplicates > 0 else "374151"),
        ("Localizados / PT-BR", total_translated, trans_fill if total_translated > 0 else card_fill, EXCEL_THEME["translation_fg"] if total_translated > 0 else "374151"),
        ("Volume Total Auditado", _format_size(total_size_bytes), card_fill, "111827"),
    ]

    ws.row_dimensions[4].height = 20
    ws.row_dimensions[5].height = 28

    for idx, (label, val, fill_obj, fg_color) in enumerate(kpis, start=1):
        lbl_cell = ws.cell(row=4, column=idx, value=label)
        lbl_cell.font = Font(name=font_family, size=9, bold=True, color="4B5563")
        lbl_cell.fill = fill_obj
        lbl_cell.alignment = Alignment(horizontal="center", vertical="center")
        lbl_cell.border = thin_border

        val_cell = ws.cell(row=5, column=idx, value=val)
        val_cell.font = Font(name=font_family, size=14, bold=True, color=fg_color)
        val_cell.fill = fill_obj
        val_cell.alignment = Alignment(horizontal="center", vertical="center")
        val_cell.border = thin_border

    # 3. Tabela de Quebra por Plataforma
    ws.cell(row=7, column=1, value="RESUMO POR PLATAFORMA / SISTEMA").font = Font(
        name=font_family, size=12, bold=True, color=EXCEL_THEME["header_bg"]
    )
    ws.row_dimensions[7].height = 24

    dash_headers = [
        "Plataforma",
        "Qtd. de Jogos",
        "% do Catálogo",
        "Volume Total",
        "Corrompidos",
        "Duplicados",
        "Com PT-BR / Tradução",
    ]

    header_row = 8
    ws.row_dimensions[header_row].height = 26
    for col_idx, text in enumerate(dash_headers, start=1):
        c = ws.cell(row=header_row, column=col_idx, value=text)
        c.font = Font(name=font_family, size=10, bold=True, color=EXCEL_THEME["header_fg"])
        c.fill = header_fill
        c.alignment = Alignment(horizontal="center" if col_idx > 1 else "left", vertical="center", indent=1 if col_idx == 1 else 0)
        c.border = thin_border

    # Agrupamento de estatísticas por plataforma
    plat_stats: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {"count": 0, "size": 0, "corrupt": 0, "dup": 0, "ptbr": 0}
    )
    for rec in records:
        st = plat_stats[rec.platform]
        st["count"] += 1
        st["size"] += rec.size_bytes
        if "sim" in rec.corrupted_status.lower():
            st["corrupt"] += 1
        if "sim" in rec.duplicate_status.lower():
            st["dup"] += 1
        if any(k in rec.translation_status.lower() for k in ("pt-br", "mod local", "rom traduzida")):
            st["ptbr"] += 1

    sorted_platforms = sorted(plat_stats.items(), key=lambda kv: (-kv[1]["count"], kv[0].lower()))

    current_row = header_row + 1
    for idx, (plat_name, st) in enumerate(sorted_platforms):
        ws.row_dimensions[current_row].height = 22
        row_fill = zebra_even_fill if idx % 2 == 0 else zebra_odd_fill
        pct = (st["count"] / total_games) if total_games > 0 else 0.0

        row_values = [
            plat_name,
            st["count"],
            pct,
            _format_size(st["size"]),
            st["corrupt"],
            st["dup"],
            st["ptbr"],
        ]

        for col_idx, val in enumerate(row_values, start=1):
            c = ws.cell(row=current_row, column=col_idx, value=val)
            c.font = Font(name=font_family, size=10, bold=(col_idx == 1), color="1F2937")
            c.fill = row_fill
            c.border = thin_border
            if col_idx == 1:
                c.alignment = Alignment(horizontal="left", vertical="center", indent=1)
            elif col_idx == 3:
                c.number_format = "0.0%"
                c.alignment = Alignment(horizontal="center", vertical="center")
            else:
                c.alignment = Alignment(horizontal="center", vertical="center")

            # Destaques visuais discretos nas contagens críticas da plataforma
            if col_idx == 5 and st["corrupt"] > 0:
                c.fill = corrupt_fill
                c.font = Font(name=font_family, size=10, bold=True, color=EXCEL_THEME["corrupt_fg"])
            elif col_idx == 6 and st["dup"] > 0:
                c.fill = dup_fill
                c.font = Font(name=font_family, size=10, bold=True, color=EXCEL_THEME["duplicate_fg"])
            elif col_idx == 7 and st["ptbr"] > 0:
                c.fill = trans_fill
                c.font = Font(name=font_family, size=10, bold=True, color=EXCEL_THEME["translation_fg"])

        current_row += 1

    # Linha de Total Consolidado no final da tabela do Dashboard
    ws.row_dimensions[current_row].height = 25
    total_row_values = [
        "TOTAL CONSOLIDADO",
        total_games,
        1.0 if total_games > 0 else 0.0,
        _format_size(total_size_bytes),
        total_corrupted,
        total_duplicates,
        total_translated,
    ]
    for col_idx, val in enumerate(total_row_values, start=1):
        c = ws.cell(row=current_row, column=col_idx, value=val)
        c.font = Font(name=font_family, size=10, bold=True, color=EXCEL_THEME["header_fg"])
        c.fill = accent_fill
        c.border = thin_border
        if col_idx == 3:
            c.number_format = "0.0%"
        c.alignment = Alignment(horizontal="center" if col_idx > 1 else "left", vertical="center", indent=1 if col_idx == 1 else 0)

    # 4. Gráfico Executivo de Distribuição por Plataforma (se houver pelo menos 1 plataforma)
    if sorted_platforms:
        chart = BarChart()
        chart.type = "col"
        chart.style = 10
        chart.title = "Distribuição de Jogos por Plataforma"
        chart.y_axis.title = "Quantidade de Jogos"
        chart.x_axis.title = "Plataforma"
        chart.legend = None
        chart.width = 18
        chart.height = 10

        data_ref = Reference(ws, min_col=2, min_row=header_row, max_row=current_row - 1)
        cats_ref = Reference(ws, min_col=1, min_row=header_row + 1, max_row=current_row - 1)
        chart.add_data(data_ref, titles_from_data=True)
        chart.set_categories(cats_ref)
        ws.add_chart(chart, f"A{current_row + 2}")

    _auto_adjust_column_widths(ws, min_width=16, max_width=45, safety_padding=6)


def _build_general_library_sheet(ws, records: List[GameRecord]) -> None:
    """
    Constrói a aba 'Biblioteca Geral' com todas as 11 colunas especificadas,
    cabeçalho escuro (#1F2937), linhas zebradas (#F9FAFB / #FFFFFF), Freeze Panes,
    AutoFilter e Formatação Condicional obrigatória.
    """
    ws.views.sheetView[0].showGridLines = True
    font_family = "Segoe UI"

    header_fill = PatternFill(start_color=EXCEL_THEME["header_bg"], end_color=EXCEL_THEME["header_bg"], fill_type="solid")
    zebra_even_fill = PatternFill(start_color=EXCEL_THEME["zebra_even"], end_color=EXCEL_THEME["zebra_even"], fill_type="solid")
    zebra_odd_fill = PatternFill(start_color=EXCEL_THEME["zebra_odd"], end_color=EXCEL_THEME["zebra_odd"], fill_type="solid")

    corrupt_fill = PatternFill(start_color=EXCEL_THEME["corrupt_bg"], end_color=EXCEL_THEME["corrupt_bg"], fill_type="solid")
    corrupt_font = Font(name=font_family, size=10, bold=True, color=EXCEL_THEME["corrupt_fg"])

    dup_fill = PatternFill(start_color=EXCEL_THEME["duplicate_bg"], end_color=EXCEL_THEME["duplicate_bg"], fill_type="solid")
    dup_font = Font(name=font_family, size=10, bold=True, color=EXCEL_THEME["duplicate_fg"])

    trans_fill = PatternFill(start_color=EXCEL_THEME["translation_bg"], end_color=EXCEL_THEME["translation_bg"], fill_type="solid")
    trans_font = Font(name=font_family, size=10, bold=True, color=EXCEL_THEME["translation_fg"])

    thin_side = Side(border_style="thin", color=EXCEL_THEME["border_color"])
    thin_border = Border(left=thin_side, right=thin_side, top=thin_side, bottom=thin_side)

    # 1. Linha de Cabeçalho (Linha 1)
    ws.row_dimensions[1].height = 28
    for col_idx, header_text in enumerate(EXCEL_HEADERS_LIBRARY, start=1):
        cell = ws.cell(row=1, column=col_idx, value=header_text)
        cell.font = Font(name=font_family, size=10, bold=True, color=EXCEL_THEME["header_fg"])
        cell.fill = header_fill
        cell.alignment = Alignment(
            horizontal="center" if col_idx in (1, 3, 6, 7, 8, 10) else "left",
            vertical="center",
            indent=1 if col_idx not in (1, 3, 6, 7, 8, 10) else 0,
        )
        cell.border = thin_border

    # 2. Congelamento de painéis (Freeze Panes) na linha de cabeçalho
    ws.freeze_panes = "A2"

    # 3. Preenchimento das linhas de dados
    for idx, rec in enumerate(records):
        row_num = idx + 2
        ws.row_dimensions[row_num].height = 22
        base_fill = zebra_even_fill if idx % 2 == 0 else zebra_odd_fill
        base_font = Font(name=font_family, size=10, color="111827")

        location_display = f"{rec.display_path} ({_format_size(rec.size_bytes)})"

        row_data = [
            rec.platform,                                # 1. Plataforma
            rec.official_name or rec.raw_name,           # 2. Nome do Jogo
            rec.release_year,                            # 3. Ano de Lançamento
            rec.genre,                                   # 4. Gênero
            rec.official_language,                       # 5. Idioma Oficial
            rec.translation_status,                      # 6. Tradução
            rec.crack_drm_status,                        # 7. Crack / DRM
            rec.duplicate_status,                        # 8. Duplicado
            location_display,                            # 9. Arquivos / Localização
            rec.corrupted_status,                        # 10. Corrompido
            rec.observations_text,                       # 11. Observações
        ]

        for col_idx, value in enumerate(row_data, start=1):
            cell = ws.cell(row=row_num, column=col_idx, value=value)
            cell.fill = base_fill
            cell.font = base_font
            cell.border = thin_border

            if col_idx in (1, 3, 6, 7, 8, 10):
                cell.alignment = Alignment(horizontal="center", vertical="center")
            else:
                cell.alignment = Alignment(horizontal="left", vertical="center", indent=1)

            # Destaque de negrito suave no Nome do Jogo e Plataforma
            if col_idx in (1, 2):
                cell.font = Font(name=font_family, size=10, bold=(col_idx == 2), color="111827")

            # Aplicação direta dos estilos condicionais nas células correspondentes:
            # Coluna 6: Tradução ("PT-BR", "Mod Local", "ROM Traduzida") -> Verde claro (#DCFCE7)
            if col_idx == 6 and any(
                token in str(value) for token in ("PT-BR", "Mod Local", "ROM Traduzida")
            ):
                cell.fill = trans_fill
                cell.font = trans_font

            # Coluna 8: Duplicado ("Sim") -> Azul suave (#DBEAFE)
            if col_idx == 8 and "Sim" in str(value):
                cell.fill = dup_fill
                cell.font = dup_font

            # Coluna 10: Corrompido ("Sim") -> Fundo vermelho (#FEE2E2) e texto escuro (#991B1B)
            if col_idx == 10 and "Sim" in str(value):
                cell.fill = corrupt_fill
                cell.font = corrupt_font

    last_row = max(2, len(records) + 1)
    last_col_letter = get_column_letter(len(EXCEL_HEADERS_LIBRARY))

    # 4. Ativação do AutoFilter cobrindo toda a tabela
    ws.auto_filter.ref = f"A1:{last_col_letter}{last_row}"

    # 5. Regras nativas de Formatação Condicional do Excel (openpyxl ConditionalFormatting)
    # Coluna F (6) = Tradução | Coluna H (8) = Duplicado | Coluna J (10) = Corrompido
    corrupt_rule = FormulaRule(
        formula=['ISNUMBER(SEARCH("Sim",J2))'],
        stopIfTrue=True,
        fill=corrupt_fill,
        font=corrupt_font,
    )
    ws.conditional_formatting.add(f"J2:J{last_row}", corrupt_rule)

    duplicate_rule = FormulaRule(
        formula=['ISNUMBER(SEARCH("Sim",H2))'],
        stopIfTrue=True,
        fill=dup_fill,
        font=dup_font,
    )
    ws.conditional_formatting.add(f"H2:H{last_row}", duplicate_rule)

    translation_rule = FormulaRule(
        formula=['OR(ISNUMBER(SEARCH("PT-BR",F2)),ISNUMBER(SEARCH("Mod Local",F2)),ISNUMBER(SEARCH("ROM Traduzida",F2)))'],
        stopIfTrue=True,
        fill=trans_fill,
        font=trans_font,
    )
    ws.conditional_formatting.add(f"F2:F{last_row}", translation_rule)

    # 6. Auto-ajuste da largura das colunas com margem de segurança
    _auto_adjust_column_widths(ws, min_width=14, max_width=70, safety_padding=5)


def generate_excel_report(
    records: List[GameRecord],
    output_path: Path,
    scanned_root: Optional[Path] = None,
) -> Path:
    """
    Gera o arquivo Excel (.xlsx) final contendo as abas 'Dashboard' e 'Biblioteca Geral'.
    Garante criação do diretório pai e suporte a caminhos longos no Windows.
    """
    output_path = Path(clean_display_path(output_path)).resolve()
    if output_path.suffix.lower() != ".xlsx":
        output_path = output_path.with_suffix(".xlsx")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    wb = Workbook()
    # Primeira aba: Dashboard
    ws_dashboard = wb.active
    ws_dashboard.title = "Dashboard"

    # Segunda aba: Biblioteca Geral
    ws_library = wb.create_sheet(title="Biblioteca Geral")

    _build_dashboard_sheet(ws_dashboard, records, scanned_root=scanned_root)
    _build_general_library_sheet(ws_library, records)

    wb.save(to_long_path(output_path))
    return output_path
