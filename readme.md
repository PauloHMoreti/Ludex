# Ludex — Catalogador e Auditor de Biblioteca Multimídia de Jogos

O **Ludex** é um sistema modular em Python projetado para inspecionar, auditar, enriquecer e catalogar bibliotecas de jogos de **PC** e **Consoles/Emuladores** (ROMs, ISOs, arquivos compactados e pastas estruturadas), gerando um inventário consolidado em uma planilha **Excel (`.xlsx`)** de padrão executivo.

---

## Principais Funcionalidades

1. **Varredura Inteligente por Entidade/Jogo (`scanner.py`)**:
   - Trata arquivos compactados (`.zip`, `.7z`, `.rar`), imagens de disco (`.iso`, `.chd`, `.rvz`, `.wbfs`, `.cso`) e ROMs como unidades de jogo.
   - Agrupa automaticamente pastas de jogos instalados de **PC**, estruturas **`PS3_GAME`** (PlayStation 3), pastas **Wii U** (`.rpx`) e descritores multi-faixa **`.cue` / `.gdi`** (evitando que arquivos `.bin`, desinstaladores `unins000.exe` ou `vcredist` sejam listados como jogos separados).
2. **Desambiguação Automática de Plataforma (`platforms.py`)**:
   - Mapeia plataformas **Nintendo** (`NES`, `SNES`, `N64`, `GameCube`, `Wii`, `Wii U`, `Switch`, `GB`, `GBC`, `GBA`, `NDS`, `3DS`), **Sony** (`PS1`, `PS2`, `PSP`, `PS3`), **Sega** (`Mega Drive`, `Master System`, `Game Gear`, `Dreamcast`, `Saturn`, `Sega CD`) e **PC**.
   - Resolve extensões ambíguas (`.iso`, `.chd`, `.bin`, `.cue`, `.pbp`, `.cso`, `.rvz`) lendo **Magic Numbers / Cabeçalhos Binários** (ex.: `0xC2339F3D` para GameCube, `0x5D1C9EA3` para Wii, Primary Volume Descriptor ISO 9660 para PS1/PS2/PSP/PS3/Sega/PC), inspecionando o interior de arquivos `.zip`/`.7z`/`.rar` sem extraí-los e analisando pastas ancestrais ou códigos seriais (`SLUS`, `BLES`, `ULUS`).
3. **Auditoria de Integridade e Corrupção (`integrity.py`)**:
   - Valida CRC interno de arquivos `.zip` (`zipfile`), `.7z` (`py7zr`) e `.rar` (`rarfile`, com **fallback gracioso** por assinatura RAR4/RAR5 e leitura de extremidades caso o binário externo `unrar` não esteja instalado no sistema).
   - Para ROMs e ISOs descompactadas, valida tamanho mínimo por formato, assinatura mágica e leitura física dos blocos iniciais e finais (64 KB), detectando arquivos truncados ou zerados.
4. **Detecção de Crack / DRM e Tradução / Localização (`scanner.py`)**:
   - **Crack / DRM (Exclusivo PC)**: Identifica `steam_api.dll`, `steam_api64.dll`, `GOG` (DRM-Free), emuladores de Steam (`Goldberg`, `SmartSteamEmu`, `CreamAPI`) e grupos de cena/repacks (`CODEX`, `FLT`, `RUNE`, `TENOKE`, `Razor1911`, `RELOADED`, `SKIDROW`, `FitGirl`, `No-CD`, `Crack`). Para consoles, preenche automaticamente com `"N/A (Console)"`.
   - **Tradução / Localização**: Classifica em `"Mod Local"` (patches `GameVicio`, `Tribo Gamer`, pastas `traducao`/`pt-br`), `"ROM Traduzida"` (tags `[T-Por]`, `[PT-BR]`, patches `.ips`/`.bps`/`.xdelta`), `"Nativo PT-BR"` ou `"Não detectada"`.
5. **Deduplicação em Duas Etapas (`scanner.py`)**:
   - **Arquivos (ROMs/ISOs/Zips)**: Agrupa primeiro por tamanho exato em bytes e valida colisões calculando o hash **SHA-256** em blocos de **64 KB**.
   - **Pastas e Títulos Equivalentes**: Compara a assinatura normalizada (`nome_sanitizado + plataforma`).
6. **Enriquecimento via API Pública com Filtro de Plataforma (`metadata.py`)**:
   - Sanitiza nomes via Regex removendo tags de dump (`[!]`, `(USA)`, `(En,Fr,De)`, `(v1.0)`, `Repack`, `MULTi`, grupos de cena).
   - Integra-se com a **IGDB API** (Twitch Developer) e/ou **RAWG API**, filtrando a busca pelo ID oficial da plataforma identificada localmente e salvando cache local (`.ludex_metadata_cache.json`).
   - Possui fallback 100% resiliente para modo offline caso nenhuma chave de API esteja configurada.
7. **Relatório Excel (`.xlsx`) Executivo (`report.py`)**:
   - **Aba `Dashboard`**: KPIs globais, tabela de resumo por plataforma (contagem, %, volume em disco, corrompidos, duplicados, traduzidos) e gráfico de barras nativo.
   - **Aba `Biblioteca Geral`**: Cabeçalho escuro (`#1F2937`), linhas zebradas (`#F9FAFB` / `#FFFFFF`), `Freeze Panes`, `AutoFilter`, ajuste automático de largura de colunas e **Formatação Condicional**:
     - `Corrompido` contendo `"Sim"` -> Fundo vermelho (`#FEE2E2`) e texto escuro (`#991B1B`).
     - `Duplicado` contendo `"Sim"` -> Destaque em azul suave (`#DBEAFE`) e texto (`#1E40AF`).
     - `Tradução` contendo `"PT-BR"`, `"Mod Local"` ou `"ROM Traduzida"` -> Destaque em verde claro (`#DCFCE7`) e texto (`#166534`).

---

## Arquitetura do Projeto

```text
Ludex/
├── config.py         # Dicionários de extensões, constantes, tema Excel e suporte a caminhos longos (\\?\)
├── platforms.py      # Desambiguação de plataformas via magic numbers, ISO9660, arquivos compactados e pastas
├── integrity.py      # Testes de integridade em .zip, .7z, .rar (com fallback gracioso) e ROMs/ISOs
├── metadata.py       # Sanitização via Regex, heurísticas locais e cliente de API (IGDB / RAWG) com cache
├── scanner.py        # Varredura recursiva, detecção de Crack/DRM, Tradução e Deduplicação SHA-256
├── report.py         # Gerador de planilhas Excel (.xlsx) estilizadas com openpyxl
├── main.py           # Interface de linha de comando (CLI) com argparse e barra de progresso tqdm
├── requirements.txt  # Dependências do projeto
└── readme.md         # Documentação e guia de uso
```

---

## Instalação

1. Certifique-se de possuir o **Python 3.10+** instalado.
2. Instale as dependências listadas no arquivo `requirements.txt`:

```bash
pip install -r requirements.txt
```

> **Nota sobre arquivos `.rar`**: A biblioteca `rarfile` utiliza o utilitário `unrar` (caso instalado no PATH do sistema) para verificar o CRC interno de cada arquivo comprimido. Caso o `unrar` não esteja instalado na máquina, o **Ludex** aciona automaticamente seu **fallback gracioso**, validando a assinatura binária RAR4/RAR5 e a integridade de leitura dos blocos iniciais e finais sem interromper a execução.

---

## Configuração Opcional de API (IGDB / RAWG)

O sistema funciona imediatamente sem configuração de API (usando o motor heurístico local). Para habilitar o enriquecimento online via **RAWG** ou **IGDB**, defina as variáveis de ambiente no sistema, em um arquivo `.env` na raiz do projeto, ou passe via argumentos de linha de comando:

```env
# Opção 1: RAWG Video Games Database API (https://rawg.io/apidocs)
RAWG_API_KEY=sua_chave_rawg_aqui

# Opção 2: IGDB API via Twitch Developer (https://api-docs.igdb.com/)
IGDB_CLIENT_ID=seu_client_id_twitch
IGDB_CLIENT_SECRET=seu_client_secret_twitch
```

---

## Como Utilizar

### 1. Escanear uma biblioteca existente
```bash
python main.py "D:\Minha Biblioteca de Jogos" -o inventario_jogos.xlsx
```

### 2. Executar informando chave da API RAWG ou IGDB via CLI
```bash
python main.py "D:\Jogos" -o inventario.xlsx --rawg-key SUA_CHAVE_RAWG
```

### 3. Executar em modo estritamente Offline / Rápido
```bash
python main.py "D:\Jogos" -o inventario.xlsx --offline --fast-archives
```

### 4. Gerar uma Biblioteca de Demonstração e Testar o Sistema Completo
Para criar automaticamente uma pasta de testes contendo jogos simulados de PC (com `steam_api64.dll`, `CODEX`, `GOG`, tradução `GameVicio`), ROMs de consoles (`SNES` com `[T-Por]`, `GBA` em `.zip`, `GameCube` e `PS2` com cabeçalhos binários reais, `PS1` `.cue/.bin`, `PS3` `PS3_GAME`, duplicata SHA-256 e arquivo `.zip` corrompido) e gerar a planilha Excel:

```bash
python main.py ./demo_library --create-demo -o demo_inventario.xlsx
```
