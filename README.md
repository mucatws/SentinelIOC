# 🛡️ Sentinel IOC

> Blue Team Indicator of Compromise Detector  
> Extracts, classifies, and enriches IOCs from logs, reports, and raw text.

---

## 🌐 English

### What is an IOC Attack?

An **Indicator of Compromise (IOC)** is a piece of forensic evidence that suggests a system has been breached or is under attack. IOCs are artifacts left behind by attackers during or after an intrusion — they are the "fingerprints" of a cyberattack.

Common IOC types include:

| Type | Example | What it means |
|---|---|---|
| **IP Address** | `185.220.101.45` | Server used for C2 (command & control) or exfiltration |
| **Domain** | `update-microsoft.tk` | Phishing or malware delivery domain |
| **URL** | `http://evil.xyz/payload.exe` | Malware download endpoint |
| **File Hash (MD5/SHA1/SHA256)** | `d41d8cd98f00b204...` | Fingerprint of a malicious file |
| **CVE** | `CVE-2021-44228` | Known vulnerability being exploited (e.g. Log4Shell) |
| **Bitcoin Wallet** | `1A1zP1eP5QGefi2...` | Ransomware payment address |
| **Onion Address** | `facebookcore.onion` | Dark web C2 or data leak site |
| **Base64 Payload** | `cG93ZXJzaGVsbA==` | Encoded command trying to evade detection |
| **Registry Key** | `HKEY_RUN\malware` | Persistence mechanism in Windows |
| **Exec Command** | `powershell -enc ...` | Living-off-the-land execution technique |

Attackers use IOCs during every phase of an intrusion: initial access, lateral movement, persistence, and data exfiltration. **Sentinel IOC** helps defenders extract and triage these artifacts automatically from any text source.

---

### What does Sentinel IOC do?

- Extracts 15+ IOC types using optimized regex patterns
- Classifies severity: `CRITICAL`, `HIGH`, `MEDIUM`, `INFO`
- Detects suspicious TLDs, phishing keywords, C2 ports, and malicious file extensions
- Validates Base64 strings by actually decoding and inspecting content
- Deduplicates domains already covered by URLs or emails
- Optionally enriches external IPs via the **AbuseIPDB** API
- Exports a full structured JSON report
- Multithreaded extraction for performance on large files

---

### Requirements

- Python 3.10 or higher
- Optional: `colorama` (for Windows color support)
- Optional: AbuseIPDB API key (free at [abuseipdb.com](https://www.abuseipdb.com))

---

### Installation & Setup on Linux

```bash
# 1. Clone the repository
git clone https://github.com/youruser/sentinel-ioc.git
cd sentinel-ioc

# 2. (Optional) Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install optional dependency
pip install colorama

# 4. Make executable (optional)
chmod +x sentinel_ioc.py
```

---

### Installation & Setup on Windows

```powershell
# 1. Clone the repository
git clone https://github.com/youruser/sentinel-ioc.git
cd sentinel-ioc

# 2. (Optional) Create a virtual environment
python -m venv venv
venv\Scripts\activate

# 3. Install optional dependency
pip install colorama
```

> **Note:** Python 3.10+ is required. Download at [python.org](https://www.python.org/downloads/).  
> During installation, check **"Add Python to PATH"**.

---

### Usage

#### Basic — scan a file
```bash
python3 sentinel_ioc.py malware_report.txt
```

#### Scan raw text directly
```bash
python3 sentinel_ioc.py "attacker used 185.220.101.45 and domain evil-update.tk"
```

#### Export results to JSON
```bash
python3 sentinel_ioc.py report.txt --json
```

#### Enrich external IPs with AbuseIPDB
```bash
python3 sentinel_ioc.py report.txt --abuseipdb-key YOUR_API_KEY
```

#### Limit display per category (all still exported to JSON)
```bash
python3 sentinel_ioc.py large_log.txt --max-display 20 --json
```

#### Full example
```bash
python3 sentinel_ioc.py incident_report.txt --abuseipdb-key abc123 --json --max-display 30
```

---

### Output example

```
============================================================
 SENTINEL IOC - By leosec
============================================================
  Source : incident_report.txt
  Date   : 2024-11-15 14:32:01
  Total IOCs extracted: 12

  -- IPv4 (2) --
    * 192.168.1.10   [INTERNAL]
    * 185.220.101.45 [EXTERNAL] AbuseIPDB: 97% (312 reports)

  -- CVE (1) --
    * CVE-2021-44228  -> Check patch status

  -- URL (1) --
    * hxxp://evil[.]xyz/payload[.]exe  [CRITICAL] extension: .exe

  -- SEVERITY SUMMARY --
    CRITICAL: 4
    HIGH: 5
    MEDIUM: 2
    INFO: 1
============================================================
```

---

### JSON output structure

```json
{
  "source": "incident_report.txt",
  "extracted_at": "2024-11-15T14:32:01",
  "total_iocs": 12,
  "severity_summary": {
    "CRITICAL": 4,
    "HIGH": 5,
    "MEDIUM": 2
  },
  "iocs": {
    "IPv4": [
      {
        "indicator": "185.220.101.45",
        "defanged": "185[.]220[.]101[.]45",
        "scope": "EXTERNAL",
        "severity": "HIGH",
        "abuseipdb_score": 97,
        "abuseipdb_reports": 312
      }
    ]
  }
}
```

---

---

## 🇧🇷 Português

### O que é um ataque IOC?

Um **Indicador de Comprometimento (IOC)** é uma evidência forense que sugere que um sistema foi invadido ou está sob ataque. IOCs são rastros deixados por atacantes durante ou após uma intrusão — são as "impressões digitais" de um ciberataque.

Tipos comuns de IOC:

| Tipo | Exemplo | O que significa |
|---|---|---|
| **Endereço IP** | `185.220.101.45` | Servidor usado para C2 (comando e controle) ou exfiltração |
| **Domínio** | `update-microsoft.tk` | Domínio de phishing ou entrega de malware |
| **URL** | `http://evil.xyz/payload.exe` | Endpoint de download de malware |
| **Hash de arquivo (MD5/SHA1/SHA256)** | `d41d8cd98f00b204...` | Impressão digital de um arquivo malicioso |
| **CVE** | `CVE-2021-44228` | Vulnerabilidade conhecida sendo explorada (ex: Log4Shell) |
| **Carteira Bitcoin** | `1A1zP1eP5QGefi2...` | Endereço de pagamento de ransomware |
| **Endereço Onion** | `facebookcore.onion` | C2 na dark web ou site de vazamento de dados |
| **Payload Base64** | `cG93ZXJzaGVsbA==` | Comando codificado tentando evadir detecção |
| **Chave de Registro** | `HKEY_RUN\malware` | Mecanismo de persistência no Windows |
| **Comando de Execução** | `powershell -enc ...` | Técnica de execução "living-off-the-land" |

Atacantes usam IOCs em todas as fases de uma intrusão: acesso inicial, movimentação lateral, persistência e exfiltração de dados. O **Sentinel IOC** ajuda os defensores a extrair e triar esses artefatos automaticamente de qualquer fonte de texto.

---

### O que o Sentinel IOC faz?

- Extrai mais de 15 tipos de IOC com padrões regex otimizados
- Classifica severidade: `CRÍTICO`, `ALTO`, `MÉDIO`, `INFO`
- Detecta TLDs suspeitos, keywords de phishing, portas C2 e extensões de arquivo maliciosas
- Valida strings Base64 decodificando e inspecionando o conteúdo real
- Remove duplicatas de domínios já cobertos por URLs ou emails
- Enriquece IPs externos opcionalmente via API **AbuseIPDB**
- Exporta relatório JSON completo e estruturado
- Extração multithreaded para performance em arquivos grandes

---

### Requisitos

- Python 3.10 ou superior
- Opcional: `colorama` (suporte a cores no Windows)
- Opcional: chave de API do AbuseIPDB (gratuita em [abuseipdb.com](https://www.abuseipdb.com))

---

### Instalação no Linux

```bash
# 1. Clone o repositório
git clone https://github.com/youruser/sentinel-ioc.git
cd sentinel-ioc

# 2. (Opcional) Crie um ambiente virtual
python3 -m venv venv
source venv/bin/activate

# 3. Instale dependência opcional
pip install colorama

# 4. Torne executável (opcional)
chmod +x sentinel_ioc.py
```

---

### Instalação no Windows

```powershell
# 1. Clone o repositório
git clone https://github.com/youruser/sentinel-ioc.git
cd sentinel-ioc

# 2. (Opcional) Crie um ambiente virtual
python -m venv venv
venv\Scripts\activate

# 3. Instale dependência opcional
pip install colorama
```

> **Atenção:** Python 3.10+ é obrigatório. Baixe em [python.org](https://www.python.org/downloads/).  
> Durante a instalação, marque **"Add Python to PATH"**.

---

### Uso

#### Básico — escanear um arquivo
```bash
python3 sentinel_ioc.py relatorio_malware.txt
```

#### Escanear texto diretamente
```bash
python3 sentinel_ioc.py "atacante usou 185.220.101.45 e dominio evil-update.tk"
```

#### Exportar resultado para JSON
```bash
python3 sentinel_ioc.py relatorio.txt --json
```

#### Enriquecer IPs externos com AbuseIPDB
```bash
python3 sentinel_ioc.py relatorio.txt --abuseipdb-key SUA_CHAVE_API
```

#### Limitar exibição por categoria (todos ainda vão para o JSON)
```bash
python3 sentinel_ioc.py log_grande.txt --max-display 20 --json
```

#### Exemplo completo
```bash
python3 sentinel_ioc.py relatorio_incidente.txt --abuseipdb-key abc123 --json --max-display 30
```

---

### Licença

MIT — use, modifique e distribua livremente.  
MIT — free to use, modify, and distribute.
