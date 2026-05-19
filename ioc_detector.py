import re
import sys
import json
import time
import base64
import ipaddress
import argparse
import urllib.request
import urllib.parse
import urllib.error
 
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
 
# =========================================================
# COLOR SUPPORT
# =========================================================
 
try:
    from colorama import init
    init()
except ImportError:
    pass
 
COLORS = {
    "CRÍTICO": "\033[91m",
    "ALTO":    "\033[93m",
    "MÉDIO":   "\033[96m",
    "OK":      "\033[92m",
    "INFO":    "\033[94m",
    "RESET":   "\033[0m",
    "BOLD":    "\033[1m",
    "DIM":     "\033[2m",
}
 
def c(text, col):
    return f"{COLORS.get(col,'')}{text}{COLORS['RESET']}"
 
# =========================================================
# IOC PATTERNS
# =========================================================
 
PATTERNS = {
 
    "IPv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
 
    # FIX: IPv6 restaurado com regex correta (sem \b apos ":")
    "IPv6": re.compile(
        r'(?<![:\w])'
        r'(?:'
        r'[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7}'
        r'|(?:[0-9a-fA-F]{1,4}:){1,7}:'
        r'|:(?::[0-9a-fA-F]{1,4}){1,7}'
        r'|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'
        r')'
        r'(?![:\w])'
    ),
 
    "URL": re.compile(
        r'https?://[^\s\'"<>]+[^\s\'"<>.,;:]',
        re.IGNORECASE
    ),
 
    "Domain": re.compile(
        r'\b(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z]{2,}\b',
        re.IGNORECASE
    ),
 
    "Email": re.compile(
        r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
    ),
 
    "MD5": re.compile(
        r'(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])'
    ),
 
    "SHA1": re.compile(
        r'(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])'
    ),
 
    "SHA256": re.compile(
        r'(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])'
    ),
 
    "CVE": re.compile(
        r'\bCVE-\d{4}-\d{4,7}\b',
        re.IGNORECASE
    ),
 
    "BTC_Wallet": re.compile(
        r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
        r'|bc1[a-z0-9]{39,59}\b'
    ),
 
    "Registry_Key": re.compile(
        r'HKEY_[A-Z_]+\\[^\s"\']+',
        re.IGNORECASE
    ),
 
    "File_Path_Win": re.compile(
        r'[Cc]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*'
        r'[^\\\/:*?"<>|\r\n]*'
    ),
 
    "Base64_Suspect": re.compile(
        r'\b(?:[A-Za-z0-9+/]{40,}={0,2})\b'
    ),
 
    "Onion": re.compile(
        r'\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b',
        re.IGNORECASE
    ),
 
    "Mutex": re.compile(
        r'(?:mutex|mutant)[_\-\s]?[a-zA-Z0-9_\-]{4,}',
        re.IGNORECASE
    ),
 
    "Suspicious_UA": re.compile(
        r'User-Agent:\s*[^\r\n]*'
        r'(?:python-requests|curl|wget|libwww|zgrab|masscan|'
        r'nmap|nuclei|dirbuster|sqlmap|hydra|nikto)',
        re.IGNORECASE
    ),
 
    "Exec_Command": re.compile(
        r'(?:powershell(?:\.exe)?)\s+[^\r\n]*'
        r'(?:-[eE][nN][cC]|'
        r'-[eE][nN][cC][oO][dD][eE][dD][cC][oO][mM][mM][aA][nN][dD])[^\r\n]*'
        r'|(?:cmd(?:\.exe)?)\s+/[cCkK]\s+[^\r\n]+'
        r'|(?:wscript|cscript|mshta)(?:\.exe)?\s+[^\r\n]+',
        re.IGNORECASE
    ),
}
 
# =========================================================
# NETWORK RANGES
# =========================================================
 
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]
 
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf",
    ".gq", ".xyz", ".top",
    ".pw", ".cc", ".su",
    ".zip", ".mov"
}
 
SUSPICIOUS_KEYWORDS = {
    "domain": [
        "update", "secure", "login",
        "verify", "account", "paypal",
        "microsoft", "google", "amazon",
        "bank", "support", "service",
        "cdn", "api", "auth"
    ],
    "url": [
        "download", "payload", "dropper",
        "shell", "cmd", "exec",
        "base64", "reverse", "meterpreter",
        "beacon", "c2", "rat", "bot"
    ]
}
 
SUSPICIOUS_PORTS = {
    4444, 1337, 31337,
    6666, 8888, 9999,
    12345, 54321
}
 
MALICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bat",
    ".vbs", ".ps1", ".scr",
    ".pif", ".jar", ".hta",
    ".msi"
}
 
# =========================================================
# HELPERS
# =========================================================
 
def defang(indicator: str) -> str:
    result = re.sub(
        r'https?://',
        'hxxp[://]',
        indicator,
        flags=re.IGNORECASE
    )
    result = re.sub(r'(?<!\[)\.(?!\])', '[.]', result)
    return result
 
 
def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_RANGES)
    except ValueError:
        return False
 
 
def classify_ip(ip_str: str) -> tuple:
    if is_private_ip(ip_str):
        return "INTERNO", "OK"
    return "EXTERNO", "ALTO"
 
 
def classify_domain(domain: str) -> tuple:
    domain_lower = domain.lower()
    tld = "." + domain_lower.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        return "ALTO", f"TLD suspeito {tld}"
    for kw in SUSPICIOUS_KEYWORDS["domain"]:
        if kw in domain_lower:
            return "MÉDIO", f"Keyword suspeita: '{kw}'"
    return "INFO", "Dominio detectado"
 
 
def is_suspicious_base64(s: str) -> tuple[bool, str]:
    padded = s + "=" * (-len(s) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except Exception:
        return False, "decode falhou"
 
    if not decoded:
        return False, "conteudo vazio"
 
    printable_ratio = sum(32 <= b < 127 for b in decoded) / len(decoded)
 
    if printable_ratio > 0.85:
        text = decoded.decode("latin-1", errors="replace").lower()
        suspicious_words = [
            "powershell", "cmd", "exec", "download",
            "http", "base64", "invoke", "iex",
            "wget", "curl", "payload", "shell",
            "/bin/", "reverse", "meterpreter", "dropper"
        ]
        for w in suspicious_words:
            if w in text:
                return True, f"contem '{w}' decodificado"
        return False, "conteudo imprimivel sem keywords"
 
    if len(decoded) >= 30:
        return True, "possivel shellcode/binario"
 
    return False, "conteudo insuficiente"
 
 
# FIX: porta extraida via urlparse, nao regex na string bruta
def check_url_port(url: str) -> str | None:
    try:
        port = urllib.parse.urlparse(url).port
        if port and port in SUSPICIOUS_PORTS:
            return str(port)
    except Exception:
        pass
    return None
 
 
def check_malicious_extension(path: str) -> str | None:
    ext = Path(path).suffix.lower()
    return ext if ext in MALICIOUS_EXTENSIONS else None
 
# =========================================================
# ABUSEIPDB
# =========================================================
 
# FIX: rate limiting restaurado (0.5s entre chamadas)
def check_abuseipdb(ip: str, api_key: str, delay: float = 0.5) -> dict:
    url = (
        "https://api.abuseipdb.com/api/v2/check"
        f"?ipAddress={urllib.parse.quote(ip)}"
        "&maxAgeInDays=90"
    )
    req = urllib.request.Request(
        url,
        headers={"Key": api_key, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
            time.sleep(delay)
            return data.get("data", {})
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}"}
    except urllib.error.URLError as e:
        return {"error": f"URL Error: {e.reason}"}
    except Exception as e:
        return {"error": str(e)}
 
# =========================================================
# MULTITHREADED EXTRACTION
# =========================================================
 
def process_pattern(args):
    ioc_type, pattern, text = args
    found = set()
    for match in pattern.findall(text):
        if isinstance(match, tuple):
            match = match[0]
        if match:
            found.add(match.strip())
    return ioc_type, found
 
 
def extract_iocs(text: str) -> dict:
    iocs = defaultdict(set)
 
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = [
            executor.submit(process_pattern, (ioc_type, pattern, text))
            for ioc_type, pattern in PATTERNS.items()
        ]
        for future in as_completed(futures):
            ioc_type, found = future.result()
            iocs[ioc_type].update(found)
 
    # FILTER BASE64
    if "Base64_Suspect" in iocs:
        filtered = {v for v in iocs["Base64_Suspect"] if is_suspicious_base64(v)[0]}
        if filtered:
            iocs["Base64_Suspect"] = filtered
        else:
            del iocs["Base64_Suspect"]
 
    # REMOVE EMAIL DOMAIN DUPLICATES
    if "Email" in iocs and "Domain" in iocs:
        email_domains = {e.split("@")[1].lower() for e in iocs["Email"]}
        iocs["Domain"] = {d for d in iocs["Domain"] if d.lower() not in email_domains}
 
    # REMOVE URL DOMAIN DUPLICATES
    if "URL" in iocs and "Domain" in iocs:
        url_domains = set()
        for url in iocs["URL"]:
            try:
                parsed = urllib.parse.urlparse(url)
                if parsed.hostname:
                    url_domains.add(parsed.hostname.lower())
            except Exception:
                pass
        iocs["Domain"] = {d for d in iocs["Domain"] if d.lower() not in url_domains}
 
    if "Domain" in iocs and not iocs["Domain"]:
        del iocs["Domain"]
 
    return {k: sorted(v) for k, v in iocs.items()}
 
# =========================================================
# IOC ANALYSIS
# =========================================================
 
def analyze_iocs(
    source: str,
    abuseipdb_key: str = None,
    export_json: bool = False,
    max_display: int = 50
):
    try:
        is_file = len(source) < 260 and Path(source).exists()
    except Exception:
        is_file = False
 
    if is_file:
        text = Path(source).read_text(errors="replace")
        source_label = Path(source).name
    else:
        text = source
        source_label = "stdin/texto"
 
    print(c(f"\n{'='*60}", "BOLD"))
    print(c(" SENTINEL IOC - By leosec", "BOLD"))
    print(c(f"{'='*60}", "BOLD"))
    print(f"  Fonte : {c(source_label, 'INFO')}")
    print(f"  Data  : {c(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'DIM')}")
 
    iocs = extract_iocs(text)
    total = sum(len(v) for v in iocs.values())
    print(f"  Total de IOCs extraidos: {c(str(total), 'ALTO')}\n")
 
    if total == 0:
        print(c("  Nenhum IOC encontrado.\n", "OK"))
        return {}
 
    report = {}
 
    for ioc_type, values in iocs.items():
 
        if not values:
            continue
 
        print(c(f"  -- {ioc_type} ({len(values)}) --", "BOLD"))
        report[ioc_type] = []
 
        for idx, val in enumerate(values):
 
            display = idx < max_display
            meta = {}
 
            # --------------------------------------------------
            if ioc_type == "IPv4":
 
                scope, sev = classify_ip(val)
                meta = {"scope": scope, "severity": sev}
                note = f"[{c(scope, sev)}]"
 
                if abuseipdb_key and scope == "EXTERNO":
                    abuse = check_abuseipdb(val, abuseipdb_key)
                    score = abuse.get("abuseConfidenceScore", 0)
                    reports_count = abuse.get("totalReports", 0)
                    if score > 0:
                        note += (
                            f" AbuseIPDB: "
                            f"{c(str(score)+'%', 'CRITICO' if score > 50 else 'ALTO')}"
                            f" ({reports_count} reports)"
                        )
                        meta["abuseipdb_score"] = score
                        meta["abuseipdb_reports"] = reports_count
                    if "error" in abuse:
                        meta["abuseipdb_error"] = abuse["error"]
 
                if display:
                    print(f"    {c('*', 'ALTO')} {c(defang(val), 'DIM')}  {note}")
 
            # --------------------------------------------------
            elif ioc_type == "IPv6":
 
                meta = {"severity": "INFO"}
                if display:
                    print(f"    {c('*', 'INFO')} {c(val, 'DIM')}  [IPv6 detectado]")
 
            # --------------------------------------------------
            elif ioc_type == "Domain":
 
                sev, reason = classify_domain(val)
                meta = {"severity": sev, "reason": reason}
 
                if display:
                    print(
                        f"    {c('*', 'ALTO')} {c(defang(val), 'DIM')} "
                        f"[{c(sev, sev)}] {reason}"
                    )
 
            # --------------------------------------------------
            elif ioc_type == "URL":
 
                low = val.lower()
                sev = (
                    "CRITICO"
                    if any(kw in low for kw in SUSPICIOUS_KEYWORDS["url"])
                    else "MEDIO"
                )
                extra = ""
 
                # FIX: porta via urlparse; campos salvos no meta
                port = check_url_port(val)
                if port:
                    sev = "CRITICO"
                    meta["suspicious_port"] = port
                    extra += f" porta C2: {c(port, 'CRITICO')}"
 
                ext = check_malicious_extension(urllib.parse.urlparse(val).path)
                if ext:
                    meta["malicious_extension"] = ext
                    extra += f" extensao: {c(ext, 'ALTO')}"
 
                meta["severity"] = sev
 
                if display:
                    print(
                        f"    {c('*', 'ALTO')} {c(defang(val), 'DIM')} "
                        f"[{c(sev, sev)}]{extra}"
                    )
 
            # --------------------------------------------------
            elif ioc_type == "CVE":
 
                meta = {"severity": "CRITICO"}
                if display:
                    print(f"    {c('*', 'CRITICO')} {c(val, 'CRITICO')}  -> Verificar patch status")
 
            # --------------------------------------------------
            elif ioc_type == "BTC_Wallet":
 
                meta = {"severity": "CRITICO"}
                if display:
                    print(f"    {c('*', 'CRITICO')} {c(val, 'ALTO')}  -> Possivel ransomware/extorsao")
 
            # --------------------------------------------------
            elif ioc_type == "Onion":
 
                meta = {"severity": "CRITICO"}
                if display:
                    print(f"    {c('*', 'CRITICO')} {c(val, 'CRITICO')}  -> Endereco Tor (Dark Web)")
 
            # --------------------------------------------------
            elif ioc_type == "Base64_Suspect":
 
                _, reason = is_suspicious_base64(val)
                meta = {"severity": "ALTO", "decode_reason": reason}
                if display:
                    print(f"    {c('*', 'ALTO')} {c(val[:40]+'...', 'DIM')}  -> {reason}")
 
            # --------------------------------------------------
            elif ioc_type == "File_Path_Win":
 
                ext = check_malicious_extension(val)
                sev = "ALTO" if ext else "MEDIO"
                meta = {"severity": sev}
                if ext:
                    meta["malicious_extension"] = ext
                if display:
                    note = f" extensao maliciosa: {c(ext, 'ALTO')}" if ext else ""
                    print(f"    {c('*', sev)} {c(val, 'DIM')}{note}")
 
            # --------------------------------------------------
            elif ioc_type == "Exec_Command":
 
                meta = {"severity": "CRITICO"}
                if display:
                    print(f"    {c('*', 'CRITICO')} {c(val[:80]+'...', 'DIM')}  -> Comando de execucao suspeito")
 
            # --------------------------------------------------
            elif ioc_type == "Suspicious_UA":
 
                meta = {"severity": "ALTO"}
                if display:
                    print(f"    {c('*', 'ALTO')} {c(val, 'DIM')}  -> User-Agent de ferramenta de ataque")
 
            # --------------------------------------------------
            else:
                # Registry_Key, Mutex, Email, MD5, SHA1, SHA256
                meta = {"severity": "MEDIO"}
                if display:
                    print(f"    {c('*', 'MEDIO')} {c(val, 'DIM')}")
 
            report[ioc_type].append({
                "indicator": val,
                "defanged": defang(val),
                **meta
            })
 
        if len(values) > max_display:
            print(c(f"    ... e mais {len(values) - max_display} indicadores (incluidos no JSON).", "DIM"))
 
        print()
 
    # RESUMO
    print(c("  -- RESUMO DE SEVERIDADE --", "BOLD"))
 
    sev_count: dict = defaultdict(int)
    for items in report.values():
        for item in items:
            sev_count[item.get("severity", "INFO")] += 1
 
    for sev in ["CRITICO", "ALTO", "MEDIO", "INFO", "OK"]:
        if sev_count[sev]:
            print(f"    {c(sev, sev)}: {sev_count[sev]}")
 
    print()
 
    if export_json:
        out = (
            Path(source_label).with_suffix(".iocs.json")
            if is_file else
            Path("iocs_output.json")
        )
        with open(out, "w", encoding="utf-8") as jf:
            json.dump(
                {
                    "source": source_label,
                    "extracted_at": datetime.now().isoformat(),
                    "total_iocs": total,
                    "severity_summary": dict(sev_count),
                    "iocs": report,
                },
                jf,
                indent=2,
                ensure_ascii=False,
                sort_keys=True
            )
        print(c(f"  IOCs exportados para: {out}", "OK"))
 
    print(c(f"{'='*60}\n", "BOLD"))
    return report
 
# =========================================================
# MAIN
# =========================================================
 
def main():
 
    parser = argparse.ArgumentParser(
        description="Sentinel IOC - Blue Team Indicator of Compromise Detector"
    )
    parser.add_argument(
        "source",
        help="Arquivo ou texto contendo IOCs"
    )
    parser.add_argument(
        "--abuseipdb-key",
        help="API Key AbuseIPDB"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Exporta JSON"
    )
    parser.add_argument(
        "--max-display",
        type=int,
        default=50,
        help="Maximo exibido por categoria (padrao: 50). Todos vao para o JSON."
    )
 
    args = parser.parse_args()
 
    analyze_iocs(
        args.source,
        abuseipdb_key=args.abuseipdb_key,
        export_json=args.json,
        max_display=args.max_display
    )
 
if __name__ == "__main__":
    main()
