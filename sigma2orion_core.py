#!/usr/bin/env python3
"""Logica compartida por sigma2orion.py (a demanda) y sigma2orion_service.py (servicio continuo)."""
import re, sys, json, urllib.request, os, time, random, socket, logging
from urllib.error import URLError, HTTPError
from datetime import datetime
import yaml

LOG_FILE = "sigma2orion.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("sigma2orion")

HTTP_TIMEOUT = 20  # segundos de espera antes de considerar timeout
HTTP_RETRIES = 3
HTTP_BACKOFF = 5  # segundos, se multiplica por el numero de intento


def load_dotenv(path=".env"):
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip())
    except FileNotFoundError:
        pass


load_dotenv()

VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
DOMAIN_SIGMA_FIELDS = {"DestinationHostname", "QueryName"}

try:
    CHECK_INTERVAL_MINUTES = float(os.environ.get("CHECK_INTERVAL_MINUTES", "60"))
except ValueError:
    CHECK_INTERVAL_MINUTES = 60
    log.warning("CHECK_INTERVAL_MINUTES invalido en .env, se usa el valor por defecto (60)")

ATOM_URL = "https://github.com/SigmaHQ/sigma/commits/master/rules/windows.atom"
API_COMMIT = "https://api.github.com/repos/SigmaHQ/sigma/commits/{sha}"
RAW_URL = "https://raw.githubusercontent.com/SigmaHQ/sigma/{sha}/{path}"
STATE_FILE = "last_sha.txt"
OUTPUT_FILE = "orion_rules.txt"
STATS_FILE = "rules_stats.jsonl"


def new_rule_id():
    return f"{random.randint(0, 99999999):08d}"


def append_output(text):
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(text + "\n")


def log_rule_stats(status, sha, path, name="", rule_id=""):
    # una linea JSON por regla procesada, para poder sacar estadisticas despues (ver stats.py)
    record = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": status,  # created | discarded_fp | no_orion_type | error
        "sha": sha,
        "path": path,
        "name": name,
        "rule_id": rule_id,
    }
    with open(STATS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

CATEGORY_TO_TYPE = {
    "process_creation": "ProcessOps",
    "registry_event": "RegistryOps",
    "registry_add": "RegistryOps",
    "registry_set": "RegistryOps",
    "network_connection": "NetworkOps",
    "dns_query": "DnsOps",
    "file_event": "SystemOps",
    "image_load": "ProcessOps",
    "create_remote_thread": "ProcessOps",
    "process_access": "ProcessOps",
}

FIELD_MAP = {
    "process_creation": {
        "Image": "ChildPath", "CommandLine": "CommandLine", "User": "LoggedUser",
        "ParentImage": "ParentPath", "ParentCommandLine": None, "OriginalFileName": None,
        "md5": "ChildMd5", "Hashes": "ChildMd5",
    },
    "registry_event": {
        "TargetObject": "Key", "Details": "ValueData", "NewName": "Value",
        "Image": "ParentPath", "User": "LoggedUser",
    },
    "network_connection": {
        "DestinationIp": "RemoteIp", "DestinationPort": "RemotePort",
        "DestinationHostname": "Hostname",
        "SourceIp": "LocalIp", "SourcePort": "LocalPort",
        "Image": "ParentPath", "User": "LoggedUser",
    },
    "dns_query": {
        "QueryName": "DomainList", "Image": "ParentPath", "User": "LoggedUser",
    },
    "file_event": {
        "TargetFilename": "ExtendedInfo", "Image": "ChildPath", "User": "LoggedUser",
    },
    "image_load": {
        "Image": "ParentPath", "ImageLoaded": "ChildPath", "User": "LoggedUser",
    },
}

MOD_TO_OP = {
    None: "equals", "contains": "containsAny", "startswith": "startsWithAny",
    "endswith": "endsWithAny", "re": "matches", "all": "containsAny (AND manual)",
}

LEVEL_TO_RISK = {
    "critical": "Critical", "high": "High Risk", "medium": "Medium Risk",
    "low": "Low Risk", "informational": "Unknown",
}


def mitre_from_tags(tags):
    ids = []
    for t in tags or []:
        m = re.match(r"attack\.(t\d+(?:\.\d+)?)$", t, re.IGNORECASE)
        if m:
            ids.append(m.group(1).upper())
    return ", ".join(ids)


def http_get(url, headers=None):
    last_exc = None
    for attempt in range(1, HTTP_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers=headers or {"User-Agent": "sigma2orion"})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
                return r.read()
        except (URLError, HTTPError, socket.timeout, ConnectionError) as exc:
            last_exc = exc
            log.warning(f"Fallo de red al pedir {url} (intento {attempt}/{HTTP_RETRIES}): {exc}")
            if attempt < HTTP_RETRIES:
                time.sleep(HTTP_BACKOFF * attempt)
    raise ConnectionError(f"No se pudo conectar a {url} tras {HTTP_RETRIES} intentos: {last_exc}")


def commit_shas():
    atom = http_get(ATOM_URL).decode("utf-8", "ignore")
    shas = re.findall(r'href="https://github\.com/SigmaHQ/sigma/commit/([a-f0-9]+)"', atom)
    if not shas:
        raise RuntimeError("no se encontro ningun commit en el atom feed")
    return shas  # orden: mas nuevo primero


def read_last_sha():
    try:
        with open(STATE_FILE) as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


def write_last_sha(sha):
    with open(STATE_FILE, "w") as f:
        f.write(sha)


def changed_windows_rules(sha):
    data = json.loads(http_get(API_COMMIT.format(sha=sha)))
    files = []
    for f in data.get("files", []):
        path = f["filename"]
        if f["status"] in ("added", "modified") and path.startswith("rules/windows") and path.endswith(".yml"):
            files.append(path)
    return files


def block_lines(block, fmap, vt_covered=frozenset(), context=""):
    lines = []
    for key, value in block.items():
        if "|" in key:
            field, modifier = key.split("|", 1)
        else:
            field, modifier = key, None
        orion_field = fmap.get(field)
        if orion_field is None:
            log.info(f"{context}campo sigma '{field}' sin equivalencia en Orion, se omite")
            continue  # sin mapeo -> se omite
        op = MOD_TO_OP.get(modifier, modifier or "equals")
        values = value if isinstance(value, list) else [value]
        for v in values:
            if field in DOMAIN_SIGMA_FIELDS:
                vclean = str(v).lstrip("*.").rstrip("*")
                if vclean.count(".") != 1:
                    log.info(f"{context}dominio '{v}' ignorado (el EDR solo matchea dominios de 2 labels)")
                    continue  # EDR solo matchea dominios de 2 labels (ej: monero.us, no monero.us.to)
                if vclean in vt_covered:
                    log.info(f"{context}dominio '{vclean}' omitido, ya bloqueado por Panda segun VT")
                    continue  # ya bloqueado por Panda segun VT
            lines.append(f"  {orion_field} ({op}) {v}")
    return lines


def expand_condition(condition, detection):
    def repl(m):
        quant, prefix = m.group(1), m.group(2)
        names = [n for n in detection if n != "condition" and n.startswith(prefix)]
        joiner = " and " if quant.lower() == "all" else " or "
        return "(" + joiner.join(names) + ")"
    return re.sub(r'(\d+|all) of ([\w_]+)\*', repl, condition)


def tokenize(condition):
    return re.findall(r'\(|\)|\bnot\b|\band\b|\bor\b|[\w_]+', condition, re.IGNORECASE)


def cleanup(lines):
    result = []
    for line in lines:
        if line in ("AND", "OR", "NOT"):
            if not result or result[-1] in ("AND", "OR", "NOT"):
                continue
        result.append(line)
    while result and result[-1] in ("AND", "OR", "NOT"):
        result.pop()
    return result


def render_condition(condition, detection, fmap, vt_covered=frozenset(), context=""):
    condition = expand_condition(condition, detection)
    out = []
    for tok in tokenize(condition):
        low = tok.lower()
        if low in ("and", "or", "not"):
            out.append(low.upper())
        elif tok in ("(", ")"):
            continue
        else:
            block = detection.get(tok)
            if block is None:
                log.info(f"{context}bloque de deteccion '{tok}' no encontrado, se ignora en la condicion")
                continue
            if isinstance(block, list):
                for i, sub in enumerate(block):
                    if i > 0:
                        out.append("OR")
                    out.extend(block_lines(sub, fmap, vt_covered, context))
            else:
                out.extend(block_lines(block, fmap, vt_covered, context))
    return cleanup(out)


def extract_domains(detection):
    domains = set()
    for name, block in detection.items():
        if name == "condition":
            continue
        blocks = block if isinstance(block, list) else [block]
        for b in blocks:
            if not isinstance(b, dict):
                continue
            for key, value in b.items():
                field = key.split("|", 1)[0]
                if field in DOMAIN_SIGMA_FIELDS:
                    values = value if isinstance(value, list) else [value]
                    for v in values:
                        v = str(v).lstrip("*.").rstrip("*")
                        if v.count(".") == 1:  # solo los que el EDR puede matchear
                            domains.add(v)
    return domains


def vt_panda_flags(domain):
    req = urllib.request.Request(
        VT_DOMAIN_URL.format(domain=domain),
        headers={"x-apikey": VT_API_KEY},
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            data = json.loads(r.read())
    except (URLError, HTTPError, socket.timeout, ConnectionError) as exc:
        log.warning(f"No se pudo consultar VirusTotal para el dominio '{domain}': {exc}")
        return None  # no se pudo consultar
    results = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
    panda = results.get("Panda")
    return panda is not None and panda.get("category") in ("malicious", "suspicious")


def vt_covered_domains(domains):
    if not VT_API_KEY or not domains:
        return set()
    covered = set()
    for i, d in enumerate(sorted(domains)):
        if i > 0:
            time.sleep(15)  # rate limit VT publico: 4 req/min
        if vt_panda_flags(d) is True:
            covered.add(d)
    return covered


FP_TRIVIAL = {"unknown", "unlikely", "none", "none known", "none expected", ""}


def fp_warning(rule):
    status = (rule.get("status") or "").lower()
    fps = [str(x).strip().lower() for x in (rule.get("falsepositives") or [])]
    real_fps = [x for x in fps if x not in FP_TRIVIAL]
    reasons = []
    if status in ("experimental", "test", "unsupported", "deprecated"):
        reasons.append(f"status={status}")
    if real_fps:
        reasons.append(f"falsepositives={'; '.join(real_fps)}")
    return reasons


def process_rule(path, sha):
    context = f"[{path}] "
    log.info(f"{context}iniciando procesamiento (commit {sha})")

    try:
        raw = http_get(RAW_URL.format(sha=sha, path=path)).decode("utf-8", "ignore")
    except ConnectionError as exc:
        log.error(f"{context}no se pudo descargar la regla, se omite: {exc}")
        log_rule_stats("error", sha, path)
        return

    rule = yaml.safe_load(raw)
    logsource = rule.get("logsource", {})
    category = logsource.get("category", "")
    orion_type = CATEGORY_TO_TYPE.get(category)
    fmap = FIELD_MAP.get(category, {})
    detection = rule.get("detection", {})
    condition = detection.get("condition", "")

    risk = LEVEL_TO_RISK.get((rule.get("level") or "").lower(), "Unknown")
    mitre = mitre_from_tags(rule.get("tags"))
    fp_reasons = fp_warning(rule)
    vt_covered = vt_covered_domains(extract_domains(detection))

    name = f"ARCustom{rule.get('title', '').replace(' ', '')}"
    rule_id = new_rule_id()
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if fp_reasons:
        log.info(f"{context}descartada por riesgo de falso positivo: {' | '.join(fp_reasons)}")
        block = []
        block.append("____________________________________\n")
        block.append(f"ID: {rule_id} | Generado: {generated_at}")
        block.append(f"[Fuente sigma: {path} | commit {sha}]")
        block.append(f"[!] Descartada, riesgo de FP: {' | '.join(fp_reasons)}")
        block.append("_____________________________________________________________\n")
        append_output("\n".join(block))
        log_rule_stats("discarded_fp", sha, path, name, rule_id)
        return

    out = []
    out.append("____________________________________\n")
    out.append(f"ID: {rule_id} | Generado: {generated_at}")
    out.append(f"Name: {name}")
    out.append(f"Description: {rule.get('description', '')}")
    out.append("Owner:Nic0 Echandi")
    out.append("Created by: nombre.apellido@empresa.com")
    out.append("Status")
    out.append(f"Risk : {risk}")
    out.append(f"MITRE ATT&CK {mitre}")
    out.append("Clients: 83xxxxxx (Nic0 Echandi)")
    out.append("83xxxxxx")
    out.append("Operating systems: Windows")
    out.append("Add this information to each generated signal: Columns (agregar todas)")
    out.append("")
    out.append(f"[Fuente sigma: {path} | commit {sha}]")
    out.append(f"Condition sigma original: {condition}")

    if not orion_type:
        log.info(f"{context}categoria sigma '{category}' sin Type equivalente en Orion")
        out.append("[!] Categoria sigma sin Type equivalente en Orion, no se puede cargar directo.")
        out.append("_____________________________________________________________\n")
        append_output("\n".join(out))
        log_rule_stats("no_orion_type", sha, path, name, rule_id)
        return

    out.append("")
    out.append(f"Type: {orion_type}")
    if vt_covered:
        out.append(f"[i] Omitidos (ya bloqueados por Panda segun VT): {', '.join(sorted(vt_covered))}")
    out.append("Datos de Condition:")
    out.extend(render_condition(condition, detection, fmap, vt_covered, context))
    out.append("")
    out.append("_____________________________________________________________\n")

    append_output("\n".join(out))
    log.info(f"{context}regla creada correctamente (ID {rule_id}, Type {orion_type})")
    log_rule_stats("created", sha, path, name, rule_id)


def run_once():
    try:
        shas = commit_shas()  # mas nuevo primero
    except (ConnectionError, RuntimeError) as exc:
        log.error(f"No se pudo obtener la lista de commits desde GitHub: {exc}")
        return

    last_sha = read_last_sha()

    if last_sha is None:
        pending = [shas[0]]  # primera corrida: solo el ultimo commit
        log.info("Primera corrida, no habia sha guardado.")
    elif last_sha in shas:
        idx = shas.index(last_sha)
        pending = list(reversed(shas[:idx]))  # nuevos, del mas viejo al mas nuevo
        if not pending:
            log.info("No hay commits nuevos desde la ultima corrida.")
            return
    else:
        pending = [shas[0]]  # last_sha muy viejo / fuera del feed
        log.info(f"Ultimo sha guardado ({last_sha}) no esta en el feed actual, tomo solo el ultimo commit.")

    for sha in pending:
        log.info(f"Procesando commit: {sha}")
        try:
            files = changed_windows_rules(sha)
        except ConnectionError as exc:
            log.error(f"No se pudo obtener los archivos del commit {sha}, se omite: {exc}")
            continue
        if not files:
            log.info("Este commit no modifico/agrego reglas .yml en rules/windows.")
            continue
        for path in files:
            try:
                process_rule(path, sha)
            except Exception as exc:
                log.error(f"Error inesperado procesando {path} (commit {sha}), se omite: {exc}")
                log_rule_stats("error", sha, path)

    write_last_sha(shas[0])
    log.info("Corrida finalizada.")
