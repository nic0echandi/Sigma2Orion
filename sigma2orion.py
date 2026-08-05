    #!/usr/bin/env python3
import re, sys, json, urllib.request, os, time, random
from datetime import datetime
import yaml


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

ATOM_URL = "https://github.com/SigmaHQ/sigma/commits/master/rules/windows.atom"
API_COMMIT = "https://api.github.com/repos/SigmaHQ/sigma/commits/{sha}"
RAW_URL = "https://raw.githubusercontent.com/SigmaHQ/sigma/{sha}/{path}"
STATE_FILE = "last_sha.txt"
OUTPUT_FILE = "orion_rules.txt"


def new_rule_id():
    return f"{random.randint(0, 99999999):08d}"


def append_output(text):
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(text + "\n")

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
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "sigma2orion"})
    with urllib.request.urlopen(req) as r:
        return r.read()


def commit_shas():
    atom = http_get(ATOM_URL).decode("utf-8", "ignore")
    shas = re.findall(r'href="https://github\.com/SigmaHQ/sigma/commit/([a-f0-9]+)"', atom)
    if not shas:
        sys.exit("no se encontro ningun commit en el atom feed")
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


def block_lines(block, fmap, vt_covered=frozenset()):
    lines = []
    for key, value in block.items():
        if "|" in key:
            field, modifier = key.split("|", 1)
        else:
            field, modifier = key, None
        orion_field = fmap.get(field)
        if orion_field is None:
            continue  # sin mapeo -> se omite
        op = MOD_TO_OP.get(modifier, modifier or "equals")
        values = value if isinstance(value, list) else [value]
        for v in values:
            if field in DOMAIN_SIGMA_FIELDS:
                vclean = str(v).lstrip("*.").rstrip("*")
                if vclean.count(".") != 1:
                    continue  # EDR solo matchea dominios de 2 labels (ej: monero.us, no monero.us.to)
                if vclean in vt_covered:
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


def render_condition(condition, detection, fmap, vt_covered=frozenset()):
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
                continue
            if isinstance(block, list):
                for i, sub in enumerate(block):
                    if i > 0:
                        out.append("OR")
                    out.extend(block_lines(sub, fmap, vt_covered))
            else:
                out.extend(block_lines(block, fmap, vt_covered))
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
        with urllib.request.urlopen(req) as r:
            data = json.loads(r.read())
    except Exception:
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
    raw = http_get(RAW_URL.format(sha=sha, path=path)).decode("utf-8", "ignore")
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
        block = []
        block.append("____________________________________\n")
        block.append(f"ID: {rule_id} | Generado: {generated_at}")
        block.append(f"[Fuente sigma: {path} | commit {sha}]")
        block.append(f"[!] Descartada, riesgo de FP: {' | '.join(fp_reasons)}")
        block.append("_____________________________________________________________\n")
        append_output("\n".join(block))
        return

    out = []
    out.append("____________________________________\n")
    out.append(f"ID: {rule_id} | Generado: {generated_at}")
    out.append(f"Name: {name}")
    out.append(f"Description: {rule.get('description', '')}")
    out.append("Owner:Telefónica Móviles Argentina")
    out.append("Created by: nombre.apellido@Tmoviles.com.ar")
    out.append("Status")
    out.append(f"Risk : {risk}")
    out.append(f"MITRE ATT&CK {mitre}")
    out.append("Clients: 83022506 (Telefónica Móviles Argentina)")
    out.append("83022506")
    out.append("Operating systems: Windows")
    out.append("Add this information to each generated signal: Columns (agregar todas)")
    out.append("")
    out.append(f"[Fuente sigma: {path} | commit {sha}]")
    out.append(f"Condition sigma original: {condition}")

    if not orion_type:
        out.append("[!] Categoria sigma sin Type equivalente en Orion, no se puede cargar directo.")
        out.append("_____________________________________________________________\n")
        append_output("\n".join(out))
        return

    out.append("")
    out.append(f"Type: {orion_type}")
    if vt_covered:
        out.append(f"[i] Omitidos (ya bloqueados por Panda segun VT): {', '.join(sorted(vt_covered))}")
    out.append("Datos de Condition:")
    out.extend(render_condition(condition, detection, fmap, vt_covered))
    out.append("")
    out.append("_____________________________________________________________\n")

    append_output("\n".join(out))


def main():
    shas = commit_shas()  # mas nuevo primero
    last_sha = read_last_sha()

    if last_sha is None:
        pending = [shas[0]]  # primera corrida: solo el ultimo commit
        print("Primera corrida, no habia sha guardado.\n")
    elif last_sha in shas:
        idx = shas.index(last_sha)
        pending = list(reversed(shas[:idx]))  # nuevos, del mas viejo al mas nuevo
        if not pending:
            print("No hay commits nuevos desde la ultima corrida.")
            return
    else:
        pending = [shas[0]]  # last_sha muy viejo / fuera del feed
        print(f"Ultimo sha guardado ({last_sha}) no esta en el feed actual, tomo solo el ultimo commit.\n")

    for sha in pending:
        print(f"Procesando commit: {sha}\n")
        files = changed_windows_rules(sha)
        if not files:
            print("Este commit no modifico/agrego reglas .yml en rules/windows.\n")
            continue
        for path in files:
            process_rule(path, sha)

    write_last_sha(shas[0])


if __name__ == "__main__":
    main()