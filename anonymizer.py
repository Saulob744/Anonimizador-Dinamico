import os, re, random, string, unicodedata, hashlib, logging, requests, html, hmac, secrets, json, time, threading
from datetime import datetime
from collections import Counter
from functools import lru_cache
from faker import Faker
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

MAX_CACHE_SIZE = 50000

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(funcName)s]: %(message)s')
logger = logging.getLogger(__name__)

SECRET_SALT = os.getenv("ANONYMIZER_SECRET_SALT", "SaltSeguroSESP2026_Producao!")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
ABORT_FILE = "abort.flag"

# Telemetria Global e Auditoria
_TELEMETRIA_LOCK = threading.Lock()

def _novo_estado_telemetria():
    return {
        "t0": time.time(),
        "inicio_iso": datetime.now().isoformat(),
        "celulas_avaliadas": 0, 
        "celulas_alteradas": 0, 
        "substituicoes_totais": 0, 
        "identidades_protegidas": set(), 
        "documentos_protegidos": set(),
        "amostras_auditoria": [],
        "contadores": {
            "PESSOAS": {"total": 0, "unicos": set(), "label": "👤 Pessoas / Nomes"},
            "CPFS": {"total": 0, "unicos": set(), "label": "🪪 CPFs"},
            "RGS": {"total": 0, "unicos": set(), "label": "📄 RGs"},
            "TELEFONES": {"total": 0, "unicos": set(), "label": "📞 Telefones"},
            "EMAILS": {"total": 0, "unicos": set(), "label": "✉️ E-mails"},
            "CEPS": {"total": 0, "unicos": set(), "label": "📮 CEPs"},
            "PLACAS": {"total": 0, "unicos": set(), "label": "🚗 Placas"},
            "CHASSIS": {"total": 0, "unicos": set(), "label": "⚙️ Chassis"},
            "IPS": {"total": 0, "unicos": set(), "label": "💻 Endereços IP"},
            "COORDENADAS": {"total": 0, "unicos": set(), "label": "📍 Coordenadas Geográficas"},
            "CODIGOS_GENERICOS": {"total": 0, "unicos": set(), "label": "🔢 Códigos / Identificadores"},
            "OUTROS": {"total": 0, "unicos": set(), "label": "🛡️ Outros Dados Sensíveis"}
        }
    }

_TELEMETRIA = _novo_estado_telemetria()

CATEGORIA_MAP = {
    "PER": "PESSOAS",
    "NOME_SOLTO": "PESSOAS",
    "CPF": "CPFS",
    "RG": "RGS",
    "PHONE": "TELEFONES",
    "EMAIL": "EMAILS",
    "CEP": "CEPS",
    "PLATE": "PLACAS",
    "PLACA": "PLACAS",
    "CHASSI": "CHASSIS",
    "IP": "IPS",
    "COORD": "COORDENADAS",
    "COORD_SINGLE": "COORDENADAS",
    "GENERIC_CODE": "CODIGOS_GENERICOS"
}

def _mascarar_amostra(texto: str) -> str:
    s = str(texto).strip()
    if len(s) <= 4: return "****"
    return f"{s[:2]}***{s[-2:]}"

_COLUMN_POLICIES, _OLLAMA_CACHE = {}, {}
fake = Faker("pt_BR")

try:
    import spacy
    nlp = spacy.load("pt_core_news_lg", disable=["lemmatizer"])
except Exception as e:
    logger.error(f"🚨 Erro no SpaCy: {e}")
    nlp = None

http_session = requests.Session()
http_session.mount("http://", HTTPAdapter(max_retries=Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])))

def _resolve_model_name():
    target = os.getenv("OLLAMA_MODEL", "llama3.2:1b")
    try:
        base_url = OLLAMA_URL.rsplit('/', 1)[0] if '/api/' in OLLAMA_URL else OLLAMA_URL
        tags_url = f"{base_url}/tags"
        resp = http_session.get(tags_url, timeout=2)
        if resp.status_code == 200:
            models = [m.get("name", "") for m in resp.json().get("models", [])]
            if any(target in m for m in models):
                return target
            if models:
                first_model = models[0]
                logger.info(f"💡 Modelo alvo '{target}' não instalado no Ollama. Utilizando modelo disponível: '{first_model}'")
                return first_model
    except Exception:
        pass
    return target

OLLAMA_MODEL = _resolve_model_name()

REGEX = {
    "CPF": re.compile(r"(?<!\d)(?:\d[-.\s_/*]{0,4}){10}\d(?!\d)"),
    "IP": re.compile(r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)"),
    "CEP": re.compile(r"(?<!\d)\d{5}[-\s]?\d{3}(?!\d)"), 
    "DATE_TIME": re.compile(r"(?<!\d)(?:(?:3[01]|[12]\d|0?[1-9])[/.-](?:1[0-2]|0?[1-9])[/.-](?:19|20)?\d\d|(?:19|20)\d\d[/.-](?:1[0-2]|0?[1-9])[/.-](?:3[01]|[12]\d|0?[1-9]))(?:[\s_T]+\d{1,2}:\d{2}(?::\d{2})?)?(?!\d)", re.I),    
    "RG": re.compile(r"(?<!\d)(?:\d[-.\s_/*]{0,4}){4,13}[0-9Xx](?!\d)"), 
    "EMAIL": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "PLATE": re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{3}[-.\s]*[0-9][A-Za-z0-9][0-9]{2}(?![A-Za-z0-9])", re.I),
    "PHONE": re.compile(r"(?<!\d)(?:\+?55[-.\s_]*)?(?:\(?[0]?\d{2}\)?[-.\s_]*)?(?:9[-.\s_]*)?\d{4,5}[-.\s_]*\d{4}(?!\d)"),
    "CHASSI": re.compile(r"(?<![A-Za-z0-9])[A-HJ-NPR-Z0-9]{17}(?![A-Za-z0-9])", re.I), 
    "COORD": re.compile(r"(?<!\d)-?\d{1,3}[.,]\d{3,}[^A-Za-z0-9]+-?\d{1,3}[.,]\d{3,}(?!\d)"), 
    "COORD_SINGLE": re.compile(r"(?<!\d)-?\d{1,3}[.,]\d{3,}(?!\d)"),
    "GENERIC_CODE": re.compile(r"(?<!\w)(?=[A-Za-z0-9-_./]*\d)(?:[A-Za-z0-9]{1,10}[-/_.]){1,5}[A-Za-z0-9]{1,10}(?!\w)|(?<!\w)[A-Za-z]+\d+[A-Za-z0-9]*(?!\w)")
}

_TITULOS_BASE = r"\b(?:[Cc]abo|[Ss]oldado|[Ss]argento|[Tt]enente|[Cc]apita[oõ]|[Cc]oronel|[Dd]elegado|[Ii]nvestigador|[Aa]gente|[Ee]scriv[aã]o|[Dd]r|[Dd]ra|[Ss]r|[Ss]ra|[Ss]enhor|[Ss]enhora|[Vv][ií]tima|[Ss]uspeito|[Aa]utor|[Ii]ndiv[ií]duo|[Pp]aciente)\b\.?"
TITLES_TO_STRIP = re.compile(_TITULOS_BASE, re.I)
TITLE_NAME_REGEX = re.compile(f"{_TITULOS_BASE}\\s+([A-ZÀ-Ÿ][a-zà-ÿ]{{1,}}(?:\\s+(?:de|da|do|dos|das|e)\\s+)?(?:[A-ZÀ-Ÿ][a-zà-ÿ]{{1,}}\\s*){{1,4}})")
STOP_WORDS_NAME = re.compile(r"\b(portadora|portador|portadores|portadoras|cpf|rg|chassi|placa|email|telefone|veiculo|celular|residencia|guarnicao|denuncia|abordagem|local|propriedade|processo|relato|inquisitorial|rua|avenida|alameda|ch[aá]cara|fazenda|s[ií]tio|trecho|vereda|rodovia|travessa|beco|pra[cç]a|santa|santo|s[aã]o|hospital|cl[ií]nica|delegacia|batalh[aã]o|estado|munic[ií]pio|cidade|goi[aá]s|paran[aá]|paulo|janeiro)\b", re.I)
FEMALE_INDICATORS = re.compile(r"\b(dra|sra|senhora|dona|vítima|vitima)\b", re.I)

def _sanitize_input(text: str) -> str: return re.sub(r'[^\w\s\.,;:!?@\-\(\)]', ' ', str(text)).strip()
def _check_abort(): return os.path.exists(ABORT_FILE)
def _clean_name(name_str: str) -> str: return re.sub(r"^[,.:\-]+|[,.:\-]+$", "", TITLES_TO_STRIP.sub("", name_str)).strip()

def _registrar_captura(typ: str, original_val: str, fake_val: str):
    cat = CATEGORIA_MAP.get(str(typ).upper(), "OUTROS")
    norm_val = _normalize(str(original_val))
    
    with _TELEMETRIA_LOCK:
        if cat in _TELEMETRIA["contadores"]:
            _TELEMETRIA["contadores"][cat]["total"] += 1
            _TELEMETRIA["contadores"][cat]["unicos"].add(norm_val)
        
        if cat == "PESSOAS":
            _TELEMETRIA["identidades_protegidas"].add(norm_val)
        else:
            _TELEMETRIA["documentos_protegidos"].add(norm_val)
            
        if len(_TELEMETRIA["amostras_auditoria"]) < 100:
            _TELEMETRIA["amostras_auditoria"].append({
                "categoria": cat,
                "original_mascarado": _mascarar_amostra(original_val),
                "substituto_gerado": fake_val
            })

def resetar_telemetria():
    global _TELEMETRIA
    with _TELEMETRIA_LOCK:
        _TELEMETRIA = _novo_estado_telemetria()

def gerar_relatorio_performance(salvar_arquivo=True, contexto="Geral", pasta_saida="relatorios") -> dict:
    with _TELEMETRIA_LOCK:
        fim_tempo = time.time()
        tempo_total = max(fim_tempo - _TELEMETRIA["t0"], 0.001)
        avaliadas = _TELEMETRIA["celulas_avaliadas"]
        alteradas = _TELEMETRIA["celulas_alteradas"]
        trocas = _TELEMETRIA["substituicoes_totais"]
        
        itens_por_seg = round(avaliadas / tempo_total, 1)
        trocas_por_seg = round(trocas / tempo_total, 1)
        taxa_sensibilidade = round((alteradas / max(avaliadas, 1)) * 100, 2)
        
        contadores_resumo = {}
        for cat, dados in _TELEMETRIA["contadores"].items():
            if dados["total"] > 0:
                contadores_resumo[cat] = {
                    "label": dados.get("label", cat),
                    "total_capturado": dados["total"],
                    "unicos_distintos": len(dados["unicos"])
                }
        
        total_pessoas = contadores_resumo.get("PESSOAS", {}).get("total_capturado", 0)
        total_pessoas_unicas = contadores_resumo.get("PESSOAS", {}).get("unicos_distintos", 0)
        total_cpfs = contadores_resumo.get("CPFS", {}).get("total_capturado", 0)
        total_cpfs_unicos = contadores_resumo.get("CPFS", {}).get("unicos_distintos", 0)
        
        tempo_formatado = f"{int(tempo_total // 60)}m {int(tempo_total % 60):02d}s" if tempo_total >= 60 else f"{tempo_total:.2f}s"
        
        relatorio = {
            "metadados": {
                "data_hora_inicio": _TELEMETRIA["inicio_iso"],
                "data_hora_fim": datetime.now().isoformat(),
                "tempo_total_segundos": round(tempo_total, 2),
                "tempo_formatado": tempo_formatado,
                "modelo_ia": OLLAMA_MODEL,
                "contexto": contexto
            },
            "metricas_performance": {
                "itens_avaliados": avaliadas,
                "itens_alterados": alteradas,
                "substituicoes_totais": trocas,
                "itens_por_segundo": itens_por_seg,
                "substituicoes_por_segundo": trocas_por_seg,
                "taxa_sensibilidade_pct": taxa_sensibilidade
            },
            "resumo_rapido": {
                "total_pessoas_protegidas": total_pessoas,
                "pessoas_unicas": total_pessoas_unicas,
                "total_cpfs_protegidos": total_cpfs,
                "cpfs_unicos": total_cpfs_unicos
            },
            "entidades_detalhadas": contadores_resumo,
            "amostras_auditoria": list(_TELEMETRIA["amostras_auditoria"])
        }
        
        caminho_arquivo = None
        if salvar_arquivo:
            try:
                os.makedirs(pasta_saida, exist_ok=True)
                ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
                nome_arq = f"relatorio_auditoria_{contexto.lower().replace(' ', '_')}_{ts_str}.json"
                caminho_arquivo = os.path.join(pasta_saida, nome_arq)
                with open(caminho_arquivo, "w", encoding="utf-8") as f:
                    json.dump(relatorio, f, indent=4, ensure_ascii=False)
                relatorio["arquivo_gerado"] = caminho_arquivo
                logger.info(f"📊 Relatório de telemetria e performance salvo em: {caminho_arquivo}")
            except Exception as e:
                logger.error(f"🚨 Falha ao salvar relatório de performance: {e}")
                
        return relatorio

def emitir_relatorio_auditoria():
    rel = gerar_relatorio_performance(salvar_arquivo=True, contexto="Auditoria")
    print("\n" + "="*70 + "\n🛡️  RELATÓRIO DE TELEMETRIA E AUDITORIA (DLP / LGPD) 🛡️\n" + "="*70)
    print(f"📊 Células/Textos avaliados:       {rel['metricas_performance']['itens_avaliados']}")
    print(f"🔴 Células/Textos alterados:       {rel['metricas_performance']['itens_alterados']}")
    print(f"🔀 Total de substituições:         {rel['metricas_performance']['substituicoes_totais']}")
    print(f"👤 Pessoas/Nomes mascarados:       {rel['resumo_rapido']['total_pessoas_protegidas']} (Únicos: {rel['resumo_rapido']['pessoas_unicas']})")
    print(f"🪪 CPFs mascarados:                {rel['resumo_rapido']['total_cpfs_protegidos']} (Únicos: {rel['resumo_rapido']['cpfs_unicos']})")
    print(f"⚡ Throughput:                     {rel['metricas_performance']['itens_por_segundo']} itens/s")
    print(f"📁 Arquivo de Saída:              {rel.get('arquivo_gerado', 'N/A')}")
    print("="*70 + "\n")
    return rel

def _ask_llm_yes_no(prompt: str, cache_key: str, system_prompt: str = "") -> bool:
    if cache_key in _OLLAMA_CACHE: return _OLLAMA_CACHE[cache_key]
    if len(_OLLAMA_CACHE) >= MAX_CACHE_SIZE: _OLLAMA_CACHE.clear() 
    try:
        resp = http_session.post(
            OLLAMA_URL, 
            json={
                "model": OLLAMA_MODEL, 
                "system": system_prompt, 
                "prompt": _sanitize_input(prompt), 
                "stream": False, 
                "options": {
                    "temperature": 0.0, 
                    "top_p": 0.1, 
                    "top_k": 1, 
                    "num_predict": 5
                }
            }, 
            timeout=(5, 20)
        )
        if resp.status_code == 200:
            resp_txt = resp.json().get("response", "").strip().upper()
            is_yes = bool(re.search(r'\bSIM\b', resp_txt)) and not bool(re.search(r'\bN[AÃ]O\b', resp_txt))
            _OLLAMA_CACHE[cache_key] = is_yes
            return is_yes
    except Exception as e: logger.warning(f"Falha LLM [{cache_key}]: {e}")
    return False

def _ask_llm_batch(candidates: list) -> list:
    if not candidates: return []
    instrucao_mestra = (
        "Validador estrito de nomes humanos em português. "
        "Responda estritamente 'SIM' se o fragmento for EXCLUSIVAMENTE um nome próprio de pessoa. "
        "Responda 'NAO' se for local, rua, órgão público, cargo, verbo ou objeto."
    )
    return [
        c for c in set(candidates) 
        if not _check_abort() 
        and len((c_clean := _sanitize_input(c.strip())).split()) >= 2 
        and not STOP_WORDS_NAME.search(c_clean) 
        and _ask_llm_yes_no(f"O fragmento '{c_clean}' é nome de pessoa? Responda SIM ou NAO:", f"PER:{c_clean.upper()}", system_prompt=instrucao_mestra)
    ]

class AegisClassifier:
    FAST_TRACK_MAP = {"CPF": "CPF", "RG": "RG", "CEP": "CEP", "PLATE": "PLACA", "EMAIL": "EMAIL", "PHONE": "PHONE", "CHASSI": "CHASSI", "IP": "IP", "COORD": "COORD", "COORD_SINGLE": "COORD_SINGLE", "TEXTO_LIVRE": "TEXTO_LIVRE", "NOME_SOLTO": "NOME_SOLTO", "DATE_TIME": "IGNORAR", "GENERIC_CODE": "GENERIC_CODE"}
    
    def get_column_tag(self, col_name: str, samples: list) -> str:
        amostras = [str(s).strip() for s in set(samples) if str(s).strip()][:50]
        if not amostras: return "TEXTO_LIVRE"
        placar = Counter()
        
        for s in amostras:
            sz = max(len(s), 1)
            if (m := REGEX["COORD"].search(s) or REGEX["COORD_SINGLE"].search(s)) and len(m.group()) / sz >= 0.70:
                placar["COORD"] += 1; continue
            
            matched = False
            for tag in ["EMAIL", "IP", "PLATE", "PHONE", "CPF", "CEP", "DATE_TIME", "RG", "CHASSI", "GENERIC_CODE"]:
                if (m := REGEX[tag].search(s)) and len(m.group()) / sz >= 0.70:
                    placar[tag] += 1; matched = True; break
            if matched: continue

            if len(re.sub(r'[^A-ZÀ-Ÿa-zà-ÿ\s]', '', s)) / sz > 0.85 and 2 <= len(s.split()) <= 7:
                placar["NOME_SOLTO"] += 1; continue
            placar["TEXTO_LIVRE" if len(s.split()) >= 8 or re.search(r'[,.!?]\s+[A-Z]', s) or sz > 100 else "IGNORAR"] += 1

        b, col_l = len(amostras) * 0.15, col_name.lower()
        if 'cpf' in col_l: placar["CPF"] += b
        if 'rg' in col_l or 'identidade' in col_l: placar["RG"] += b
        if 'placa' in col_l: placar["PLATE"] += b
        if any(x in col_l for x in ['nome', 'vitima', 'autor']): placar["NOME_SOLTO"] += b

        if placar["COORD"] > 0 and not any(REGEX["COORD"].search(s) for s in amostras): placar["COORD_SINGLE"] = placar.pop("COORD")
        if not placar: return "IGNORAR"
        
        vencedor, pts = placar.most_common(1)[0]
        confianca = pts / (len(amostras) + b)
        tag_decidida = self.FAST_TRACK_MAP.get(vencedor, vencedor)
        
        logger.info(f"⚖️ [JULGAMENTO] Coluna '{col_name}' -> Vencedor: {vencedor} (Confiança: {confianca*100:.1f}%) => Decisão: {tag_decidida}")
        return tag_decidida

_aegis_engine = AegisClassifier()

def setup_column_policies(rows: list, target_columns: list):
    for col in (target_columns or []):
        if col in _COLUMN_POLICIES: continue
        valores = list({str(r.get(col)).strip() for r in rows if r.get(col) and str(r.get(col)).strip().upper() not in ["NÃO CONSTA", "NULL", "NONE", "", "PREJUDICADO"]})
        if valores: _COLUMN_POLICIES[col] = _aegis_engine.get_column_tag(col, valores[:50])

@lru_cache(maxsize=100000)
def _normalize(text: str) -> str: return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c)).upper().strip()
def _imitar_codigo(codigo: str, r: random.Random) -> str: return "".join(str(r.randint(0, 9)) if c.isdigit() else (r.choice(string.ascii_uppercase) if c.isalpha() and c.isupper() else (r.choice(string.ascii_lowercase) if c.isalpha() else c)) for c in codigo)

@lru_cache(maxsize=MAX_CACHE_SIZE)
def _get_fake(value: str, typ: str, context_prefix: str = "") -> str:
    norm = _normalize(html.unescape(re.sub(r'<[^>]+>', '', value)).strip())
    s_int = int(hmac.new(SECRET_SALT.encode(), norm.encode(), hashlib.sha256).hexdigest()[:16], 16)
    fake.seed_instance(s_int)
    r = random.Random(s_int)
    
    if typ in ["COORD", "COORD_SINGLE"]: return re.sub(r"-?\d{1,3}[.,]\d{4,}", lambda m: f"{float(m.group().replace(',', '.')) + r.uniform(-0.003, 0.003):.6f}" if m else m.group(), norm)
    if typ in ["PER", "NOME_SOLTO"]: 
        fn = norm.split()[0] if norm.split() else ""
        is_fem = fn.endswith('A') or fn in {'SUELI', 'GLEICI', 'ISIS'} if fn not in {'LUIZ', 'DAVI', 'IGOR'} else bool(FEMALE_INDICATORS.search(context_prefix))
        _TELEMETRIA["identidades_protegidas"].add(norm)
        return f"{fake.first_name_female() if is_fem else fake.first_name_male()} {fake.last_name()}".upper()
    
    _TELEMETRIA["documentos_protegidos"].add(norm)
    if typ == "CPF": return fake.cpf()
    if typ in ["RG", "CEP", "GENERIC_CODE", "PHONE"]: return _imitar_codigo(norm, r)
    if typ in ["PLATE", "PLACA"]: return fake.license_plate().upper()
    if typ == "EMAIL": return fake.email().lower()
    if typ == "IP": return fake.ipv4()
    if typ == "CHASSI": return "".join(r.choices("ABCDEFGHJKLMNPRSTUVWXYZ0123456789", k=17))
    return fake.word().upper()

TAG_PRIORITY = ["CPF", "EMAIL", "PHONE", "PLATE", "CHASSI", "COORD", "COORD_SINGLE", "CEP", "RG", "GENERIC_CODE", "IP"]
TAG_RANK = {t: i for i, t in enumerate(["PER"] + TAG_PRIORITY)}

def _detect_all(text: str, regras_mascara: dict):
    found, r_get = [], regras_mascara.get
    tags_enabled = {t for t, k in [("CPF", "CPF"), ("RG", "RG"), ("CEP", "RG"), ("GENERIC_CODE", "RG"), ("EMAIL", "EMAIL"), ("IP", "IP"), ("PLATE", "PLATE"), ("CHASSI", "CHASSI"), ("PHONE", "PHONE"), ("COORD", "COORD"), ("COORD_SINGLE", "COORD")] if r_get(k, True)}
    ordered_tags = [t for t in TAG_PRIORITY if t in tags_enabled]
    ds = [m.span() for m in REGEX["DATE_TIME"].finditer(text)]

    for typ in ordered_tags:
        found.extend((m.start(), m.end(), m.group(), typ) for m in REGEX[typ].finditer(text) if not any(max(m.start(), d[0]) < min(m.end(), d[1]) for d in ds))
    occ = [(i[0], i[1]) for i in found]

    for m in TITLE_NAME_REGEX.finditer(text):
        if _check_abort(): break
        s, e = m.start(1), m.end(1)
        val_c = _clean_name(text[s:e])
        if len(val_c.split()) >= 2 and not STOP_WORDS_NAME.search(val_c) and not any(max(s, o[0]) < min(e, o[1]) for o in occ):
            found.append((s, e, val_c, "PER"))

    if r_get("NOMES_IA", True) and nlp:
        doc = nlp(text.title() if text.isupper() else text)
        cand = {ent.text.strip(".,;:?!() \n'\"") for ent in doc.ents if ent.label_ == "PER"}
        appr = _ask_llm_batch(list(cand))
        for s, e, v in [(m.start(), m.end(), m.group()) for a in appr for m in re.finditer(re.escape(a), text, re.I)]:
            if not any(max(s, o[0]) < min(e, o[1]) for o in occ): found.append((s, e, v, "PER"))

    return sorted(found, key=lambda x: (x[0], -(x[1] - x[0]), TAG_RANK.get(x[3], 99)))

def anonymize_value(col_name: str, val, regras_mascara=None):
    try:
        if not val: return val, None
        text, r_mask = str(val), regras_mascara or {}
        if isinstance(r_mask, bool): r_mask = {"COORD": r_mask, "COORD_SINGLE": r_mask}
        
        with _TELEMETRIA_LOCK:
            _TELEMETRIA["celulas_avaliadas"] += 1
            
        pol = _COLUMN_POLICIES.get(col_name, "TEXTO_LIVRE")
        if pol == "IGNORAR" or (pol in ["COORD", "COORD_SINGLE"] and not r_mask.get("COORD", True)): return text, None

        if pol in ["NOME_SOLTO", "COORD", "COORD_SINGLE", "PLACA", "CPF", "RG", "CEP", "EMAIL", "PLATE", "PHONE", "IP", "CHASSI", "GENERIC_CODE"]:
            fake_v = _get_fake(text, pol)
            if fake_v != text:
                with _TELEMETRIA_LOCK:
                    _TELEMETRIA["celulas_alteradas"] += 1
                    _TELEMETRIA["substituicoes_totais"] += 1
                _registrar_captura(pol, text, fake_v)
                if random.random() < 0.05:
                    logger.info(f"🔎 [TROCA DIRETA | {col_name}] '{text}' ➡️ '{fake_v}'")
            return fake_v, ("TEXT" if fake_v != text else None)

        if pol == "TEXTO_LIVRE":
            ents = _detect_all(text, r_mask)
            if not ents: return text, None
            
            res, last = [], 0
            for s, e, v, t in ents:
                if s < last: continue
                fake_v = _get_fake(v, t, text[max(0, s-20):s])
                with _TELEMETRIA_LOCK:
                    _TELEMETRIA["substituicoes_totais"] += 1
                _registrar_captura(t, v, fake_v)
                if random.random() < 0.20 or col_name == "RAW_TEXT_INJECTION":
                    logger.info(f"🔎 [TROCA NARRATIVA | {col_name}] '{v}' ➡️ '{fake_v}'")
                res.extend([text[last:s], fake_v])
                last = e
            res.append(text[last:])
            txt_fin = "".join(res)
            if txt_fin != text:
                with _TELEMETRIA_LOCK:
                    _TELEMETRIA["celulas_alteradas"] += 1
            return txt_fin, ("TEXT" if txt_fin != text else None)
        return text, None
    except Exception as e:
        logger.error(f"Erro '{col_name}': {e}")
        return "[DADO SUPRIMIDO POR SEGURANÇA]", None

def reset_memory(): _OLLAMA_CACHE.clear(); _COLUMN_POLICIES.clear(); _get_fake.cache_clear()

def _apply_shield(text, callback, *args):
    vault = {}
    def hide(m):
        tk = f" __SHLD{secrets.token_hex(4)}__ "
        vault[tk.strip()] = m.group(0)
        return tk
    safe_t = re.compile(r"<[^>]+>").sub(hide, html.unescape(str(text)))
    fin, _ = callback(*args, safe_t)
    for tk, orig in vault.items(): fin = str(fin).replace(f" {tk} ", orig).replace(tk, orig)
    return fin

def process_chunk_parallel(rows, modo, regras_mascara, target_columns):
    if modo != "🛡️ Anonimização Total" or not rows: return rows
    if (alvo := [c for c in rows[0].keys() if c in target_columns]): setup_column_policies(rows, alvo)
    
    for idx, r in enumerate(rows):
        if idx % 50 == 0 and _check_abort(): break
        for col, old in dict(r).items():
            if col not in target_columns or not old or type(old).__name__ in ['date', 'datetime', 'Timestamp', 'bool']: continue
            try: r[col] = _apply_shield(old, lambda c, s: anonymize_value(c, s, regras_mascara or {}), col)
            except Exception: r[col] = "[SUPRIMIDO POR FALHA]"
    return rows 

def process_raw_text(text: str, regras_mascara=None) -> str:
    if not text: return text
    _COLUMN_POLICIES["RAW_TEXT_INJECTION"] = "TEXTO_LIVRE"
    return _apply_shield(text, lambda c, s: anonymize_value(c, s, regras_mascara or {}), "RAW_TEXT_INJECTION")