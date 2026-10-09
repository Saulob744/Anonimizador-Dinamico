import streamlit as st
import re
import random
import string
import logging
import warnings
import urllib.parse
import time
import psutil
import os
import html
import pyodbc
import json
import threading
import io
import zipfile
import csv
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import anonymizer
import db_utils

try: import pandas as pd
except ImportError: pd = None
try: import PyPDF2
except ImportError: PyPDF2 = None
try: import docx
except ImportError: docx = None
try: from fpdf import FPDF
except ImportError: FPDF = None

STATUS_FILE = "pipeline_progress.json"
FILE_STATUS_FILE = "file_pipeline_progress.json"
ABORT_FILE = "abort.flag"

if "CACHE_RESULTADOS_ARQUIVOS" not in st.session_state:
    st.session_state.CACHE_RESULTADOS_ARQUIVOS = None
if "file_process_started" not in st.session_state:
    st.session_state.file_process_started = False

def save_progress(arquivo_alvo, fase, t_atual, t_total, l_atual, l_total, velocidade, tempo, finalizado=False, politicas=None, relatorio_performance=None):
    data = {
        "fase": fase, "tabelas_processadas": t_atual, "tabelas_total": t_total,
        "linhas_processadas": l_atual, "linhas_total": l_total,
        "velocidade": velocidade, "tempo_decorrido": tempo, "finalizado": finalizado,
        "politicas": politicas or {},
        "relatorio_performance": relatorio_performance
    }
    try:
        with open(arquivo_alvo, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
    except Exception:
        pass

def load_progress(arquivo_alvo):
    if os.path.exists(arquivo_alvo):
        for _ in range(5):
            try:
                with open(arquivo_alvo, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                time.sleep(0.1)
    return None

def render_painel_relatorio_performance(relatorio, titulo="📊 Avaliação de Performance e Capacidade da Anonimização"):
    if not relatorio:
        return
        
    st.markdown("---")
    st.markdown(f"### {titulo}")
    
    meta = relatorio.get("metadados", {})
    perf = relatorio.get("metricas_performance", {})
    resumo = relatorio.get("resumo_rapido", {})
    entidades = relatorio.get("entidades_detalhadas", {})
    
    # 4 colunas principais de alto nível
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(
            label="⚡ Velocidade Média",
            value=f"{perf.get('itens_por_segundo', 0):,.1f} itens/s",
            help="Taxa de transferência: total de itens ou células avaliadas por segundo."
        )
    with col2:
        st.metric(
            label="⏱️ Tempo Total",
            value=meta.get("tempo_formatado", "0s"),
            help=f"Duração cronometrada: {meta.get('tempo_total_segundos', 0)}s."
        )
    with col3:
        st.metric(
            label="🛡️ Dados Mascarados",
            value=f"{perf.get('substituicoes_totais', 0):,}",
            help=f"Total de transformações sensíveis aplicadas (Taxa de sensibilidade da base: {perf.get('taxa_sensibilidade_pct', 0)}%)."
        )
    with col4:
        st.metric(
            label="👥 Pessoas Protegidas",
            value=f"{resumo.get('pessoas_unicas', 0):,} únicas",
            delta=f"{resumo.get('total_pessoas_protegidas', 0)} ocorrências",
            delta_color="off",
            help="Total de identidades de pessoas e nomes próprios identificados e mascarados."
        )

    # Detalhamento de Entidades Capturadas
    if entidades:
        st.markdown("#### 🔍 Mapeamento Granular de Dados Sensíveis Capturados")
        dados_tabela = []
        for cat, dados in entidades.items():
            dados_tabela.append({
                "Categoria Sensível": dados.get("label", cat),
                "Ocorrências Substituídas": f"{dados.get('total_capturado', 0):,}",
                "Registros Únicos Distintos": f"{dados.get('unicos_distintos', 0):,}"
            })
        
        df_entidades = pd.DataFrame(dados_tabela)
        st.dataframe(df_entidades, use_container_width=True, hide_index=True)
        
    # Informações de Auditoria e Botão de Download
    arq_path = relatorio.get("arquivo_gerado")
    c_btn, c_info = st.columns([1, 2])
    with c_btn:
        rel_json_bytes = json.dumps(relatorio, indent=4, ensure_ascii=False).encode("utf-8")
        nome_download = os.path.basename(arq_path) if arq_path else "relatorio_auditoria_performance.json"
        st.download_button(
            label="📥 Baixar Relatório de Auditoria (.JSON)",
            data=rel_json_bytes,
            file_name=nome_download,
            mime="application/json",
            type="primary",
            use_container_width=True
        )
    with c_info:
        if arq_path:
            st.caption(f"📁 **Arquivo Gerado no Servidor:** `{arq_path}`\n\n*(Modelo IA: `{meta.get('modelo_ia', 'N/A')}` | Contexto: `{meta.get('contexto', 'Geral')}`)*")
            
    with st.expander("📄 Ver Estrutura Técnica Completa do Relatório (Auditoria DLP / LGPD)", expanded=False):
        st.json(relatorio)

def clear_abort():
    if os.path.exists(ABORT_FILE):
        try: os.remove(ABORT_FILE)
        except: pass

def check_abort():
    return os.path.exists(ABORT_FILE)

def limpar_sessao():
    for f in [STATUS_FILE, FILE_STATUS_FILE, "resultado_lote.zip", ABORT_FILE]:
        if os.path.exists(f):
            try: os.remove(f)
            except Exception: pass
    for key in ["analise_concluida", "todas_colunas_disponiveis", "colunas_selecionadas_finais", "CACHE_RESULTADOS_ARQUIVOS", "file_process_started", "colunas_ordenaveis", "limite_linhas_db", "coluna_ordenacao", "direcao_ordenacao", "texto_anonimizado_resultado", "relatorio_texto_livre"]:
        if key in st.session_state:
            del st.session_state[key]

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logging.getLogger("streamlit.runtime.scriptrunner_utils.script_run_context").setLevel(logging.ERROR)
warnings.filterwarnings("ignore")

st.set_page_config(page_title="Pipeline de Proteção", page_icon="🔒", layout="wide")
st.markdown("""
    <style>
    :root { --primary: #0ea5e9; --bg-dark: #0f172a; --text-light: #e2e8f0; }
    .block-container { padding-top: 2rem; padding-bottom: 2rem; }
    h1, h2, h3 { font-family: 'Inter', sans-serif; font-weight: 600; color: #f8fafc; }
    .stButton>button { border-radius: 6px; font-weight: 500; transition: all 0.2s; }
    .stButton>button[kind="primary"] { background-color: var(--primary); border: none; }
    .stButton>button[kind="primary"]:hover { background-color: #0284c7; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
    [data-testid="stMetricValue"] { font-size: 1.5rem; color: var(--primary); font-weight: 600; }
    .stProgress .st-at { background-color: var(--primary); }
    .texto-seguro { border-left: 4px solid var(--primary); padding: 16px; border-radius: 4px; background-color: #1e293b; color: #cbd5e1; white-space: pre-wrap; font-family: 'Fira Code', monospace; font-size: 0.9rem; line-height: 1.5; }
    .sidebar-section { margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid #334155; }
    div[data-testid="stSidebarNav"] { display: none; }
    </style>
""", unsafe_allow_html=True)

def build_url(db_type, config_dict):
    if isinstance(config_dict, str):
        import ast
        try: config_dict = ast.literal_eval(config_dict)
        except: config_dict = {}

    host = config_dict.get("host", "localhost")
    port = config_dict.get("port", "")
    db = config_dict.get("db", "")
    user = config_dict.get("user", "")
    password = config_dict.get("password", "")

    url = None
    if db_type == "mssql":
        try: driver = [d for d in pyodbc.drivers() if "SQL Server" in d][-1]
        except IndexError: driver = "ODBC Driver 17 for SQL Server"
        if host and "localdb" in host.lower():
            odbc_str = rf"DRIVER={{{driver}}};SERVER=(localdb)\MSSQLLocalDB;DATABASE={db};Trusted_Connection=yes;"
            url = f"mssql+pyodbc:///?odbc_connect={urllib.parse.quote_plus(odbc_str)}"
        elif user and password:
            url = f"mssql+pyodbc://{urllib.parse.quote_plus(user)}:{urllib.parse.quote_plus(password)}@{host}:{port}/{db}?driver={urllib.parse.quote_plus(driver)}"
        else:
            url = f"mssql+pyodbc://@{host}:{port}/{db}?driver={urllib.parse.quote_plus(driver)}&trusted_connection=yes"
    elif db_type == "postgresql":
        url = f"postgresql+psycopg2://{urllib.parse.quote_plus(user)}:{urllib.parse.quote_plus(password)}@{host}:{port}/{db}?client_encoding=utf8"
    elif db_type == "mysql":
        url = f"mysql+pymysql://{urllib.parse.quote_plus(user)}:{urllib.parse.quote_plus(password)}@{host}:{port}/{db}?charset=utf8mb4"
    return url

def run_pipeline_background(db_type, src_cfg, dst_cfg, filter_tables, n_cores, chunk_size, max_limit, order_by_col_pref, order_direction, modo, regras_mascara, target_cols, pause_between_chunks=0.0):
    t0_global = time.time()
    clear_abort()
    anonymizer.resetar_telemetria()
    try:
        save_progress(STATUS_FILE, "Conectando aos bancos de dados...", 0, 0, 0, 0, 0, 0)
        src_engine = db_utils.connect(build_url(db_type, src_cfg))
        dst_engine = db_utils.connect(build_url(db_type, dst_cfg))
        db_utils.set_replication_role(dst_engine, "replica")

        schemas = db_utils.get_user_schemas(src_engine)
        allowed = [t.strip() for t in filter_tables.split(",")] if filter_tables else []
        work_list = []
        total_estimated, total_tables = 0, 0

        for s in schemas:
            db_utils.copy_schema(src_engine, dst_engine, s)
            tables = [t for t in db_utils.get_tables(src_engine, s) if not allowed or t in allowed]
            ordered = db_utils.build_dependency_graph(src_engine, tables, s)
            for t in ordered:
                count = db_utils.get_table_count(src_engine, t, s)
                if max_limit > 0 and count > max_limit:
                    count = max_limit
                work_list.append((s, t, count))
                total_estimated += count
                total_tables += 1

        if total_estimated == 0:
            save_progress(STATUS_FILE, "Erro: Nenhuma linha encontrada.", 0, 0, 0, 0, 0, 0, finalizado=True)
            return

        for s, t, _ in reversed(work_list): db_utils.truncate_table(dst_engine, t, s)
        
        total_rows, processed_tables, last_json_update = 0, 0, 0
        weighted_speed_samples = []

        with ThreadPoolExecutor(max_workers=n_cores) as executor:
            for s, t, t_count in work_list:
                processed_tables += 1
                cols_da_tabela = [c.replace(f"{t}.", "", 1) for c in target_cols if c.startswith(f"{t}.")]

                limit_val = max_limit if max_limit > 0 else None
                col_ordem = None if order_by_col_pref == "Nenhuma" else order_by_col_pref
                dir_ordem = "DESC" if "DESC" in order_direction else "ASC"
                
                for chunk in db_utils.fetch_rows_streaming(src_engine, t, s, chunk_size, order_by_column=col_ordem, max_limit=limit_val, order_direction=dir_ordem, pause_between_chunks=pause_between_chunks):
                    chunk_start = time.time()
                    rows = [dict(r) for r in chunk]

                    if modo == "🛡️ Anonimização Total":
                        if n_cores > 1:
                            sub_sz = max(1, len(rows) // n_cores)
                            sub_chunks = [rows[i:i + sub_sz] for i in range(0, len(rows), sub_sz)]
                            futures = [executor.submit(anonymizer.process_chunk_parallel, sub_chunk, modo, regras_mascara, cols_da_tabela) for sub_chunk in sub_chunks]
                            
                            linhas_limpas = []
                            abort_detected = False
                            
                            for sub, f in zip(sub_chunks, futures):
                                while True:
                                    if check_abort():
                                        abort_detected = True
                                        break
                                    try:
                                        res = f.result(timeout=1.0)
                                        linhas_limpas.extend(res or sub)
                                        break
                                    except TimeoutError:
                                        pass
                                if abort_detected:
                                    break
                            
                            if abort_detected:
                                executor.shutdown(wait=False)
                                save_progress(STATUS_FILE, "🛑 Abortado pelo Operador", processed_tables, total_tables, total_rows, total_estimated, 0, time.time() - t0_global, finalizado=True)
                                return
                            
                            rows = linhas_limpas
                        else:
                            if check_abort():
                                save_progress(STATUS_FILE, "🛑 Abortado pelo Operador", processed_tables, total_tables, total_rows, total_estimated, 0, time.time() - t0_global, finalizado=True)
                                return
                            try: rows = anonymizer.process_chunk_parallel(rows, modo, regras_mascara, cols_da_tabela) or rows
                            except Exception: pass

                    if rows: db_utils.insert_rows(dst_engine, t, s, rows)
                    total_rows += len(rows)
                    
                    chunk_speed = len(rows) / max(time.time() - chunk_start, 0.001)
                    weighted_speed_samples.append(chunk_speed)
                    if len(weighted_speed_samples) > 30: weighted_speed_samples.pop(0)

                    now = time.time()
                    if now - last_json_update > 2.5:
                        stable_speed = sum(weighted_speed_samples) / len(weighted_speed_samples) if weighted_speed_samples else 0
                        save_progress(STATUS_FILE, f"Processando: {t}", processed_tables, total_tables, total_rows, total_estimated, stable_speed, now - t0_global, False, anonymizer._COLUMN_POLICIES)
                        last_json_update = now

        db_utils.set_replication_role(dst_engine, "origin")
        relatorio = anonymizer.gerar_relatorio_performance(salvar_arquivo=True, contexto="Banco de Dados")
        save_progress(STATUS_FILE, "Concluído", processed_tables, total_tables, total_rows, total_estimated, 0, time.time() - t0_global, finalizado=True, politicas=anonymizer._COLUMN_POLICIES, relatorio_performance=relatorio)

    except Exception as e:
        save_progress(STATUS_FILE, f"Erro Fatal: {e}", 0, 0, 0, 0, 0, 0, finalizado=True)

def run_files_pipeline_background(arquivos_payload, formato_saida, regras_mascara, colunas_ignoradas_csv, chunk_size, n_cores):
    t0_global = time.time()
    total_arquivos = len(arquivos_payload)
    arquivos_prontos = []
    clear_abort()
    anonymizer.resetar_telemetria()
    
    try:
        save_progress(FILE_STATUS_FILE, "Iniciando Esteira de Arquivos...", 0, total_arquivos, 0, 100, 0, 0, False)
        
        for idx, arq in enumerate(arquivos_payload):
            if check_abort():
                save_progress(FILE_STATUS_FILE, "🛑 Abortado pelo Operador", idx, total_arquivos, 0, 100, 0, time.time()-t0_global, finalizado=True)
                return

            nome_base = arq["name"].rsplit('.', 1)[0]
            extensao = arq["ext"]
            bytes_in = arq["bytes"]
            
            save_progress(FILE_STATUS_FILE, f"Processando: {arq['name']}", idx, total_arquivos, 0, 100, 0, time.time()-t0_global, False)

            if extensao in ["txt", "pdf"]:
                texto_bruto = ""
                if extensao == "txt":
                    texto_bruto = bytes_in.decode("utf-8", errors='ignore')
                elif extensao == "pdf":
                    pdf_reader = PyPDF2.PdfReader(io.BytesIO(bytes_in))
                    for pagina in pdf_reader.pages:
                        txt_pg = pagina.extract_text()
                        if txt_pg: texto_bruto += txt_pg + "\n\n"
                
                with ThreadPoolExecutor(max_workers=1) as txt_exec:
                    f = txt_exec.submit(anonymizer.process_raw_text, texto_bruto, regras_mascara)
                    abort_detected = False
                    while True:
                        if check_abort():
                            abort_detected = True
                            break
                        try:
                            resultado_limpo = f.result(timeout=1.0)
                            break
                        except TimeoutError:
                            pass
                    
                    if abort_detected:
                        txt_exec.shutdown(wait=False)
                        save_progress(FILE_STATUS_FILE, "🛑 Abortado pelo Operador", idx, total_arquivos, 0, 100, 0, time.time()-t0_global, finalizado=True)
                        return

                fmt_atual = extensao if formato_saida == "Manter Original" else formato_saida
                if fmt_atual == "txt":
                    arquivos_prontos.append({"name": f"SEGURO_{nome_base}.txt", "data": resultado_limpo.encode('utf-8')})
                elif fmt_atual == "pdf":
                    pdf_out = FPDF()
                    pdf_out.add_page(); pdf_out.set_font("Arial", size=11)
                    pdf_out.multi_cell(0, 5, resultado_limpo.encode('latin-1', 'replace').decode('latin-1'))
                    arquivos_prontos.append({"name": f"SEGURO_{nome_base}.pdf", "data": pdf_out.output(dest='S').encode('latin-1')})

            elif extensao == "csv":
                amostra = bytes_in[:4096].decode('utf-8', errors='ignore')
                try: sep_detectado = csv.Sniffer().sniff(amostra).delimiter
                except: sep_detectado = ','

                buffer_out = io.StringIO()
                buffer_in = io.BytesIO(bytes_in)

                df_header = pd.read_csv(io.BytesIO(bytes_in), sep=sep_detectado, encoding_errors='replace', on_bad_lines='skip', nrows=0)
                cols_alvo = [c for c in df_header.columns if c not in colunas_ignoradas_csv]
                
                chunk_iter = pd.read_csv(buffer_in, sep=sep_detectado, encoding_errors='replace', on_bad_lines='skip', chunksize=chunk_size)
                
                first_chunk = True
                linhas_processadas_total = 0
                
                with ThreadPoolExecutor(max_workers=n_cores) as executor:
                    for chunk in chunk_iter:
                        lote_start = time.time()
                        linhas = chunk.to_dict('records')
                        
                        if n_cores > 1:
                            sub_sz = max(1, len(linhas) // n_cores)
                            sub_chunks = [linhas[i:i + sub_sz] for i in range(0, len(linhas), sub_sz)]
                            futures = [executor.submit(anonymizer.process_chunk_parallel, sub_chunk, "🛡️ Anonimização Total", regras_mascara, cols_alvo) for sub_chunk in sub_chunks]
                            
                            linhas_limpas = []
                            abort_detected = False
                            
                            for sub, f in zip(sub_chunks, futures):
                                while True:
                                    if check_abort():
                                        abort_detected = True
                                        break
                                    try:
                                        res = f.result(timeout=1.0)
                                        linhas_limpas.extend(res or sub)
                                        break
                                    except TimeoutError:
                                        pass
                                if abort_detected:
                                    break
                                    
                            if abort_detected:
                                executor.shutdown(wait=False)
                                save_progress(FILE_STATUS_FILE, "🛑 Abortado pelo Operador", idx, total_arquivos, linhas_processadas_total, linhas_processadas_total, 0, time.time()-t0_global, finalizado=True)
                                return
                        else:
                            if check_abort():
                                save_progress(FILE_STATUS_FILE, "🛑 Abortado pelo Operador", idx, total_arquivos, linhas_processadas_total, linhas_processadas_total, 0, time.time()-t0_global, finalizado=True)
                                return
                            try: linhas_limpas = anonymizer.process_chunk_parallel(linhas, "🛡️ Anonimização Total", regras_mascara, cols_alvo) or linhas
                            except Exception: linhas_limpas = linhas

                        df_out = pd.DataFrame(linhas_limpas)
                        df_out.to_csv(buffer_out, sep=sep_detectado, index=False, mode='a', header=first_chunk)
                        first_chunk = False
                        
                        linhas_processadas_total += len(linhas_limpas)
                        vel_chunk = len(linhas_limpas) / max(time.time() - lote_start, 0.001)
                        save_progress(FILE_STATUS_FILE, f"Lote CSV: {arq['name']} ({linhas_processadas_total} linhas)", idx, total_arquivos, linhas_processadas_total, linhas_processadas_total+1000, vel_chunk, time.time()-t0_global, False)
                
                arquivos_prontos.append({"name": f"SEGURO_{nome_base}.csv", "data": buffer_out.getvalue().encode('utf-8-sig')})

        if len(arquivos_prontos) > 0:
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
                for pf in arquivos_prontos:
                    zip_file.writestr(pf["name"], pf["data"])
            
            with open("resultado_lote.zip", "wb") as f:
                f.write(zip_buffer.getvalue())

        relatorio = anonymizer.gerar_relatorio_performance(salvar_arquivo=True, contexto="Arquivos")
        save_progress(FILE_STATUS_FILE, "Concluído", total_arquivos, total_arquivos, 100, 100, 0, time.time() - t0_global, finalizado=True, relatorio_performance=relatorio)

    except Exception as e:
        logger.error(f"Erro Arquivos Background: {e}", exc_info=True)
        save_progress(FILE_STATUS_FILE, f"Erro Fatal: {e}", 0, 0, 0, 0, 0, 0, finalizado=True)

st.title("🔒 Pipeline de Proteção de Dados")
st.markdown("Proteção de PIIs em escala para fluxos operacionais e de inteligência.")

if "view_mode" not in st.session_state: st.session_state.view_mode = "Bancos de Dados"

with st.sidebar:
    st.markdown("### Selecione o Modo")
    modo_selecionado = st.radio("Menu de Navegação", ["🗄️ Bancos de Dados", "📄 Arquivos (.pdf, .csv, .txt)", "📝 Texto Livre"], label_visibility="collapsed")
    
    if modo_selecionado.replace("🗄️ ", "").replace("📄 ", "").replace("📝 ", "") != st.session_state.view_mode:
        limpar_sessao()
        st.session_state.view_mode = modo_selecionado.replace("🗄️ ", "").replace("📄 ", "").replace("📝 ", "")
        st.rerun()

    st.divider()
    st.markdown("### 🛡️ Políticas de Proteção")
    
    with st.expander("Configurar Tipos de Dados", expanded=True):
        st.markdown("<small>Desmarque para manter o dado original:</small>", unsafe_allow_html=True)
        mask_cpf_rg = st.checkbox("CPF e RG", value=True)
        mask_cep_cod= st.checkbox("CEPs e Códigos (IDs/Matrículas)", value=True, help="Ofusca sequências numéricas genéricas preservando a estrutura.") 
        mask_names  = st.checkbox("Nomes (IA Neural)", value=True)
        mask_phone  = st.checkbox("Telefones", value=True)
        mask_email  = st.checkbox("E-mails", value=True)
        mask_ip     = st.checkbox("Endereços IP", value=True)
        mask_plate  = st.checkbox("Placas e Chassis", value=True)
        mask_geo    = st.checkbox("📍 Coordenadas GPS (Jittering)", value=True, help="Adiciona um ruído matemático determinístico para ofuscar o local exato.")    
        mask_date   = st.checkbox("Datas e Horas", value=True)

    dicionario_regras = {
        "CPF": mask_cpf_rg, "RG": mask_cpf_rg, 
        "CEP": mask_cep_cod, "GENERIC_CODE": mask_cep_cod, 
        "NOMES_IA": mask_names,
        "PHONE": mask_phone, "EMAIL": mask_email, "IP": mask_ip,
        "PLATE": mask_plate, "CHASSI": mask_plate, 
        "COORD": mask_geo, "COORD_SINGLE": mask_geo, 
        "DATE_TIME": mask_date,
    }
    st.divider()

    if st.session_state.view_mode == "Bancos de Dados":
        st.markdown("#### Configuração Conexão")
        db_type = st.selectbox("Motor", ["postgresql", "mysql", "mssql"])
        ab_o, ab_d = st.tabs(["Origem (Restrito / Leitura)", "Destino (Local / Livre)"])

        def get_default_db_config(prefix):
            env_url = os.getenv("DB_SOURCE" if prefix == "origem" else "DB_TARGET")
            cfg = {"host": "localhost", "port": "", "db": "", "user": "", "password": ""}
            if env_url:
                try:
                    clean = env_url.split("://")[-1] if "://" in env_url else env_url
                    p = urllib.parse.urlparse(f"dummy://{clean}")
                    if p.hostname: cfg["host"] = p.hostname
                    if p.port: cfg["port"] = str(p.port)
                    if p.path: cfg["db"] = p.path.lstrip("/")
                    if p.username: cfg["user"] = p.username
                    if p.password: cfg["password"] = p.password
                except Exception:
                    pass
            return cfg

        def render_db_form(prefix):
            defaults = get_default_db_config(prefix)
            return {
                "host": st.text_input("Host", value=defaults["host"], key=f"{prefix}_host"),
                "port": st.text_input("Porta", value=defaults["port"], key=f"{prefix}_port"),
                "db": st.text_input("Banco", value=defaults["db"], key=f"{prefix}_db"),
                "user": st.text_input("Usuário", value=defaults["user"], key=f"{prefix}_user"),
                "password": st.text_input("Senha", value=defaults["password"], type="password", key=f"{prefix}_pass")
            }

        with ab_o: src_cfg = render_db_form("origem")
        with ab_d: dst_cfg = render_db_form("destino")

        st.markdown("#### Parâmetros de Motor")
        modo = st.selectbox("Modo BD", ["🛡️ Anonimização Total", "⚡ Cópia Direta"])
        chunk_size_db = st.number_input(
            "Lote Sequencial DB (Rows)", 
            value=int(os.getenv("CHUNK_SIZE_DB", 9000)), 
            step=1000, 
            max_value=9500, 
            help="Tamanho do lote sequencial. Configurado em 9.000 para não estourar o limite de 10.000 linhas de bancos de dados restritos."
        )
        pause_db = st.slider(
            "Pausa entre Consultas (segundos)", 
            min_value=0.0, 
            max_value=5.0, 
            value=0.0, 
            step=0.5, 
            help="Tempo de espera entre requisições sequenciais (útil caso o banco externo limite a taxa de requisições)."
        )
        filter_tables = st.text_input("Filtrar tabelas (vírgula)")
        super_proc_db = st.toggle("🚀 Multi CPU BD", value=False)
        n_cores_db = st.slider("CPU BD", 1, psutil.cpu_count(logical=True), psutil.cpu_count(logical=True)) if super_proc_db else 1

        st.divider()
        btn_analisar = st.button("Analisar Estrutura", use_container_width=True)
        
        if btn_analisar:
            try:
                src_engine = db_utils.connect(build_url(db_type, src_cfg))
                schemas = db_utils.get_user_schemas(src_engine)
                allowed = [t.strip() for t in filter_tables.split(",")] if filter_tables else []
                
                todas_set = set()
                ordenaveis_set = set() 
                
                if schemas:
                    for schema in schemas:
                        tables = db_utils.get_tables(src_engine, schema)
                        for table in [t for t in tables if not allowed or t in allowed]:
                            info_tabela = db_utils.get_table_info(src_engine, table, schema)
                            for col_info in info_tabela.get("columns", []):
                                col_name = col_info['name']
                                todas_set.add(f"{table}.{col_name}")
                                
                                if col_info.get("is_date") or col_name.lower() in ['id', 'codigo', 'cod', 'created_at', 'data_registro']:
                                    ordenaveis_set.add(col_name)
                
                st.session_state.todas_colunas_disponiveis = sorted(list(todas_set))
                st.session_state.colunas_ordenaveis = sorted(list(ordenaveis_set))
                st.session_state.analise_concluida = True
                st.success(f"✅ {len(st.session_state.todas_colunas_disponiveis)} colunas mapeadas.")
            except Exception as e: st.error(f"Erro ao analisar: {e}")

        start_btn_db = False
        if st.session_state.get("analise_concluida", False):
            st.markdown("#### ⚙️ Governança de Extração")
            limite_linhas_db = st.number_input(
                "Limite Máximo por Tabela (0 = Sem limite)", 
                value=1000, step=1000, 
                help="A extração será encerrada ao atingir esta linha. Protege contra DoS."
            )
            
            opcoes_ordem = ["Nenhuma"] + st.session_state.get("colunas_ordenaveis", [])
            col_ordem, col_dir = st.columns(2)
            with col_ordem:
                coluna_ordenacao = st.selectbox(
                    "Coluna de Ordenação", 
                    options=opcoes_ordem, 
                    help="Recomendado: colunas de Data ou ID."
                )
            with col_dir:
                direcao_ordenacao = st.selectbox(
                    "Direção da Leitura",
                    options=["Mais Antigos Primeiro (ASC)", "Mais Recentes Primeiro (DESC)"]
                )
            
            st.markdown("#### Mapeamento de Exceções")
            colunas_ignoradas_db = st.multiselect("Ignorar colunas BD:", options=st.session_state.todas_colunas_disponiveis, default=[])
            start_btn_db = st.button("Iniciar Pipeline de Banco", type="primary", use_container_width=True)
            
            if start_btn_db: 
                st.session_state.colunas_selecionadas_finais = [col for col in st.session_state.todas_colunas_disponiveis if col not in colunas_ignoradas_db]
                st.session_state.limite_linhas_db = limite_linhas_db
                st.session_state.coluna_ordenacao = coluna_ordenacao
                st.session_state.direcao_ordenacao = direcao_ordenacao
                st.session_state.pause_db = pause_db

    elif st.session_state.view_mode == "Arquivos (.pdf, .csv, .txt)":
        st.markdown("#### Parâmetros de Motor (Arquivos)")
        chunk_size_file = st.number_input("Lote de Memória CSV (Rows)", value=5000, step=1000, help="Quantidade de linhas carregadas na memória por vez.")
        super_proc_file = st.toggle("🚀 Multi CPU Arquivos", value=True)
        n_cores_file = st.slider("CPU Arquivos", 1, psutil.cpu_count(logical=True), max(1, psutil.cpu_count(logical=True)-1)) if super_proc_file else 1


if st.session_state.view_mode == "Bancos de Dados":
    st.markdown("### Monitoramento do Pipeline Estruturado")
    
    if start_btn_db:
        save_progress(STATUS_FILE, "Iniciando Thread Fantasma...", 0, 1, 0, 1, 0, 0, finalizado=False)
        threading.Thread(
            target=run_pipeline_background, 
            args=(
                db_type, src_cfg, dst_cfg, filter_tables, n_cores_db, chunk_size_db, 
                st.session_state.limite_linhas_db, st.session_state.coluna_ordenacao, st.session_state.direcao_ordenacao,
                modo, dicionario_regras, st.session_state.colunas_selecionadas_finais,
                st.session_state.get("pause_db", 0.0)
            ), 
            daemon=True
        ).start()
        time.sleep(1); st.rerun()   

    estado_atual = load_progress(STATUS_FILE)
    if estado_atual:
        if not estado_atual.get("finalizado", True):
            st.info("🔄 O processo de banco de dados está rodando em background.")
            
            col_a, col_b = st.columns([1, 1])
            with col_a:
                if st.button("🔄 Atualizar Monitor", type="primary", use_container_width=True): st.rerun()
            with col_b:
                if st.button("🛑 Abortar Operação", type="secondary", use_container_width=True):
                    with open(ABORT_FILE, "w") as f: f.write("abort")
                    st.warning("Sinal de parada de emergência acionado! Interrompendo motor...")
                    time.sleep(1.5)
                    st.rerun()
                
            l_proc, l_tot, vel = estado_atual.get("linhas_processadas", 0), estado_atual.get("linhas_total", 0), estado_atual.get("velocidade", 0)
            eta = f"{divmod(divmod(int(max(0, l_tot - l_proc) / vel), 60)[0], 60)[0]}h {divmod(int(max(0, l_tot - l_proc) / vel), 60)[0] % 60}m {int(max(0, l_tot - l_proc) / vel) % 60}s" if vel > 0 else "..."
                
            st.progress(min(0.25 + ((l_proc / max(l_tot, 1)) * 0.75), 1.0) if l_proc > 0 else 0.1)
            
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Status Atual", estado_atual['fase'])
            c2.metric("Tabelas Concluídas", f"{estado_atual['tabelas_processadas']}/{estado_atual['tabelas_total']}")
            c3.metric("Registros Processados", f"{l_proc:,}/{l_tot:,}")
            c4.metric("Mutação Neural", f"{vel:,.0f} reg/s" if vel > 0 else "-", delta=eta, delta_color="off")
            
            politicas_atuais = estado_atual.get("politicas", {})
            if politicas_atuais:
                with st.expander("📊 Radar Top-Down: Decisões de Classificação por Coluna", expanded=True):
                    st.markdown("<small>Acompanhe em tempo real como o motor Aegis classificou o conteúdo.</small>", unsafe_allow_html=True)
                    df_politicas = pd.DataFrame(
                        list(politicas_atuais.items()), 
                        columns=["Nome da Coluna", "Tag de Anonimização"]
                    )
                    st.dataframe(df_politicas, use_container_width=True, hide_index=True)

            time.sleep(2); st.rerun()
        else:
            if "Abortado" in estado_atual.get("fase", ""): st.warning("⚠️ Operação Interrompida com Sucesso e Sem Corromper a Base.")
            elif "Erro" in estado_atual.get("fase", ""): st.error(f"🚨 Falha no Banco: {estado_atual['fase']}")
            else: 
                st.success("✅ Cópia e Mascaramento de Banco de Dados Concluídos com Sucesso!")
                if estado_atual.get("relatorio_performance"):
                    render_painel_relatorio_performance(estado_atual["relatorio_performance"], "📊 Relatório de Performance e Auditoria (Banco de Dados)")
            if st.button("Limpar Histórico de Banco"): limpar_sessao(); st.rerun()
    else:
        st.info("Configure a conexão no menu lateral para iniciar a análise.")

elif st.session_state.view_mode == "Arquivos (.pdf, .csv, .txt)":
    st.markdown("### Processamento de Arquivos em Lote Desacoplado")
    st.markdown("Evita bloqueios na interface e estouros de RAM através de processamento em background (Fatiamento de Chunks).")
    
    if not st.session_state.file_process_started:
        arquivos = st.file_uploader("Upload de Documentos", type=["txt", "csv", "pdf"], accept_multiple_files=True, label_visibility="collapsed")
        
        if arquivos:
            tem_pdf_txt = any(a.name.lower().endswith(('pdf', 'txt')) for a in arquivos)
            tem_csv = any(a.name.lower().endswith('csv') for a in arquivos)

            formato_saida = "Manter Original"
            if tem_pdf_txt:
                escolha = st.radio("Formato de saída para PDFs e Textos:", ["Manter Formato Original", "Converter para PDF (.pdf)", "Extrair como Texto Simples (.txt)"], horizontal=True)
                if escolha == "Converter para PDF (.pdf)": formato_saida = "pdf"
                elif escolha == "Extrair como Texto Simples (.txt)": formato_saida = "txt"

            colunas_ignoradas_csv = []
            if tem_csv:
                try:
                    todas_colunas_unicas = set()
                    for arq in arquivos:
                        if arq.name.lower().endswith('.csv'):
                            amostra = arq.getvalue()[:4096].decode('utf-8', errors='ignore')
                            try: sep_det = csv.Sniffer().sniff(amostra).delimiter
                            except: sep_det = ','
                            
                            arq.seek(0)
                            df_header = pd.read_csv(arq, sep=sep_det, encoding_errors='replace', on_bad_lines='skip', nrows=0)
                            todas_colunas_unicas.update(df_header.columns)
                    
                    if todas_colunas_unicas:
                        st.markdown("#### Mapeamento Global de Exceções (Tabelas CSV)")
                        st.info("⚠️ Selecione as colunas que NÃO devem ser alteradas pela IA em **nenhuma** das tabelas carregadas.")
                        colunas_ignoradas_csv = st.multiselect("Ignorar colunas:", options=sorted(list(todas_colunas_unicas)), default=[])
                except Exception as e:
                    st.warning(f"Não foi possível ler as colunas prévias ({e}).")

            if st.button("🚀 Iniciar Esteira de Blindagem em Lote", type="primary", use_container_width=True):
                st.session_state.file_process_started = True
                payload = [{"name": a.name, "ext": a.name.split('.')[-1].lower(), "bytes": a.getvalue()} for a in arquivos]
                
                save_progress(FILE_STATUS_FILE, "Iniciando Thread Fantasma...", 0, len(payload), 0, 100, 0, 0, False)
                threading.Thread(
                    target=run_files_pipeline_background, 
                    args=(payload, formato_saida, dicionario_regras, colunas_ignoradas_csv, chunk_size_file, n_cores_file), 
                    daemon=True
                ).start()
                time.sleep(1)
                st.rerun()

    if st.session_state.file_process_started:
        estado_arquivos = load_progress(FILE_STATUS_FILE)
        if estado_arquivos:
            if not estado_arquivos.get("finalizado", True):
                st.info("🔄 A esteira de arquivos está rodando em background. A interface está liberada.")
                
                col_a, col_b = st.columns([1, 1])
                with col_a:
                    if st.button("🔄 Atualizar Progresso", type="primary", use_container_width=True): st.rerun()
                with col_b:
                    if st.button("🛑 Abortar Operação", type="secondary", use_container_width=True):
                        with open(ABORT_FILE, "w") as f: f.write("abort")
                        st.warning("Sinal de parada de emergência acionado! Interrompendo motor...")
                        time.sleep(1.5)
                        st.rerun()
                
                progresso_arq = (estado_arquivos['tabelas_processadas'] / max(estado_arquivos['tabelas_total'], 1))
                st.progress(progresso_arq if progresso_arq > 0 else 0.05)
                
                l_proc = estado_arquivos.get("linhas_processadas", 0)
                vel = estado_arquivos.get("velocidade", 0)
                
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Ação Atual", estado_arquivos['fase'])
                c2.metric("Arquivos Concluídos", f"{estado_arquivos['tabelas_processadas']}/{estado_arquivos['tabelas_total']}")
                c3.metric("Linhas do CSV Atual", f"{l_proc:,}")
                c4.metric("Mutação Neural", f"{vel:,.0f} reg/s" if vel > 0 else "-")
                
                time.sleep(2); st.rerun()
            else:
                if "Abortado" in estado_arquivos.get("fase", ""): 
                    st.warning("⚠️ Operação Interrompida com Sucesso. (Nenhum arquivo sobrescrito)")
                elif "Erro" in estado_arquivos.get("fase", ""): 
                    st.error(f"🚨 Falha no Processamento: {estado_arquivos['fase']}")
                else: 
                    st.success("✅ Esteira de Arquivos Concluída com Sucesso!")
                    
                    if os.path.exists("resultado_lote.zip"):
                        with open("resultado_lote.zip", "rb") as f:
                            zip_data = f.read()
                            
                        st.download_button(
                            label="📦 Baixar Lote Blindado (.ZIP)",
                            data=zip_data,
                            file_name="Arquivos_Seguros_Aegis.zip",
                            mime="application/zip",
                            type="primary",
                            use_container_width=True
                        )
                    
                    if estado_arquivos.get("relatorio_performance"):
                        render_painel_relatorio_performance(estado_arquivos["relatorio_performance"], "📊 Relatório de Performance e Auditoria (Arquivos)")
                
                if st.button("🧹 Limpar Painel e Processar Novo Lote"): 
                    limpar_sessao(); st.rerun()

elif st.session_state.view_mode == "Texto Livre":
    st.markdown("### Auditoria Rápida de Fragmentos (Copiar & Colar)")
    
    if "texto_anonimizado_resultado" not in st.session_state:
        st.session_state.texto_anonimizado_resultado = None
    if "relatorio_texto_livre" not in st.session_state:
        st.session_state.relatorio_texto_livre = None

    col1, col2 = st.columns(2)
    
    with col1:
        texto_original = st.text_area(
            "Entrada (Dados Suspeitos)", 
            height=400, 
            placeholder="Cole o laudo policial ou documento aqui..."
        )
        btn_txt = st.button("Injetar Máscaras no Texto", type="primary", use_container_width=True)
        
        if btn_txt and texto_original:
            with st.spinner("Varrendo PIIs e aplicando DLP..."):
                anonymizer.resetar_telemetria()
                st.session_state.texto_anonimizado_resultado = anonymizer.process_raw_text(
                    texto_original, 
                    dicionario_regras
                )
                st.session_state.relatorio_texto_livre = anonymizer.gerar_relatorio_performance(
                    salvar_arquivo=True, 
                    contexto="Texto Livre"
                )

    with col2:
        st.markdown("**Saída (Dados Protegidos)**")
        
        if st.session_state.texto_anonimizado_resultado:
            texto_limpo = st.session_state.texto_anonimizado_resultado
            
            st.caption("📋 Passe o mouse sobre o bloco abaixo e clique no ícone para copiar:")
            st.code(texto_limpo, language="text")
            
            st.divider()
            
            col_down, col_clear = st.columns([2, 1])
            with col_down:
                st.download_button(
                    label="📥 Baixar Texto Anonimizado (.txt)",
                    data=texto_limpo.encode('utf-8'),
                    file_name="texto_anonimizado.txt",
                    mime="text/plain",
                    use_container_width=True
                )
            with col_clear:
                if st.button("🧹 Limpar Resultado", use_container_width=True):
                    st.session_state.texto_anonimizado_resultado = None
                    st.session_state.relatorio_texto_livre = None
                    st.rerun()
        else:
            st.info("Aguardando inserção e processamento de texto no painel à esquerda.")

    if st.session_state.get("relatorio_texto_livre"):
        render_painel_relatorio_performance(st.session_state.relatorio_texto_livre, "📊 Avaliação de Performance e Capacidade (Texto Livre)")