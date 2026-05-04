import os
import json
import re
import shutil
import socket
import hashlib
import subprocess
import threading
import time
import sys

import psutil
import requests
from flask import Flask, send_from_directory, request, jsonify, redirect, session, Response
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ✅ per-user root
USERS_ROOT = os.path.join(BASE_DIR, "USERS")
DATA_DIR = os.path.join(BASE_DIR, "DATA")
USERS_DB = os.path.join(DATA_DIR, "users.json")

os.makedirs(USERS_ROOT, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("PANEL_SECRET_KEY", "CHANGE_ME_" + os.urandom(16).hex())

ADMIN_USERNAME = os.environ.get("ADMIN_USER", "hama")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASS", "1211")

running_procs = {}
server_states = {}
lock = threading.Lock()


# ================= دعم CORS للجميع (حل المشكلة 403) =================
@app.after_request
def add_cors_headers(response):
    """إضافة رؤوس CORS للسماح لجميع المواقع بالوصول"""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response


# معالجة طلبات OPTIONS المسبقة لـ CORS
@app.route('/proxy/<owner>/<folder>', methods=['OPTIONS'])
@app.route('/proxy/<owner>/<folder>/', methods=['OPTIONS'])
@app.route('/proxy/<owner>/<folder>/<path:subpath>', methods=['OPTIONS'])
def handle_options(owner, folder, subpath=""):
    """معالجة طلبات OPTIONS مسبقاً لـ CORS"""
    response = Response()
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    return response


# ================= دعم Railway والمنصات السحابية =================
def get_public_base_url():
    """الحصول على الرابط العام للمنصة"""
    railway_url = os.environ.get("RAILWAY_STATIC_URL")
    if railway_url:
        return f"https://{railway_url}"
    
    render_url = os.environ.get("RENDER_EXTERNAL_URL")
    if render_url:
        return render_url
    
    heroku_url = os.environ.get("HEROKU_APP_NAME")
    if heroku_url:
        return f"https://{heroku_url}.herokuapp.com"
    
    return None


def get_ip():
    """الحصول على IP العام (لمنصات الـ VPS)"""
    try:
        response = requests.get('https://api.ipify.org', timeout=3)
        if response.status_code == 200:
            return response.text
    except:
        pass
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_project_url(owner: str, folder: str, port: int) -> str:
    """
    بناء الرابط الصحيح للمشروع.
    - على Railway: https://اسم-التطبيق.railway.app/proxy/owner/folder
    - على VPS: http://IP:PORT
    """
    public_base = get_public_base_url()
    
    if public_base:
        return f"{public_base}/proxy/{owner}/{folder}"
    else:
        return f"http://{get_ip()}:{port}"


def sanitize_folder_name(name: str) -> str:
    name = (name or "").strip()
    name = re.sub(r"\s+", "-", name)
    name = re.sub(r"[^A-Za-z0-9\-_\.]", "", name)
    return name[:200]


def safe_name(name: str) -> str:
    name = (name or "").strip()
    name = re.sub(r"[\\/]+", "", name)
    name = re.sub(r"[^A-Za-z0-9\-_\. ]", "", name)
    return name[:200].strip()


def set_state(key: str, state: str):
    with lock:
        server_states[key] = state


def get_state(key: str) -> str:
    with lock:
        return server_states.get(key, "Offline")


def log_append(key: str, text: str):
    try:
        owner, folder = parse_server_key(key, allow_admin=True)
        p = os.path.join(get_server_dir(owner, folder), "server.log")
        with open(p, "a", encoding="utf-8", errors="ignore") as f:
            f.write(text)
    except Exception:
        pass


# ---------------------------
# Users DB
# ---------------------------
def load_users():
    if not os.path.exists(USERS_DB):
        return {"users": []}
    try:
        with open(USERS_DB, "r", encoding="utf-8") as f:
            return json.load(f) or {"users": []}
    except Exception:
        return {"users": []}


def save_users(db):
    tmp = USERS_DB + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)
    os.replace(tmp, USERS_DB)


def find_user(db, username: str):
    u = (username or "").strip().lower()
    for x in db.get("users", []):
        if (x.get("username") or "").strip().lower() == u:
            return x
    return None


def is_admin_session():
    u = session.get("user") or {}
    return bool(u.get("is_admin"))


def current_username():
    u = session.get("user") or {}
    return (u.get("username") or "").strip()


def get_user_limit(username: str) -> int:
    if is_admin_session():
        return 999999
    db = load_users()
    u = find_user(db, username)
    if not u:
        return 1
    return 16 if u.get("premium", False) else 1


# ---------------------------
# Auth decorators
# ---------------------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect("/login")
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect("/login")
        if not is_admin_session():
            return jsonify({"success": False, "message": "Admin only"}), 403
        return fn(*args, **kwargs)
    return wrapper


# ---------------------------
# Per-user server directories
# ---------------------------
def get_user_servers_root(username: str) -> str:
    return os.path.join(USERS_ROOT, username, "servers")


def get_server_dir(owner: str, folder: str) -> str:
    return os.path.join(get_user_servers_root(owner), folder)


def ensure_user_dirs(username: str):
    os.makedirs(get_user_servers_root(username), exist_ok=True)


def parse_server_key(key: str, allow_admin: bool):
    key = (key or "").strip()
    if "::" in key:
        owner, folder = key.split("::", 1)
        owner = owner.strip()
        folder = folder.strip()
        if not allow_admin:
            raise ValueError("not allowed")
        if not is_admin_session():
            raise ValueError("forbidden")
        return owner, folder
    return current_username(), key


def can_access_key(key: str) -> bool:
    try:
        owner, folder = parse_server_key(key, allow_admin=True)
    except Exception:
        return False
    if is_admin_session():
        return True
    return owner == current_username()


def safe_join_server_path(key: str, rel_path: str = "") -> str:
    owner, folder = parse_server_key(key, allow_admin=True)
    root = os.path.abspath(get_server_dir(owner, folder))
    rel_path = (rel_path or "").replace("\\", "/").strip()
    if rel_path.startswith("/") or rel_path.startswith("~"):
        rel_path = rel_path.lstrip("/").lstrip("~")
    joined = os.path.abspath(os.path.join(root, rel_path))
    if not (joined == root or joined.startswith(root + os.sep)):
        raise ValueError("Invalid path")
    return joined


# ---------------------------
# Meta per server
# ---------------------------
def ensure_meta(owner: str, folder: str):
    server_dir = get_server_dir(owner, folder)
    os.makedirs(server_dir, exist_ok=True)
    meta_path = os.path.join(server_dir, "meta.json")
    base = {"display_name": folder, "startup_file": "", "owner": owner, "banned": False, "port": 5000, "is_web": False, "public": True}
    if not os.path.exists(meta_path):
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(base, f, indent=2)
    else:
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                m = json.load(f) or {}
        except Exception:
            m = {}
        changed = False
        for k, v in base.items():
            if k not in m:
                m[k] = v
                changed = True
        if m.get("owner") != owner:
            m["owner"] = owner
            changed = True
        if changed:
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(m, f, indent=2)
    return meta_path


def read_meta(owner: str, folder: str):
    ensure_meta(owner, folder)
    meta_path = os.path.join(get_server_dir(owner, folder), "meta.json")
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {"display_name": folder, "startup_file": "", "owner": owner, "banned": False, "port": 5000, "is_web": False, "public": True}


def write_meta(owner: str, folder: str, meta):
    meta_path = os.path.join(get_server_dir(owner, folder), "meta.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


# ---------------------------
# Auto-install system
# ---------------------------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def installed_file_path(owner: str, folder: str):
    return os.path.join(get_server_dir(owner, folder), ".installed")


def read_installed(owner: str, folder: str):
    p = installed_file_path(owner, folder)
    data = {"req_sha": "", "pkgs": set()}
    if not os.path.exists(p):
        return data
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f.read().splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("REQ_SHA="):
                    data["req_sha"] = line.split("=", 1)[1].strip()
                else:
                    data["pkgs"].add(line)
    except Exception:
        pass
    return data


def write_installed(owner: str, folder: str, req_sha=None, add_pkgs=None):
    p = installed_file_path(owner, folder)
    cur = read_installed(owner, folder)
    if req_sha is not None:
        cur["req_sha"] = req_sha
    if add_pkgs:
        cur["pkgs"].update(add_pkgs)
    lines = []
    if cur["req_sha"]:
        lines.append(f"REQ_SHA={cur['req_sha']}")
    lines.extend(sorted(cur["pkgs"]))
    with open(p, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


def ensure_requirements_installed(owner: str, folder: str):
    server_dir = get_server_dir(owner, folder)
    req_path = os.path.join(server_dir, "requirements.txt")
    if not os.path.exists(req_path):
        return False
    req_sha = sha256_file(req_path)
    cur = read_installed(owner, folder)
    if cur["req_sha"] == req_sha:
        return False
    log_append(f"{owner}::{folder}", "[SYSTEM] Installing requirements.txt...\n")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], cwd=server_dir)
        write_installed(owner, folder, req_sha=req_sha)
        log_append(f"{owner}::{folder}", "[SYSTEM] requirements installed ✅\n")
        return True
    except subprocess.CalledProcessError as e:
        log_append(f"{owner}::{folder}", f"[SYSTEM] requirements install failed: {e}\n")
        return False


def start_with_autoinstall(owner: str, folder: str, startup_file: str):
    wrapper_code = r'''
import runpy, sys, subprocess, traceback, re, os
script = sys.argv[1]
cwd = os.getcwd()

def append_installed(pkg):
    try:
        p = os.path.join(cwd, ".installed")
        existing = set()
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                existing = set([x.strip() for x in f.read().splitlines() if x.strip()])
        if pkg and pkg not in existing:
            with open(p, "a", encoding="utf-8") as f:
                f.write(pkg + "\n")
    except:
        pass

def parse_missing_name(e):
    n = getattr(e, "name", None)
    if n: return n
    s = str(e)
    m = re.search(r"No module named '([^']+)'", s)
    if m: return m.group(1)
    return None

while True:
    try:
        runpy.run_path(script, run_name="__main__")
        break
    except ModuleNotFoundError as e:
        pkg = parse_missing_name(e)
        if not pkg:
            traceback.print_exc()
            break
        print(f"[AUTO-INSTALL] Missing module: {pkg} -> installing...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
            append_installed(pkg)
            print(f"[AUTO-INSTALL] Installed: {pkg} ✅ -> restarting...")
            continue
        except Exception as ex:
            print(f"[AUTO-INSTALL] Failed: {ex}")
            traceback.print_exc()
            break
    except Exception:
        traceback.print_exc()
        break
'''
    server_dir = get_server_dir(owner, folder)
    log_path = os.path.join(server_dir, "server.log")
    log_file = open(log_path, "a", encoding="utf-8", errors="ignore")
    proc = subprocess.Popen(
        [sys.executable, "-u", "-c", wrapper_code, startup_file],
        cwd=server_dir,
        stdout=log_file,
        stderr=log_file,
    )
    return proc, log_file


def start_web_project(owner: str, folder: str, startup_file: str):
    """تشغيل مشروع ويب (Flask) مع احترام المنفذ المحفوظ في meta.json"""
    server_dir = get_server_dir(owner, folder)
    startup_path = os.path.join(server_dir, startup_file)
    
    meta = read_meta(owner, folder)
    saved_port = meta.get("port", 0)
    
    if saved_port and saved_port != 5000:
        port = saved_port
        log_append(f"{owner}::{folder}", f"[SYSTEM] ✅ Using saved port from meta.json: {port}\n")
    else:
        port = 5000
        try:
            with open(startup_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                match = re.search(r'port\s*=\s*(\d+)', content)
                if match:
                    port = int(match.group(1))
                match = re.search(r'app\.run\([^)]*port\s*=\s*(\d+)', content)
                if match:
                    port = int(match.group(1))
        except:
            pass
        log_append(f"{owner}::{folder}", f"[SYSTEM] Detected port from file: {port}\n")
    
    meta["port"] = port
    meta["is_web"] = True
    write_meta(owner, folder, meta)
    
    log_path = os.path.join(server_dir, "server.log")
    log_file = open(log_path, "a", encoding="utf-8", errors="ignore")
    
    env = os.environ.copy()
    env["PORT"] = str(port)
    env["FLASK_RUN_HOST"] = "0.0.0.0"
    env["FLASK_APP"] = startup_file
    
    proc = subprocess.Popen(
        [sys.executable, startup_file],
        cwd=server_dir,
        stdout=log_file,
        stderr=log_file,
        env=env
    )
    
    project_url = get_project_url(owner, folder, port)
    log_append(f"{owner}::{folder}", f"[SYSTEM] ✅ Web app starting on port {port}\n")
    log_append(f"{owner}::{folder}", f"[SYSTEM] ✅ Available at: {project_url}\n")
    return proc, log_file


def is_web_project(startup_file_path: str) -> bool:
    try:
        with open(startup_file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            web_indicators = ["Flask", "flask", "app.run", "FastAPI", "Django"]
            return any(indicator in content for indicator in web_indicators)
    except:
        return False


def stop_proc(key: str):
    if key in running_procs:
        proc, logf = running_procs[key]
        try:
            p = psutil.Process(proc.pid)
            for child in p.children(recursive=True):
                child.kill()
            p.kill()
        except Exception:
            pass
        try:
            logf.close()
        except Exception:
            pass
        running_procs.pop(key, None)


def background_start(key: str, owner: str, folder: str, startup_file: str):
    try:
        set_state(key, "Installing")
        log_append(key, "[SYSTEM] Preparing...\n")
        ensure_requirements_installed(owner, folder)
        set_state(key, "Starting")
        log_append(key, "[SYSTEM] Starting...\n")
        
        server_dir = get_server_dir(owner, folder)
        startup_path = os.path.join(server_dir, startup_file)
        
        if is_web_project(startup_path):
            log_append(key, "[SYSTEM] Detected as WEB project (Flask/FastAPI)\n")
            proc, logf = start_web_project(owner, folder, startup_file)
        else:
            log_append(key, "[SYSTEM] Detected as BOT/script\n")
            proc, logf = start_with_autoinstall(owner, folder, startup_file)
        
        running_procs[key] = (proc, logf)
        time.sleep(2.0)
        if proc.poll() is None:
            set_state(key, "Running")
            log_append(key, "[SYSTEM] ✅ Started successfully\n")
        else:
            set_state(key, "Offline")
            log_append(key, f"[SYSTEM] ❌ Process died with code {proc.poll()}\n")
    except Exception as e:
        log_append(key, f"[SYSTEM] ❌ Start failed: {e}\n")
        set_state(key, "Offline")


# =============== Proxy Routes مع دعم الوصول العام ===============
@app.route("/proxy/<owner>/<folder>")
@app.route("/proxy/<owner>/<folder>/")
@app.route("/proxy/<owner>/<folder>/<path:subpath>")
def proxy_project(owner, folder, subpath=""):
    """
    ✅ تم إصلاح مشكلة الوصول: الآن يمكن لأي شخص الدخول إلى المشروع من أي متصفح أو جهاز
    """
    key = f"{owner}::{folder}"
    
    # ✅ التحقق من وجود المشروع
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        response = Response("Project not found", status=404)
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response
    
    meta = read_meta(owner, folder)
    
    # ✅ التحقق من إعدادات الخصوصية (جديد)
    if not meta.get("public", True):
        response = Response("This project is private", status=403)
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response
    
    # التحقق من الحظر من الأدمن فقط (وليس من المصادقة)
    if meta.get("banned", False):
        response = Response("This server has been banned by admin", status=403)
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response
    
    state = get_state(key)
    if state != "Running":
        response = Response(f"Server is not running. Current status: {state}", status=404)
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response
    
    port = meta.get("port", 5000)
    target_url = f"http://localhost:{port}/{subpath}"
    if request.query_string:
        target_url += f"?{request.query_string.decode()}"
    
    try:
        # توجيه الطلب إلى المشروع الداخلي
        headers = {k: v for k, v in request.headers if k.lower() != 'host'}
        
        # تجاهل رأس Cookie للمصادقة (حتى لا يتعارض)
        headers.pop('Cookie', None)
        
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=60  # زيادة المهلة إلى 60 ثانية
        )
        
        # إضافة رؤوس CORS للاستجابة
        response = Response(resp.content, status=resp.status_code, headers=dict(resp.headers))
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        
        return response
        
    except requests.exceptions.ConnectionError:
        response = Response(f"Project not reachable on port {port}. Make sure it's running.", status=502)
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response
    except Exception as e:
        response = Response(f"Proxy error: {e}", status=500)
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response


# ---------------------------
# Pages
# ---------------------------
@app.route("/")
@login_required
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/login")
def login_page():
    return send_from_directory(BASE_DIR, "login.html")


@app.route("/admin")
@login_required
def admin_page():
    if not is_admin_session():
        return redirect("/")
    return send_from_directory(BASE_DIR, "admin.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")


# ---------------------------
# Auth APIs (معدل - بدون create)
# ---------------------------
@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session["user"] = {"username": ADMIN_USERNAME, "is_admin": True}
        return jsonify({"success": True, "is_admin": True})
    
    db = load_users()
    u = find_user(db, username)
    if not u:
        return jsonify({"success": False, "message": "Invalid username or password"}), 401
    if not u.get("active", True):
        return jsonify({"success": False, "message": "Account is banned / inactive"}), 403
    if not check_password_hash(u.get("password_hash", ""), password):
        return jsonify({"success": False, "message": "Invalid username or password"}), 401
    
    session["user"] = {"username": u.get("username"), "is_admin": False}
    ensure_user_dirs(u.get("username"))
    return jsonify({"success": True, "is_admin": False})


# ---------------------------
# Server listing
# ---------------------------
def list_all_servers_for_admin():
    servers = []
    if not os.path.isdir(USERS_ROOT):
        return servers
    for owner in sorted(os.listdir(USERS_ROOT)):
        root = get_user_servers_root(owner)
        if not os.path.isdir(root):
            continue
        for folder in sorted(os.listdir(root)):
            server_dir = get_server_dir(owner, folder)
            if not os.path.isdir(server_dir):
                continue
            meta = read_meta(owner, folder)
            banned = bool(meta.get("banned", False))
            key = f"{owner}::{folder}"
            st = "Banned" if banned else get_state(key)
            servers.append({
                "title": meta.get("display_name", folder),
                "folder": folder,
                "owner": owner,
                "key": key,
                "subtitle": f"Owner: {owner}",
                "startup_file": meta.get("startup_file", ""),
                "status": st,
                "port": meta.get("port", 5000),
                "banned": banned
            })
    return servers


def list_servers_for_user(username: str):
    ensure_user_dirs(username)
    root = get_user_servers_root(username)
    servers = []
    for folder in sorted(os.listdir(root)):
        server_dir = get_server_dir(username, folder)
        if not os.path.isdir(server_dir):
            continue
        meta = read_meta(username, folder)
        banned = bool(meta.get("banned", False))
        key = folder
        st = "Banned" if banned else get_state(key)
        servers.append({
            "title": meta.get("display_name", folder),
            "folder": folder,
            "owner": username,
            "key": key,
            "subtitle": f"Owner: {username}",
            "startup_file": meta.get("startup_file", ""),
            "status": st,
            "port": meta.get("port", 5000)
        })
    return servers


@app.route("/servers")
@login_required
def servers():
    if is_admin_session():
        return jsonify({"success": True, "servers": list_all_servers_for_admin()})
    return jsonify({"success": True, "servers": list_servers_for_user(current_username())})


@app.route("/add", methods=["POST"])
@login_required
def add_server():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    folder = sanitize_folder_name(name)
    if not folder:
        return jsonify({"success": False, "message": "Invalid server name"}), 400
    
    if is_admin_session():
        owner = current_username()
    else:
        owner = current_username()
    
    ensure_user_dirs(owner)
    
    if not is_admin_session():
        limit = get_user_limit(owner)
        existing = [d for d in os.listdir(get_user_servers_root(owner)) if os.path.isdir(get_server_dir(owner, d))]
        if len(existing) >= limit:
            return jsonify({"success": False, "message": f"Server limit reached ({limit}). Ask admin for premium."}), 403
    
    target = get_server_dir(owner, folder)
    if os.path.exists(target):
        return jsonify({"success": False, "message": "Server already exists"}), 409
    
    os.makedirs(target, exist_ok=True)
    open(os.path.join(target, "server.log"), "w", encoding="utf-8").close()
    
    meta = {
        "display_name": name or folder,
        "startup_file": "",
        "owner": owner,
        "banned": False,
        "port": 5000,
        "is_web": False,
        "public": True
    }
    write_meta(owner, folder, meta)
    
    set_state(folder if not is_admin_session() else f"{owner}::{folder}", "Offline")
    
    if is_admin_session():
        return jsonify({"success": True, "servers": list_all_servers_for_admin()})
    return jsonify({"success": True, "servers": list_servers_for_user(owner)})


# ---------------------------
# Server control + stats
# ---------------------------
@app.route("/server/stats/<path:key>")
@login_required
def server_stats(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    
    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"status": "Offline", "cpu": "0%", "mem": "0 MB", "logs": "", "ip": get_ip(), "port": 5000, "url": ""}), 404
    
    meta = read_meta(owner, folder)
    if meta.get("banned", False):
        set_state(key, "Banned")
    
    proc_tuple = running_procs.get(key)
    running = False
    cpu, mem = "0%", "0 MB"
    
    if proc_tuple:
        proc, _logf = proc_tuple
        if psutil.pid_exists(proc.pid):
            try:
                p = psutil.Process(proc.pid)
                if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                    running = True
                    cpu = f"{p.cpu_percent(interval=None)}%"
                    mem = f"{p.memory_info().rss / 1024 / 1024:.1f} MB"
            except Exception:
                pass
    
    log_path = os.path.join(server_dir, "server.log")
    try:
        logs = open(log_path, "r", encoding="utf-8", errors="ignore").read() if os.path.exists(log_path) else ""
    except Exception:
        logs = ""
    
    state = get_state(key)
    if meta.get("banned", False):
        state = "Banned"
    elif running:
        state = "Running"
        set_state(key, "Running")
    elif state not in ("Installing", "Starting"):
        state = "Offline"
        set_state(key, "Offline")
    
    port = meta.get("port", 5000)
    url = get_project_url(owner, folder, port) if state == "Running" else ""
    
    return jsonify({
        "status": state,
        "cpu": cpu,
        "mem": mem,
        "logs": logs,
        "ip": get_ip(),
        "port": port,
        "url": url
    })


@app.route("/server/action/<path:key>/<act>", methods=["POST"])
@login_required
def server_action(key, act):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    
    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"success": False, "message": "Server not found"}), 404
    
    meta = read_meta(owner, folder)
    if meta.get("banned", False):
        set_state(key, "Banned")
        return jsonify({"success": False, "message": "Server is banned by admin"}), 403
    
    if act in ("stop", "restart"):
        stop_proc(key)
        set_state(key, "Offline")
    
    if act == "stop":
        return jsonify({"success": True})
    
    startup = meta.get("startup_file") or ""
    if not startup:
        return jsonify({"success": False, "message": "No main file set"}), 400    
    open(os.path.join(server_dir, "server.log"), "w", encoding="utf-8").close()
    
    t = threading.Thread(target=background_start, args=(key, owner, folder, startup), daemon=True)
    t.start()
    return jsonify({"success": True})


@app.route("/server/set-startup/<path:key>", methods=["POST"])
@login_required
def set_startup(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    
    owner, folder = parse_server_key(key, allow_admin=True)
    data = request.get_json(silent=True) or {}
    f = (data.get("file") or "").strip()
    meta = read_meta(owner, folder)
    meta["startup_file"] = f
    write_meta(owner, folder, meta)
    return jsonify({"success": True})


@app.route("/server/set-port/<path:key>", methods=["POST"])
@login_required
def set_server_port(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    
    data = request.get_json(silent=True) or {}
    new_port = data.get("port")
    if not isinstance(new_port, int) or new_port < 1024 or new_port > 65535:
        return jsonify({"success": False, "message": "Port must be between 1024 and 65535"}), 400
    
    owner, folder = parse_server_key(key, allow_admin=True)
    meta = read_meta(owner, folder)
    meta["port"] = new_port
    write_meta(owner, folder, meta)
    
    if get_state(key) == "Running":
        stop_proc(key)
        set_state(key, "Offline")
        log_append(key, f"[SYSTEM] Port changed to {new_port}. Restart required.\n")
    
    return jsonify({"success": True, "port": new_port})


# ---------------------------
# File manager APIs
# ---------------------------
@app.route("/files/list/<path:key>")
@login_required
def files_list(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden", "path": ""}), 403
    
    rel = request.args.get("path", "") or ""
    try:
        base = safe_join_server_path(key, rel)
    except Exception:
        return jsonify({"success": False, "message": "Invalid path", "path": ""}), 400
    
    dirs, files = [], []
    if os.path.isdir(base):
        for name in sorted(os.listdir(base), key=lambda x: (not os.path.isdir(os.path.join(base, x)), x.lower())):
            if rel == "" and name in ("meta.json", "server.log"):
                continue
            full = os.path.join(base, name)
            if os.path.isdir(full):
                dirs.append({"name": name})
            elif os.path.isfile(full):
                try:
                    size_kb = os.path.getsize(full) / 1024
                    size = f"{size_kb:.1f} KB"
                except Exception:
                    size = ""
                files.append({"name": name, "size": size})
    
    return jsonify({"success": True, "path": rel, "dirs": dirs, "files": files})


@app.route("/files/content/<path:key>")
@login_required
def file_content(key):
    if not can_access_key(key):
        return jsonify({"content": ""}), 403
    file_rel = request.args.get("file", "") or ""
    try:
        full = safe_join_server_path(key, file_rel)
    except Exception:
        return jsonify({"content": ""}), 400
    if os.path.isdir(full):
        return jsonify({"content": ""}), 400
    try:
        with open(full, "r", encoding="utf-8", errors="ignore") as f:
            return jsonify({"content": f.read()})
    except Exception:
        return jsonify({"content": ""})


@app.route("/files/save/<path:key>", methods=["POST"])
@login_required
def file_save(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    
    data = request.get_json(silent=True) or {}
    file_rel = data.get("file", "") or ""
    content = data.get("content", "")
    
    try:
        full = safe_join_server_path(key, file_rel)
    except Exception:
        return jsonify({"success": False, "message": "Invalid path"}), 400
    
    os.makedirs(os.path.dirname(full), exist_ok=True)
    try:
        with open(full, "w", encoding="utf-8") as f:
            f.write(content)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/mkdir/<path:key>", methods=["POST"])
@login_required
def file_mkdir(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    data = request.get_json(silent=True) or {}
    rel = data.get("path", "") or ""
    name = safe_name(data.get("name", ""))
    if not name:
        return jsonify({"success": False, "message": "Bad name"}), 400
    try:
        target = safe_join_server_path(key, os.path.join(rel, name))
        os.makedirs(target, exist_ok=False)
        return jsonify({"success": True})
    except FileExistsError:
        return jsonify({"success": False, "message": "Already exists"}), 409
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/rename/<path:key>", methods=["POST"])
@login_required
def file_rename(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    data = request.get_json(silent=True) or {}
    rel = data.get("path", "") or ""
    old = safe_name(data.get("old", ""))
    new = safe_name(data.get("new", ""))
    if not old or not new:
        return jsonify({"success": False, "message": "Bad name"}), 400
    try:
        src = safe_join_server_path(key, os.path.join(rel, old))
        dst = safe_join_server_path(key, os.path.join(rel, new))
        os.rename(src, dst)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/delete/<path:key>", methods=["POST"])
@login_required
def file_delete(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    data = request.get_json(silent=True) or {}
    rel = data.get("path", "") or ""
    name = safe_name(data.get("name", ""))
    kind = (data.get("kind") or "file").lower()
    if not name:
        return jsonify({"success": False, "message": "Bad name"}), 400
    try:
        target = safe_join_server_path(key, os.path.join(rel, name))
        if kind == "dir":
            shutil.rmtree(target)
        else:
            os.remove(target)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/upload/<path:key>", methods=["POST"])
@login_required
def file_upload(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    
    # قائمة الملفات الممنوعة
    DENIED_EXT = ('.pyc', '.sh', '.exe', '.bat', '.env', '.pem', '.key')
    
    rel = request.args.get("path", "") or ""
    try:
        base_dir = safe_join_server_path(key, rel)
    except Exception:
        return jsonify({"success": False, "message": "Invalid path"}), 400
    os.makedirs(base_dir, exist_ok=True)
    
    files = request.files.getlist("files") or []
    if not files:
        one = request.files.get("file")
        if one:
            files = [one]
    if not files:
        return jsonify({"success": False, "message": "No file"}), 400
    
    relpaths = request.form.getlist("relpaths")
    saved = 0
    
    for i, f in enumerate(files):
        if not f or not f.filename:
            continue
        filename = os.path.basename(f.filename)
        
        # منع رفع الملفات الخطيرة
        if filename.lower().endswith(DENIED_EXT):
            continue
        
        rp = ""
        if relpaths and i < len(relpaths):
            rp = (relpaths[i] or "").replace("\\", "/").lstrip("/")
        
        try:
            if rp:
                target_dir = safe_join_server_path(key, os.path.join(rel, os.path.dirname(rp)))
            else:
                target_dir = base_dir
        except Exception:
            continue
        
        os.makedirs(target_dir, exist_ok=True)
        f.save(os.path.join(target_dir, filename))
        saved += 1
    
    return jsonify({"success": True, "saved": saved})


# ---------------------------
# Admin APIs (معدل - مع إضافة create user)
# ---------------------------
@app.route("/api/admin/servers")
@admin_required
def admin_servers():
    return jsonify({"success": True, "servers": list_all_servers_for_admin()})


@app.route("/api/admin/server/ban", methods=["POST"])
@admin_required
def admin_server_ban():
    data = request.get_json(silent=True) or {}
    folder = (data.get("folder") or "").strip()
    banned = bool(data.get("banned", True))
    
    # البحث عن المالك
    found_owner = None
    if os.path.isdir(USERS_ROOT):
        for owner in os.listdir(USERS_ROOT):
            server_dir = get_server_dir(owner, folder)
            if os.path.isdir(server_dir):
                found_owner = owner
                break
    
    if not found_owner:
        return jsonify({"success": False, "message": "Server not found"}), 404
    
    meta = read_meta(found_owner, folder)
    meta["banned"] = banned
    write_meta(found_owner, folder, meta)
    
    key = f"{found_owner}::{folder}"
    if banned:
        stop_proc(key)
        set_state(key, "Banned")
        log_append(key, "[ADMIN] Server banned.\n")
    else:
        set_state(key, "Offline")
        log_append(key, "[ADMIN] Server unbanned.\n")
    return jsonify({"success": True})


@app.route("/api/admin/users")
@admin_required
def admin_users():
    db = load_users()
    counts = {}
    if os.path.isdir(USERS_ROOT):
        for owner in os.listdir(USERS_ROOT):
            root = get_user_servers_root(owner)
            if os.path.isdir(root):
                counts[owner] = len([d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))])
    
    users = []
    for u in db.get("users", []):
        users.append({
            "username": u.get("username"),
            "email": u.get("email"),
            "active": bool(u.get("active", True)),
            "premium": bool(u.get("premium", False)),
            "servers": counts.get(u.get("username") or "", 0),
        })
    return jsonify({"success": True, "users": users})


@app.route("/api/admin/user/create", methods=["POST"])
@admin_required
def admin_user_create():
    """إنشاء مستخدم جديد بواسطة الأدمن"""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    premium = bool(data.get("premium", False))
    
    # التحقق من صحة البيانات
    if not username or len(username) < 3:
        return jsonify({"success": False, "message": "Username must be at least 3 chars"}), 400
    if not re.fullmatch(r"[A-Za-z0-9_\.]+", username):
        return jsonify({"success": False, "message": "Username allowed: letters, numbers, _ and ."}), 400
    if username.upper() == ADMIN_USERNAME.upper():
        return jsonify({"success": False, "message": "This username is reserved"}), 400
    if not email or "@" not in email:
        return jsonify({"success": False, "message": "Enter a valid email"}), 400
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 chars"}), 400
    
    db = load_users()
    if find_user(db, username):
        return jsonify({"success": False, "message": "Username already exists"}), 409
    
    db["users"].append({
        "username": username,
        "email": email,
        "password_hash": generate_password_hash(password),
        "active": True,
        "premium": premium
    })
    save_users(db)
    ensure_user_dirs(username)
    
    return jsonify({"success": True, "message": f"User {username} created successfully"})


@app.route("/api/admin/user/update", methods=["POST"])
@admin_required
def admin_user_update():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"success": False, "message": "Username required"}), 400
    db = load_users()
    u = find_user(db, username)
    if not u:
        return jsonify({"success": False, "message": "User not found"}), 404
    if "active" in data:
        u["active"] = bool(data["active"])
    if "premium" in data:
        u["premium"] = bool(data["premium"])
    save_users(db)
    return jsonify({"success": True})


@app.route("/api/admin/quickstats")
@admin_required
def admin_quickstats():
    total_servers = 0
    running = 0
    installing = 0
    banned = 0
    
    for s in list_all_servers_for_admin():
        total_servers += 1
        if s.get("status") == "Banned":
            banned += 1
        elif s.get("status") == "Running":
            running += 1
        elif s.get("status") in ("Installing", "Starting"):
            installing += 1
    
    db = load_users()
    total_users = len(db.get("users", []))
    active_users = sum(1 for u in db.get("users", []) if u.get("active", True))
    premium_users = sum(1 for u in db.get("users", []) if u.get("premium", False))
    
    return jsonify({"success": True, "stats": {
        "servers_total": total_servers,
        "servers_running": running,
        "servers_installing": installing,
        "servers_banned": banned,
        "users_total": total_users,
        "users_active": active_users,
        "users_premium": premium_users
    }})


if __name__ == "__main__":
    # دعم منفذ Railway
    port = int(os.environ.get("PORT", os.environ.get("SERVER_PORT", 3034)))
    public_url = get_public_base_url()
    if public_url:
        print(f"\n🚀 RAGNAR HOST RUNNING ON RAILWAY")
        print(f"📍 Main URL: {public_url}")
        print(f"📍 Proxy URL: {public_url}/proxy/username/folder")
    else:
        print(f"\n🚀 RAGNAR HOST RUNNING ON {get_ip()}:{port}")
    print(f"✅ CORS enabled for all origins")
    print(f"✅ All proxy routes support public access (no login required)")
    print(f"✅ Admin can create users from /admin panel")
    print(f"✅ Self-registration disabled\n")
    app.run(host="0.0.0.0", port=port)
