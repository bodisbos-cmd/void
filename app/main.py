from __future__ import annotations
import asyncio, base64, hashlib, hmac, io, json, logging, os, secrets, shutil, sqlite3, subprocess, time, uuid
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone, timedelta
from html import escape as html_escape
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit
import qrcode
from qrcode.image.svg import SvgPathImage
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from itsdangerous import BadSignature
from starlette.background import BackgroundTask
from starlette.datastructures import MutableHeaders
from starlette.middleware.sessions import SessionMiddleware

APP_NAME="Void"
PROFILES=[
    {"key":"ws","label":"WebSocket","network":"ws","path":"/ws","port":10001,"mode":None},
    {"key":"httpupgrade","label":"HTTPUpgrade","network":"httpupgrade","path":"/httpupgrade","port":10002,"mode":None},
    {"key":"xhttp_auto","label":"XHTTP · auto","network":"xhttp","path":"/xhttp","port":10003,"mode":"auto"},
    {"key":"xhttp_packet_up","label":"XHTTP · packet-up","network":"xhttp","path":"/xhttp-packet","port":10004,"mode":"packet-up"},
    {"key":"xhttp_stream_up","label":"XHTTP · stream-up · آزمایشی","network":"xhttp","path":"/xhttp-stream-up","port":10005,"mode":"stream-up","experimental":True},
    {"key":"xhttp_stream_one","label":"XHTTP · stream-one · آزمایشی","protocol":"vless","network":"xhttp","path":"/xhttp-stream-one","port":10006,"mode":"stream-one","experimental":True},
    {"key":"trojan_ws","label":"Trojan · WebSocket TLS","protocol":"trojan","network":"ws","path":"/trojan-ws","port":10007,"mode":None},
    {"key":"vmess_ws","label":"VMess · WebSocket TLS","protocol":"vmess","network":"ws","path":"/vmess-ws","port":10008,"mode":None},
    {"key":"ws_alt","label":"WebSocket · مسیر جایگزین","network":"ws","path":"/connect","port":10010,"mode":None,"subscription_label":"vless-ws-alt"},
    {"key":"httpupgrade_alt","label":"HTTPUpgrade · مسیر جایگزین","network":"httpupgrade","path":"/upgrade","port":10011,"mode":None,"subscription_label":"vless-httpupgrade-alt"},
    {"key":"xhttp_stream_up_alt","label":"XHTTP · stream-up · مسیر جایگزین · آزمایشی","network":"xhttp","path":"/xhttp-stream-up-alt","port":10012,"mode":"stream-up","experimental":True,"subscription_label":"xhttp-stream-up-alt"},
    {"key":"xhttp_stream_one_alt","label":"XHTTP · stream-one · مسیر جایگزین · آزمایشی","network":"xhttp","path":"/xhttp-stream-one-alt","port":10013,"mode":"stream-one","experimental":True,"subscription_label":"xhttp-stream-one-alt"},
    {"key":"ss_ws","label":"Shadowsocks 2022 · WebSocket TLS","protocol":"shadowsocks","network":"ws","path":"/ss-ws","port":10009,"mode":None},
]
DATA_DIR=Path(os.getenv("DATA_DIR","/data")); DATA_DIR.mkdir(parents=True,exist_ok=True)
DB_PATH=DATA_DIR/"panel.sqlite3"; XRAY_CONFIG=DATA_DIR/"xray.json"
XRAY_BIN=os.getenv("XRAY_BIN","/usr/local/bin/xray"); PUBLIC_DOMAIN=os.getenv("RAILWAY_PUBLIC_DOMAIN","").strip()
BASE_URL=os.getenv("BASE_URL","").strip().rstrip("/")
LOG=logging.getLogger("void"); logging.basicConfig(level=os.getenv("LOG_LEVEL","INFO").upper())
xray_proc=None; xray_lock=asyncio.Lock(); restore_lock=asyncio.Lock()

def utc_now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
@contextmanager
def db():
    """Open one short-lived SQLite unit of work and always close its connection."""
    DATA_DIR.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(DB_PATH,timeout=30,isolation_level="DEFERRED")
    c.row_factory=sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=30000")
    try:
        yield c
        c.commit()
    except BaseException:
        c.rollback()
        raise
    finally:
        c.close()
def password_hash(password,salt=None):
    salt=salt or secrets.token_bytes(16); digest=hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1,dklen=32)
    return f"scrypt${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"
def verify_password(password,encoded):
    try:
        scheme,salt,expected=encoded.split("$",2)
        if scheme!="scrypt": return False
        actual=password_hash(password,base64.urlsafe_b64decode(salt)).split("$",2)[2]
        return hmac.compare_digest(actual,expected)
    except (ValueError,TypeError): return False
def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY CHECK(id=1),password_hash TEXT NOT NULL,password_changed_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS panel_admins(id TEXT PRIMARY KEY,username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('owner','admin','viewer')),enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,password_changed_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS clients(id TEXT PRIMARY KEY,name TEXT NOT NULL,client_uuid TEXT NOT NULL UNIQUE,sub_token TEXT NOT NULL UNIQUE,enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,note TEXT NOT NULL DEFAULT '',expires_at TEXT,quota_bytes INTEGER,used_bytes INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS resellers(id TEXT PRIMARY KEY,username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,quota_bytes INTEGER NOT NULL CHECK(quota_bytes>0),enabled INTEGER NOT NULL DEFAULT 1,parent_id TEXT,created_at TEXT NOT NULL,FOREIGN KEY(parent_id) REFERENCES resellers(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,at TEXT NOT NULL,level TEXT NOT NULL,message TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS profile_feedback(id INTEGER PRIMARY KEY AUTOINCREMENT,client_id TEXT NOT NULL,carrier TEXT NOT NULL,profile_key TEXT NOT NULL,result TEXT NOT NULL CHECK(result IN ('ok','fail')),created_at TEXT NOT NULL,user_agent TEXT NOT NULL DEFAULT '',UNIQUE(client_id,carrier,profile_key));
        CREATE TABLE IF NOT EXISTS metrics_history(
            sampled_at INTEGER PRIMARY KEY,
            recorded_traffic_bytes INTEGER NOT NULL DEFAULT 0,
            cpu_percent REAL,
            memory_used_percent REAL
        );
        CREATE INDEX IF NOT EXISTS idx_metrics_history_sampled_at ON metrics_history(sampled_at DESC);
        CREATE TABLE IF NOT EXISTS client_usage_history(client_id TEXT NOT NULL,sampled_at INTEGER NOT NULL,used_bytes INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(client_id,sampled_at));
        CREATE INDEX IF NOT EXISTS idx_client_usage_history_sampled_at ON client_usage_history(client_id,sampled_at DESC);
        CREATE INDEX IF NOT EXISTS idx_profile_feedback_carrier ON profile_feedback(carrier,profile_key,created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_clients_created ON clients(created_at DESC);
        """)
        if not c.execute("SELECT id FROM admins WHERE id=1").fetchone():
            # Preserve admin/admin for local development, but fail closed on production installs.
            # A public deployment must provide its own non-default bootstrap secret.
            env_names=("APP_ENV","ENVIRONMENT","RAILWAY_ENVIRONMENT_NAME")
            production_mode=(
                any(os.getenv(k,"").strip().lower() in ("production","prod") for k in env_names)
                or bool(os.getenv("RAILWAY_PROJECT_ID") and os.getenv("RAILWAY_SERVICE_ID"))
            )
            pw=os.getenv("ABYSS_INITIAL_ADMIN_PASSWORD","").strip()
            if production_mode and (len(pw) < 16 or pw.lower() in ("admin","password","12345678","changeme")):
                raise RuntimeError("Set a strong, unique ABYSS_INITIAL_ADMIN_PASSWORD before starting a production installation.")
            if not pw:
                pw="admin"
            changed=utc_now()
            c.execute("INSERT INTO admins VALUES(1,?,?)",(password_hash(pw),changed))
            p=DATA_DIR/"INITIAL_ADMIN_PASSWORD.txt"; p.write_text(f"Username: admin\nPassword: {pw}\n",encoding="utf-8")
            try: p.chmod(0o600)
            except OSError: pass
            LOG.warning("Initial administrator credential saved to %s; change it after signing in",p)
        # Migrate the existing single-admin credential without changing its password.
        legacy=c.execute("SELECT password_hash,password_changed_at FROM admins WHERE id=1").fetchone()
        if legacy and not c.execute("SELECT id FROM panel_admins WHERE username='admin'").fetchone():
            c.execute("INSERT INTO panel_admins(id,username,password_hash,role,enabled,created_at,password_changed_at) VALUES(?,?,?,?,1,?,?)",
                ("owner-admin","admin",legacy["password_hash"],"owner",legacy["password_changed_at"],legacy["password_changed_at"]))
        # The bootstrap file is only a first-login record. Do not reset the password
        # from it on restart: the administrator may already have changed credentials.
        initial_file=DATA_DIR/"INITIAL_ADMIN_PASSWORD.txt"
        if initial_file.exists():
            try: initial_file.chmod(0o600)
            except OSError: pass
        # Safe in-place migration for persistent databases created by older releases.
        cols={row["name"] for row in c.execute("PRAGMA table_info(clients)")}
        for name, declaration in (("expires_at","TEXT"),("quota_bytes","INTEGER"),("used_bytes","INTEGER NOT NULL DEFAULT 0"),("profile_keys","TEXT")):
            if name not in cols: c.execute(f"ALTER TABLE clients ADD COLUMN {name} {declaration}")
        if "owner_id" not in cols: c.execute("ALTER TABLE clients ADD COLUMN owner_id TEXT")
        c.execute("CREATE INDEX IF NOT EXISTS idx_clients_owner ON clients(owner_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_resellers_parent ON resellers(parent_id)")
        c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('created_at',?)",(utc_now(),))
def event(level,message):
    LOG.log(getattr(logging,level.upper(),logging.INFO),message)
    try:
        with db() as c:
            c.execute("INSERT INTO events(at,level,message) VALUES(?,?,?)",(utc_now(),level.upper(),message[:500]))
            c.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 250)")
    except Exception: LOG.exception("event storage failed")
def get_clients(include_client_uuid=False, owner_id=None, scoped=False):
    cols="id,name,client_uuid,enabled,created_at,note,expires_at,quota_bytes,used_bytes,owner_id,profile_keys" if include_client_uuid else "id,name,enabled,created_at,note,expires_at,quota_bytes,used_bytes,owner_id,profile_keys"
    with db() as c:
        if scoped: return [dict(r) for r in c.execute(f"SELECT {cols} FROM clients WHERE owner_id=? ORDER BY created_at DESC",(owner_id,))]  # nosec B608: cols is a fixed allowlisted projection
        return [dict(r) for r in c.execute(f"SELECT {cols} FROM clients ORDER BY created_at DESC")]  # nosec B608: cols is a fixed allowlisted projection
def get_profile_flags():
    with db() as c:
        saved={row["key"]:row["value"] for row in c.execute("SELECT key,value FROM settings WHERE key LIKE 'profile:%'")}
    return {p["key"]:saved.get("profile:"+p["key"],"0" if p.get("experimental") else "1")=="1" for p in PROFILES}

def get_ss2022_server_password():
    with db() as c:
        row=c.execute("SELECT value FROM settings WHERE key='ss2022_server_password'").fetchone()
        if row: return row["value"]
        generated=base64.b64encode(secrets.token_bytes(16)).decode()
        c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('ss2022_server_password',?)",(generated,))
        return c.execute("SELECT value FROM settings WHERE key='ss2022_server_password'").fetchone()["value"]

def client_is_expired(expires_at):
    if not expires_at:
        return False
    try:
        value=str(expires_at).replace("Z","+00:00")
        expiry=datetime.fromisoformat(value)
        if expiry.tzinfo is None:
            expiry=expiry.replace(tzinfo=timezone.utc)
        return expiry <= datetime.now(timezone.utc)
    except (TypeError,ValueError):
        # Fail closed on corrupt expiry metadata.
        return True

def client_is_active(client):
    if not client.get("enabled"):
        return False
    if client_is_expired(client.get("expires_at")):
        return False
    quota=client.get("quota_bytes")
    return quota is None or int(client.get("used_bytes") or 0) < int(quota)

def valid_name(name:Any):
    if not isinstance(name,str): raise HTTPException(422,"Client name must be text")
    name=" ".join(name.strip().split())
    if not name or len(name)>64 or any(ord(x)<32 for x in name): raise HTTPException(422,"Client name must be 1–64 printable characters")
    return name
def make_xray_config():
    all_clients=[x for x in get_clients(True) if client_is_active(x)]
    ins=[{"tag":"api","listen":"127.0.0.1","port":10085,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":10085,"network":"tcp"}}]
    flags=get_profile_flags()
    for profile in PROFILES:
        if not flags[profile["key"]]: continue
        port,network,path=profile["port"],profile["network"],profile["path"]
        profile_clients=[]
        for client in all_clients:
            try: selected=json.loads(client.get("profile_keys") or "null")
            except (TypeError,ValueError): selected=None
            if selected is None or profile["key"] in selected:
                profile_clients.append({"id":client["client_uuid"],"email":f"client-{client['id']}"})
        clients=profile_clients
        stream={"network":network,"security":"none"}
        stream[{"ws":"wsSettings","httpupgrade":"httpupgradeSettings","xhttp":"xhttpSettings"}[network]]={"path":path,**({"mode":profile["mode"]} if profile["mode"] else {})}
        protocol=profile.get("protocol","vless")
        if protocol=="vless":
            settings={"clients":clients,"decryption":"none"}
        elif protocol=="trojan":
            settings={"clients":[{"password":x["id"],"email":x["email"]} for x in clients]}
        elif protocol=="vmess":
            settings={"clients":[{"id":x["id"],"alterId":0,"email":x["email"]} for x in clients]}
        elif protocol=="shadowsocks":
            ss_clients=[{"password":base64.b64encode(hashlib.sha256(x["id"].encode()).digest()[:16]).decode(),"email":x["email"]} for x in clients]
            settings={"method":"2022-blake3-aes-128-gcm","password":get_ss2022_server_password(),"network":"tcp","clients":ss_clients}
        else:
            raise ValueError("Unsupported profile protocol: "+protocol)
        inbound={"tag":f"in-{profile['key']}","listen":"127.0.0.1","port":port,"protocol":protocol,"settings":settings,"streamSettings":stream}
        ins.append(inbound)
    return {"log":{"loglevel":"debug" if os.getenv("ABYSS_TEST_MODE")=="1" else "warning"},"api":{"tag":"api","services":["StatsService"]},"stats":{},"policy":{"levels":{"0":{"statsUserUplink":True,"statsUserDownlink":True}}},"inbounds":ins,"outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"block"},{"protocol":"freedom","tag":"api"}],"routing":{"domainStrategy":"AsIs","rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"}]}}
def validate_and_write_xray():
    tmp=XRAY_CONFIG.with_suffix(".tmp"); tmp.write_text(json.dumps(make_xray_config(),indent=2),encoding="utf-8"); tmp.replace(XRAY_CONFIG)
    if Path(XRAY_BIN).exists():
        r=subprocess.run([XRAY_BIN,"run","-test","-config",str(XRAY_CONFIG)],capture_output=True,text=True,timeout=15)
        if r.returncode: raise RuntimeError("Xray configuration test failed: "+(r.stderr or r.stdout)[-1000:])
async def start_xray():
    global xray_proc
    async with xray_lock:
        validate_and_write_xray()
        if not Path(XRAY_BIN).exists(): event("WARNING","Xray is not installed; control dashboard remains available."); return
        if xray_proc and xray_proc.poll() is None:
            # Flush counters before every Xray restart so client create/pause/edit
            # operations do not silently discard traffic accumulated since the last poll.
            try: apply_xray_stats(read_xray_stats())
            except Exception as e: event("WARNING",f"Could not flush Xray usage before restart: {e}")
            xray_proc.terminate()
            try: xray_proc.wait(timeout=4)
            except subprocess.TimeoutExpired: xray_proc.kill()
        err=open(DATA_DIR/"xray-stderr.log","ab")
        try: xray_proc=subprocess.Popen([XRAY_BIN,"run","-config",str(XRAY_CONFIG)],stdout=err,stderr=err)
        finally: err.close()
        await asyncio.sleep(.25)
        if xray_proc.poll() is not None: raise RuntimeError("Xray exited; inspect /data/xray-stderr.log")
def read_xray_stats():
    if not Path(XRAY_BIN).exists(): return {}
    result=subprocess.run([XRAY_BIN,"api","statsquery","--server=127.0.0.1:10085","--pattern","user>>>client-","--reset"],capture_output=True,text=True,timeout=8)
    if result.returncode: raise RuntimeError((result.stderr or result.stdout)[-500:])
    try: payload=json.loads(result.stdout)
    except json.JSONDecodeError: raise RuntimeError("Xray stats API returned invalid JSON")
    stats={}
    for item in payload.get("stat",payload.get("stats",[])):
        name=str(item.get("name","")); value=int(item.get("value",0))
        # user>>>client-<client UUID>>>traffic>>>uplink/downlink
        bits=name.split(">>>")
        if len(bits)>=4 and bits[0]=="user" and bits[1].startswith("client-") and bits[2]=="traffic":
            cid=bits[1].removeprefix("client-")
            stats.setdefault(cid,0); stats[cid]+=max(0,value)
    return stats

def apply_xray_stats(stats):
    if not stats: return
    with db() as c:
        for key,delta in stats.items():
            if delta<=0: continue
            # Accept legacy 8-character emails during a rolling upgrade, but
            # use the full UUID for new Xray stats to avoid prefix collisions.
            if len(key)==8:
                c.execute("UPDATE clients SET used_bytes=used_bytes+? WHERE substr(id,1,8)=?",(int(delta),key))
            else:
                c.execute("UPDATE clients SET used_bytes=used_bytes+? WHERE id=?",(int(delta),key))

CLIENT_USAGE_HISTORY_SAMPLE_SECONDS=3600
CLIENT_USAGE_HISTORY_RETENTION_SECONDS=90*86400

def record_client_usage_history(now=None, client_id=None):
    """Store hourly per-client cumulative usage, never the panel-wide total."""
    now=int(time.time() if now is None else now)
    with db() as c:
        if client_id is None:
            rows=c.execute(
                "SELECT c.id,c.used_bytes,(SELECT MAX(h.sampled_at) FROM client_usage_history h WHERE h.client_id=c.id) AS last_sampled_at FROM clients c"
            ).fetchall()
        else:
            rows=c.execute(
                "SELECT c.id,c.used_bytes,(SELECT MAX(h.sampled_at) FROM client_usage_history h WHERE h.client_id=c.id) AS last_sampled_at FROM clients c WHERE c.id=?",
                (client_id,)
            ).fetchall()
        for row in rows:
            last=row["last_sampled_at"]
            if last is None or now-int(last)>=CLIENT_USAGE_HISTORY_SAMPLE_SECONDS:
                c.execute(
                    "INSERT OR REPLACE INTO client_usage_history(client_id,sampled_at,used_bytes) VALUES(?,?,?)",
                    (row["id"],now,max(0,int(row["used_bytes"] or 0)))
                )
        c.execute(
            "DELETE FROM client_usage_history WHERE sampled_at < ?",
            (now-CLIENT_USAGE_HISTORY_RETENTION_SECONDS,)
        )
        c.execute("DELETE FROM client_usage_history WHERE client_id NOT IN (SELECT id FROM clients)")

def get_client_usage_history(client_id, days=90, now=None):
    now=int(time.time() if now is None else now)
    days=max(1,min(90,int(days)))
    try:
        record_client_usage_history(now=now,client_id=client_id)
        with db() as c:
            rows=c.execute(
                "SELECT sampled_at,used_bytes FROM client_usage_history WHERE client_id=? AND sampled_at>=? ORDER BY sampled_at",
                (client_id,now-days*86400)
            ).fetchall()
        return [{"at":int(row["sampled_at"]),"used_bytes":max(0,int(row["used_bytes"] or 0))} for row in rows]
    except Exception as e:
        try: event("WARNING",f"Usage history unavailable for client {str(client_id)[:8]}: {e}")
        except Exception: pass
        return []

async def enforce_client_limits():
    # Expiry and already-recorded quota enforcement must continue even while
    # Xray is down; only the live counter query depends on a running process.
    if Path(XRAY_BIN).exists() and xray_proc and xray_proc.poll() is None:
        stats=read_xray_stats()
        apply_xray_stats(stats)
    try:
        record_client_usage_history()
    except Exception as e:
        try: event("WARNING",f"Client usage history sample failed: {e}")
        except Exception: pass
    auto_disabled=[]
    with db() as c:
        rows=[dict(x) for x in c.execute("SELECT id,name,enabled,expires_at,quota_bytes,used_bytes FROM clients")]
        for row in rows:
            if not row["enabled"]: continue
            expired=client_is_expired(row["expires_at"])
            exhausted=bool(row["quota_bytes"] is not None and int(row["used_bytes"] or 0)>=int(row["quota_bytes"]))
            if expired or exhausted:
                c.execute("UPDATE clients SET enabled=0 WHERE id=?",(row["id"],))
                auto_disabled.append((row["name"],"expired" if expired else "quota reached"))
    # Log after closing the database transaction to avoid nested SQLite writers.
    for name,reason in auto_disabled:
        event("INFO",f"Client {name!r} automatically disabled: {reason}.")
    # Apply any auto-disabled clients to Xray once, but do not prevent the DB
    # enforcement from completing if the engine is currently unavailable.
    if auto_disabled and Path(XRAY_BIN).exists():
        try:
            await start_xray()
        except Exception as e:
            event("ERROR",f"Could not apply automatically disabled clients to Xray: {e}")

async def monitor():
    while True:
        await asyncio.sleep(10)
        if Path(XRAY_BIN).exists() and (xray_proc is None or xray_proc.poll() is not None):
            try: event("WARNING","Restarting stopped Xray process."); await start_xray()
            except Exception as e: event("ERROR",f"Xray recovery failed: {e}")
        try: await enforce_client_limits()
        except Exception as e: event("ERROR",f"Client usage/expiry monitor failed: {e}")
@asynccontextmanager
async def lifespan(app):
    init_db()
    try: await start_xray()
    except Exception as e: event("ERROR",f"Xray startup failed: {e}")
    task=asyncio.create_task(monitor()); yield; task.cancel()
    if xray_proc and xray_proc.poll() is None: xray_proc.terminate()
app=FastAPI(title=APP_NAME,docs_url=None,redoc_url=None,openapi_url=None,lifespan=lifespan)

@app.get("/brand-logo", include_in_schema=False)
async def brand_logo():
    logo_path=Path(__file__).with_name("abyss-tunnel-logo.jpg")
    if not logo_path.is_file():
        raise HTTPException(status_code=404,detail="Logo asset not found")
    return FileResponse(logo_path,media_type="image/jpeg",headers={"Cache-Control":"public, max-age=86400"})

class RememberMeSessionMiddleware(SessionMiddleware):
    """Use a session cookie by default; remember-me sessions expire after 30 days."""

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await super().__call__(scope, receive, send)
            return

        initial_session_was_empty = True
        raw_cookie = Request(scope).cookies.get(self.session_cookie)
        if raw_cookie:
            try:
                signed = raw_cookie.encode("utf-8")
                unpacked = self.signer.unsign(signed)
                candidate = json.loads(base64.b64decode(unpacked))
                max_age = 30 * 24 * 60 * 60 if isinstance(candidate, dict) and candidate.get("remember_me") is True else 8 * 60 * 60
                verified = self.signer.unsign(signed, max_age=max_age)
                decoded = json.loads(base64.b64decode(verified))
                scope["session"] = decoded if isinstance(decoded, dict) else {}
                initial_session_was_empty = False
            except (BadSignature, ValueError, TypeError, UnicodeDecodeError):
                scope["session"] = {}
        else:
            scope["session"] = {}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                if scope["session"]:
                    data = base64.b64encode(json.dumps(scope["session"]).encode("utf-8"))
                    data = self.signer.sign(data)
                    max_age = "Max-Age=2592000; " if scope["session"].get("remember_me") is True else ""
                    header_value = f"{self.session_cookie}={data.decode('utf-8')}; path={self.path}; {max_age}{self.security_flags}"
                    headers = MutableHeaders(scope=message)
                    headers.append("Set-Cookie", header_value)
                elif not initial_session_was_empty:
                    header_value = f"{self.session_cookie}=null; path={self.path}; expires=Thu, 01 Jan 1970 00:00:00 GMT; {self.security_flags}"
                    headers = MutableHeaders(scope=message)
                    headers.append("Set-Cookie", header_value)
            await send(message)

        await self.app(scope, receive, send_wrapper)

sf=DATA_DIR/".session_secret"
if not sf.exists():
    sf.write_text(secrets.token_urlsafe(48),encoding="ascii")
    try: sf.chmod(0o600)
    except OSError: pass
app.add_middleware(RememberMeSessionMiddleware,secret_key=sf.read_text().strip(),session_cookie="abyss_session",max_age=28800,same_site="strict",https_only=os.getenv("COOKIE_SECURE","1")!="0")
@app.middleware("http")
async def headers(request,call_next):
    r=await call_next(request); r.headers["X-Content-Type-Options"]="nosniff"; r.headers["X-Frame-Options"]="DENY"; r.headers["Referrer-Policy"]="no-referrer"; return r
def require_admin(r):
    if r.session.get("admin") is True:
        admin_id=r.session.get("admin_id","owner-admin")
        with db() as c:
            account=c.execute("SELECT role,enabled,password_changed_at FROM panel_admins WHERE id=?",(admin_id,)).fetchone()
        if not account or not account["enabled"]:
            r.session.clear()
            raise HTTPException(401,"Administrator account is disabled or no longer exists")
        if r.session.get("admin_password_changed_at") != account["password_changed_at"]:
            r.session.clear()
            raise HTTPException(401,"Administrator password changed; please sign in again")
        r.session["admin_role"]=account["role"]
        return
    rid=r.session.get("reseller_id")
    if not rid: raise HTTPException(401,"Authentication required")
    with db() as c:
        current=c.execute("SELECT id,enabled,parent_id FROM resellers WHERE id=?",(rid,)).fetchone()
        if not current or not current["enabled"]:
            r.session.clear()
            raise HTTPException(401,"Reseller account is disabled")
        parent_id=current["parent_id"]
        while parent_id:
            parent=c.execute("SELECT id,enabled,parent_id FROM resellers WHERE id=?",(parent_id,)).fetchone()
            if not parent or not parent["enabled"]:
                r.session.clear()
                raise HTTPException(401,"Parent reseller account is disabled")
            parent_id=parent["parent_id"]
def require_role(r,*roles):
    require_admin(r)
    role=r.session.get("admin_role","owner") if r.session.get("admin") is True else "reseller"
    if role not in roles: raise HTTPException(403,"Insufficient permissions")
def is_root(r): return r.session.get("admin") is True and r.session.get("admin_role","owner")=="owner"
def owner_id_for(r):
    if r.session.get("admin") is True: return None
    return str(r.session.get("reseller_id",""))
def require_root(r):
    require_role(r,"owner")
def require_client_access(r,cid):
    if is_root(r): return
    with db() as c: row=c.execute("SELECT owner_id FROM clients WHERE id=?",(cid,)).fetchone()
    if not row or row["owner_id"] != owner_id_for(r): raise HTTPException(404,"Client not found")
def reseller_allocated(c,rid):
    a=c.execute("SELECT COALESCE(SUM(quota_bytes),0) n FROM clients WHERE owner_id=?",(rid,)).fetchone()["n"]
    b=c.execute("SELECT COALESCE(SUM(quota_bytes),0) n FROM resellers WHERE parent_id=?",(rid,)).fetchone()["n"]
    return int(a or 0)+int(b or 0)
def reseller_remaining(rid):
    with db() as c:
        row=c.execute("SELECT quota_bytes,enabled FROM resellers WHERE id=?",(rid,)).fetchone()
        if not row or not row["enabled"]: raise HTTPException(403,"Reseller account is disabled")
        return int(row["quota_bytes"])-reseller_allocated(c,rid)
def reseller_allocated_for(rid):
    with db() as c:
        return reseller_allocated(c,rid)
def assert_reseller_chain_enabled(c,rid):
    current_id=rid
    seen=set()
    while current_id:
        if current_id in seen:
            raise HTTPException(403,"Invalid reseller hierarchy")
        seen.add(current_id)
        row=c.execute("SELECT enabled,parent_id FROM resellers WHERE id=?",(current_id,)).fetchone()
        if not row or not row["enabled"]:
            raise HTTPException(403,"Reseller account or parent is disabled")
        current_id=row["parent_id"]
def require_csrf(r,allow_viewer=False):
    require_admin(r)
    if not allow_viewer and r.session.get("admin") is True and r.session.get("admin_role")=="viewer":
        raise HTTPException(403,"Read-only viewer account")
    a=r.session.get("csrf",""); b=r.headers.get("x-csrf-token","")
    if not a or not b or not hmac.compare_digest(str(a),b): raise HTTPException(403,"Invalid CSRF token")
def rate_check(r,key,limit=8,window=300):
    now=int(time.time())
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        k="rate:"+key; row=c.execute("SELECT value FROM settings WHERE key=?",(k,)).fetchone()
        if not row: c.execute("INSERT INTO settings VALUES(?,?)",(k,f"{now}:1")); return True
        try: start,count=map(int,row["value"].split(":",1))
        except Exception: start,count=now,limit
        if now-start>=window: c.execute("UPDATE settings SET value=? WHERE key=?",(f"{now}:1",k)); return True
        if count>=limit: return False
        c.execute("UPDATE settings SET value=? WHERE key=?",(f"{start}:{count+1}",k)); return True

LOGIN='''<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="dark"><title>Abyss Tunnel · ورود</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;min-height:100dvh;display:grid;place-items:center;padding:18px;background:radial-gradient(ellipse at 50% 0,#163a43 0,transparent 52%),#080b12;color:#edf2ff;font:15px system-ui,-apple-system,sans-serif}.card{width:min(420px,100%);padding:clamp(22px,6vw,34px);border:1px solid #263b49;border-radius:22px;background:rgba(16,22,34,.96);box-shadow:0 24px 90px #0006}h1{margin:12px 0 8px;font-size:clamp(26px,7vw,34px)}p{line-height:1.9}.mint{color:#8de8d6;letter-spacing:.13em;font-size:11px;font-weight:800}.muted{color:#91a3b4}label{display:block;margin:16px 0 7px;font-size:13px}input{width:100%;min-width:0;padding:13px;border-radius:10px;border:1px solid #2a3548;background:#090e17;color:white;font:inherit}input:focus{outline:2px solid #76e4d1;outline-offset:1px}button{width:100%;padding:13px;margin-top:16px;background:#8de8d6;color:#061412;border:0;border-radius:10px;font:inherit;font-weight:800;cursor:pointer}.err{color:#ff9f9f;font-size:12px;overflow-wrap:anywhere}.symbol{display:grid;place-items:center;width:44px;height:44px;border:1px solid #2c5958;border-radius:13px;background:#102b30;color:#8de8d6;font-size:23px;margin-top:24px}.app-shell{display:grid;grid-template-columns:250px minmax(0,1fr);min-height:100dvh;max-width:1700px;margin:0 auto;background:#080b12}
.sidebar{position:sticky;top:0;height:100dvh;align-self:start;padding:22px 14px;border-left:1px solid #202d3b;background:linear-gradient(180deg,#0d141e,#090d14);z-index:25}
.side-brand{padding:9px 10px 23px;color:#8de8d6;font-size:13px;font-weight:850;letter-spacing:.12em}
.side-caption{padding:12px 10px 7px;color:#687d91;font-size:10px;letter-spacing:.12em}
.side-nav{display:grid;gap:6px}.nav-item{width:100%;text-align:right;display:flex;align-items:center;gap:11px;padding:12px;border:1px solid transparent;border-radius:11px;background:transparent;color:#9eafc0}
.nav-item:hover,.nav-item.active{background:#12242b;border-color:#24474a;color:#8de8d6}.nav-icon{width:25px;text-align:center;font-size:16px}
.workspace{min-width:0;width:100%;max-width:1400px;margin:0 auto;padding:20px clamp(12px,2vw,28px) 38px}
#menuToggle{display:none}.nav-hidden{display:none!important}.section-heading{margin-top:7px;font-size:20px;font-weight:800;color:#eaf5f7}
.top{padding:8px 0 15px;border-bottom:1px solid #1e2a38}.stats{margin-top:18px}
@media(max-width:850px){.app-shell{display:block}.sidebar{position:fixed;top:0;right:0;bottom:0;width:min(290px,84vw);height:100dvh;transform:translateX(105%);transition:transform .2s ease;box-shadow:none;border-left:1px solid #263748}.sidebar.open{transform:translateX(0);box-shadow:0 0 0 9999px #02050bc7}#menuToggle{display:inline-flex;position:sticky;top:8px;z-index:28;margin:8px 8px 0 auto;padding:10px 13px;background:#10252b;border-color:#2a5555;color:#8de8d6}.workspace{padding-top:8px}}
@media(prefers-reduced-motion:reduce){.sidebar{transition:none}}
</style><style id="abyss-premium-upgrade">
:root{color-scheme:dark;--abyss-bg:#050505;--abyss-panel:#0d0d0e;--abyss-line:#2a2a2d;--abyss-mint:#c1c2c6;--abyss-text:#eeeeef;--abyss-muted:#9b9ba0}
html{scroll-behavior:smooth}body{background-color:var(--abyss-bg)}body:before{content:"";position:fixed;inset:0;pointer-events:none;z-index:-1;background:linear-gradient(116deg,transparent 0 13%,rgba(190,190,195,.025) 13.08%,transparent 13.2% 38%,rgba(190,190,195,.018) 38.08%,transparent 38.2% 67%,rgba(190,190,195,.022) 67.08%,transparent 67.2%),linear-gradient(164deg,transparent 0 27%,rgba(190,190,195,.016) 27.08%,transparent 27.2% 58%,rgba(190,190,195,.02) 58.08%,transparent 58.2%),radial-gradient(ellipse at 50% 0%,rgba(255,255,255,.025),transparent 48%)}
.card,.panel,.box,.section,.stat,.metric,.client-card{border-color:var(--abyss-line)!important;box-shadow:0 12px 36px rgba(0,0,0,.14);transition:border-color .18s ease,transform .18s ease,box-shadow .18s ease}
button,.btn,a.button{transition:filter .15s ease,transform .15s ease,box-shadow .15s ease}button:hover,.btn:hover,a.button:hover{filter:brightness(1.08);transform:translateY(-1px)}
button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--abyss-mint);outline-offset:3px}
input,select,textarea{max-width:100%;min-width:0}table{display:block;max-width:100%;overflow-x:auto;border-collapse:collapse}main,.container,.wrap{min-width:0}
@media(max-width:600px){body{font-size:14px}main,.container,.wrap{padding-left:12px!important;padding-right:12px!important}.card,.panel,.box{border-radius:15px!important}.row{flex-wrap:wrap}.row>*{max-width:100%}button,.btn{min-height:42px}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;transition:none!important;animation:none!important}}
</style><style id="abyss-login-premium">body{overflow:hidden;background:radial-gradient(ellipse at 15% 20%,rgba(38,107,112,.23),transparent 38%),radial-gradient(ellipse at 85% 85%,rgba(42,61,100,.22),transparent 40%),#070a10}.card{position:relative;overflow:hidden;border-color:#2b4653;background:linear-gradient(155deg,rgba(17,27,41,.98),rgba(9,14,23,.98));box-shadow:0 32px 110px #0009,0 0 0 1px #8de8d60a}.card:before{content:"";position:absolute;inset:0 0 auto;height:2px;background:linear-gradient(90deg,transparent,#8de8d6,#547a9c,transparent)}.mint{font-size:10px;letter-spacing:.19em}.symbol{width:54px;height:54px;margin-top:26px;border-radius:17px;border-color:#396b6a;background:linear-gradient(145deg,#163b3d,#0d1c27);box-shadow:0 10px 35px #0005;font-size:25px}form{margin-top:20px}label{color:#b8c9d7}button{box-shadow:0 10px 26px #8de8d61b}button:hover{filter:brightness(1.06)}@media(max-width:420px){.card{border-radius:19px}.symbol{margin-top:20px}}</style><style>html,body,button,input,select,textarea{font-family:'Vazirmatn',Tahoma,system-ui,sans-serif}</style></head><body><main class="card"><div class="abyss-brand-row login-brand"><img class="abyss-logo-image" src="/brand-logo" alt="" aria-hidden="true"><span class="brand-name">ABYSS TUNNEL<small>• I T A •</small></span></div><h1>ورود به پنل مدیریت</h1><p class="muted">برای ادامه، اطلاعات خود را وارد کنید.</p><form method="post"><input type="hidden" name="csrf_token" value="{{CSRF}}"><label for="username">نام کاربری</label><div class="login-input-wrap"><span class="login-input-icon" aria-hidden="true">♙</span><input id="username" name="username" placeholder="نام کاربری" autocomplete="username" required></div><label for="password">رمز عبور</label><div class="login-input-wrap"><span class="login-input-icon" aria-hidden="true">♧</span><input id="password" type="password" name="password" placeholder="رمز عبور" autocomplete="current-password" required><button type="button" class="login-password-toggle" aria-label="نمایش رمز عبور" aria-pressed="false" onclick="const i=document.getElementById('password');i.type=i.type==='password'?'text':'password';this.textContent=i.type==='text'?'◌':'◉';this.setAttribute('aria-pressed',i.type==='text');this.setAttribute('aria-label',i.type==='text'?'پنهان کردن رمز عبور':'نمایش رمز عبور')">◉</button></div><div class="login-extra-row"><label class="remember-option"><input type="checkbox" name="remember_me" value="on"><span>مرا به خاطر بسپار</span></label><a href="#" onclick="document.getElementById('loginHelpDialog').showModal();return false">فراموشی رمز عبور؟</a></div><p class="err">{{ERROR}}</p><button>ورود</button></form></main></body></html>'''
DASH='''<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Abyss Tunnel</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#080b12;color:#edf2ff;font:14px system-ui,-apple-system,sans-serif}.wrap{max-width:1100px;margin:auto;padding:22px 14px}.card{background:#101622;border:1px solid #222d40;border-radius:14px;padding:17px;margin:14px 0}.top,.row,.client{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}.mint{color:#76e4d1;font-size:11px;letter-spacing:.12em}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.num{font-size:26px;font-weight:750}.fields{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-top:14px}input,button{font:inherit;border-radius:8px;padding:10px}input{min-width:0;width:100%;background:#090e17;color:white;border:1px solid #2a3548}button{cursor:pointer;background:#14202b;color:white;border:1px solid #2d3b50}button.primary{background:#76e4d1;color:#07120f;font-weight:700}.tools{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.client{padding:14px 0;border-top:1px solid #222d40}.client-info{min-width:180px;flex:1}.actions{display:flex;gap:6px;flex-wrap:wrap}.small{font-size:11px;color:#8794ac;line-height:1.8}.section-title{font-weight:700}.hidden{display:none!important}#status{color:#76e4d1}.client-name{overflow-wrap:anywhere}dialog{width:min(720px,calc(100% - 20px));max-height:90dvh;overflow:auto;padding:20px;border:1px solid #304254;border-radius:18px;background:#101722;color:#edf2ff;box-shadow:0 25px 90px #0009}dialog::backdrop{background:#02050bd9;backdrop-filter:blur(5px)}.modal-top{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:16px}.modal-top h2{font-size:18px;margin:0}.sub-layout{display:grid;grid-template-columns:minmax(0,1fr) 170px;gap:16px;align-items:start}.sub-field{margin:12px 0}.sub-field label{display:block;font-size:12px;color:#9babc0;margin-bottom:6px}.sub-field input{direction:ltr;text-align:left;font-size:12px}.sub-buttons{display:flex;flex-wrap:wrap;gap:8px}.qr-preview{width:170px;max-width:100%;background:white;border-radius:12px;padding:8px;aspect-ratio:1}.danger{border-color:#70404a;color:#ffb5bd}.profile-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin-top:13px}.profile-setting{display:flex;align-items:center;gap:10px;padding:12px;border:1px solid #27384a;border-radius:10px;background:#0b111b;min-width:0}.profile-setting input{width:18px;height:18px;accent-color:#76e4d1;flex-shrink:0}.profile-setting span{overflow-wrap:anywhere}.button-link{display:inline-flex;align-items:center;padding:10px;border-radius:8px;border:1px solid #2d3b50;background:#14202b;color:white;text-decoration:none;font:inherit}@media(max-width:700px){.stats{grid-template-columns:1fr 1fr}.fields{grid-template-columns:1fr 1fr}.wrap{padding:14px 10px}.actions button{padding:8px;font-size:12px}}@media(max-width:560px){.sub-layout{grid-template-columns:1fr}.profile-grid{grid-template-columns:1fr}.qr-preview{width:145px;display:block;margin:8px auto 0}}@media(max-width:420px){.stats,.fields{grid-template-columns:1fr}}
</style><style id="abyss-premium-upgrade">
:root{color-scheme:dark;--abyss-bg:#050505;--abyss-panel:#0d0d0e;--abyss-line:#2a2a2d;--abyss-mint:#c1c2c6;--abyss-text:#eeeeef;--abyss-muted:#9b9ba0}
html{scroll-behavior:smooth}body{background-color:var(--abyss-bg)}body:before{content:"";position:fixed;inset:0;pointer-events:none;z-index:-1;background:radial-gradient(ellipse at 80% -10%,rgba(43,130,125,.16),transparent 42%),radial-gradient(ellipse at 0% 40%,rgba(37,66,107,.13),transparent 42%)}
.card,.panel,.box,.section,.stat,.metric,.client-card{border-color:var(--abyss-line)!important;box-shadow:0 12px 36px rgba(0,0,0,.14);transition:border-color .18s ease,transform .18s ease,box-shadow .18s ease}
button,.btn,a.button{transition:filter .15s ease,transform .15s ease,box-shadow .15s ease}button:hover,.btn:hover,a.button:hover{filter:brightness(1.08);transform:translateY(-1px)}
button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--abyss-mint);outline-offset:3px}
input,select,textarea{max-width:100%;min-width:0}table{display:block;max-width:100%;overflow-x:auto;border-collapse:collapse}main,.container,.wrap{min-width:0}
@media(max-width:600px){body{font-size:14px}main,.container,.wrap{padding-left:12px!important;padding-right:12px!important}.card,.panel,.box{border-radius:15px!important}.row{flex-wrap:wrap}.row>*{max-width:100%}button,.btn{min-height:42px}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;transition:none!important;animation:none!important}}
</style><style id="abyss-premium-layout">.app-shell{max-width:1800px;grid-template-columns:258px minmax(0,1fr)}.sidebar{padding:26px 16px;background:linear-gradient(180deg,#0d1620,#080c13);border-left:1px solid #263849;overflow-y:auto;overscroll-behavior:contain;scrollbar-width:thin;scrollbar-color:#343438 transparent}.side-brand{font-size:14px;letter-spacing:.16em;padding:10px 12px 25px}.side-caption{font-size:10px;letter-spacing:.14em}.nav-item{font-size:13px;min-height:43px}.nav-item.active{box-shadow:inset -3px 0 #8de8d6}.workspace{max-width:1460px;padding:26px clamp(14px,2.5vw,36px) 46px}.top{align-items:center;gap:18px;padding:12px 0 20px}.top .tools{justify-content:flex-start;flex-wrap:wrap}.section-heading{font-size:23px;letter-spacing:-.02em}.stats{gap:14px}.stats>.card,.workspace>section.card{border-radius:18px;padding:21px;background:linear-gradient(145deg,#111b28,#0c121c)}.fields{grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}.field{display:grid;gap:7px;min-width:0;color:#9aafc1;font-size:12px}.field input,.field select{height:44px;padding:11px 12px;border-radius:11px;background:#080e17;border-color:#2c3d50}.field input:focus,.field select:focus{border-color:#8de8d6;box-shadow:0 0 0 3px #8de8d61c}.workspace .section-title{font-size:16px}.workspace .small{line-height:1.85}.workspace .client{padding:16px 0;border-top-color:#263647}.workspace .actions{gap:7px}.workspace button,.workspace .button-link{border-radius:10px;min-height:40px}.workspace button.primary{box-shadow:0 7px 22px #8de8d61a}.workspace #clients{display:grid;gap:9px}.workspace #clients .client{padding:14px;border:1px solid #263749;border-radius:13px;background:#0a111b}.workspace #subDialog{border-color:#304556}.workspace .stats .num{font-size:29px}.workspace [data-section-page]{scroll-margin-top:20px}#menuToggle{border-radius:12px;box-shadow:0 10px 25px #0005}.sidebar.open{box-shadow:0 0 0 9999px #02050bc7}.workspace .tools button{white-space:nowrap}@media(max-width:850px){.workspace{padding:10px 12px 30px}.top{padding-top:10px}.top .tools{gap:7px}.top .tools button{flex:1}.fields{grid-template-columns:1fr}.sidebar{z-index:60}.workspace>section.card{padding:15px}.stats>.card{padding:15px}}@media(min-width:851px){#menuToggle{display:none!important}}@media(prefers-reduced-motion:reduce){.nav-item,.workspace button{transition:none!important}}</style><style>html,body,button,input,select,textarea{font-family:'Vazirmatn',Tahoma,system-ui,sans-serif}</style></head><body><main class="app-shell">
<button type="button" id="menuToggle" onclick="toggleSidebar()" aria-label="باز کردن منو">☰ منو</button>
<aside class="sidebar" id="sidebar"><div class="side-brand abyss-brand-row"><span class="abyss-logo-mark" aria-hidden="true"></span><span class="brand-name">AbyssTunnel<small>• I T A •</small></span></div><div class="side-caption">مدیریت داشبورد</div><nav class="side-nav" aria-label="ناوبری داشبورد">
<button class="nav-item active" data-nav="dashboard" onclick="showSection('dashboard')"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/></svg></span>داشبورد</button>
<button class="nav-item" data-nav="clients" onclick="showSection('clients')"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="3.2"/><path d="M5 20c.5-3.6 3-5.5 7-5.5s6.5 1.9 7 5.5"/></svg></span>مدیریت کاربران</button><button class="nav-item" data-nav="create" onclick="showSection('create')"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg></span>ساخت سرویس</button><button class="nav-item" data-nav="servers" onclick="showSection('servers')"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="4" width="16" height="6" rx="1.5"/><rect x="4" y="14" width="16" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01M10 7h7M10 17h7"/></svg></span>مدیریت سرورها</button><button class="nav-item" data-nav="protocols" onclick="showSection('protocols')"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="6" cy="5" r="2"/><circle cx="18" cy="19" r="2"/><circle cx="18" cy="5" r="2"/><path d="M6 7v5a4 4 0 0 0 4 4h6M14 5h2M18 7v10"/></svg></span>پروتکل‌ها</button><button class="nav-item" data-nav="reports" onclick="showSection('reports')"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 18V9M10 18V5M16 18v-7M22 18V3" transform="translate(-1 1)"/></svg></span>گزارش‌ها</button>
<button class="nav-item" data-nav="reseller" onclick="showSection('reseller')"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="8" r="3"/><circle cx="17" cy="9" r="2.3"/><path d="M3 20c.3-3.3 2.4-5 6-5s5.7 1.7 6 5M15 15c3.6-.5 5.5 1.1 6 4"/></svg></span>حساب‌های نمایندگی و سهمیه</button>
<button class="nav-item" data-nav="settings" onclick="showSection('settings')"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-1.8 1.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5v.2h-2.6v-.2a1.7 1.7 0 0 0-1-1.5 1.7 1.7 0 0 0-1.9.3l-.1.1-1.8-1.8.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H6.3v-2.6h.2a1.7 1.7 0 0 0 1.5-1 1.7 1.7 0 0 0-.3-1.9l-.1-.1 1.8-1.8.1.1a1.7 1.7 0 0 0 1.9.3 1.7 1.7 0 0 0 1-1.5v-.2h2.6v.2a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1 1.8 1.8-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.5 1h.2v2.6h-.2a1.7 1.7 0 0 0-1.5 1z"/></svg></span>تنظیمات اتصال</button>
<button class="nav-item" data-nav="diagnostics" onclick="showSection('diagnostics')"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l1.6 6.4L20 11l-6.4 1.6L12 19l-1.6-6.4L4 11l6.4-1.6L12 3zM19 16l.7 2.3L22 19l-2.3.7L19 22l-.7-2.3L16 19l2.3-.7L19 16z"/></svg></span>عیب‌یابی هوشمند</button>
<button class="nav-item" data-nav="backup" data-owner-only onclick="showSection('backup')"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="4" width="16" height="16" rx="2"/><path d="M8 4v4h8V4M8 14h8M8 17h5"/></svg></span>پشتیبان‌گیری</button>
<button class="nav-item" data-nav="metrics" onclick="showSection('metrics')"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 12h4l3-7 4 14 3-7h4"/></svg></span>پایش زنده</button>
<button class="nav-item" data-nav="admins" data-owner-only onclick="showSection('admins')"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="3.2"/><path d="M5 20c.5-3.6 3-5.5 7-5.5s6.5 1.9 7 5.5"/></svg></span>مدیریت مدیران</button>
<button class="nav-item" data-nav="apikeys" data-owner-only onclick="showSection('apikeys')"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="8" r="3"/><circle cx="17" cy="9" r="2.3"/><path d="M3 20c.3-3.3 2.4-5 6-5s5.7 1.7 6 5M15 15c3.6-.5 5.5 1.1 6 4"/></svg></span>API و ربات</button>
<button class="nav-item" data-nav="events" onclick="showSection('events')"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 18V9M10 18V5M16 18v-7M22 18V3" transform="translate(-1 1)"/></svg></span>رویدادهای اخیر</button>
<a class="nav-item" href="/api-docs" target="_blank" rel="noopener"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 4h6v6M20 4l-9 9"/><path d="M18 13v6a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h6"/></svg></span>مستندات API</a>
</nav><div class="side-caption" style="margin-top:18px">سازنده · Abyss Tunnel · دسترسی سریع</div><div class="abyss-utility-links" aria-label="پیوندهای پروژه"><a href="https://github.com/bodisbos-cmd/Void" target="_blank" rel="noopener">⌘ GitHub</a><a href="https://github.com/bodisbos-cmd/Void/stargazers" target="_blank" rel="noopener">☆ ستاره دادن</a><a href="#support-link-not-configured" onclick="if(this.getAttribute('href')==='#support-link-not-configured'){alert('لینک حمایت مالی هنوز تنظیم نشده است؛ متغیر SUPPORT_URL را در Railway تنظیم کن.');return false}">◇ حمایت از پروژه</a></div><div class="sidebar-account-badge" aria-label="حساب فعلی"><span class="sidebar-account-avatar" aria-hidden="true">◉</span><span><b id="sidebarAccountUsername">admin</b><small id="sidebarAccountRole">مدیر کل</small></span></div><div class="sidebar-quick-actions" aria-label="اقدامات حساب"><button type="button" onclick="changePassword()" data-i18n="changePassword">تغییر رمز عبور</button><button type="button" onclick="load()" data-i18n="refresh">به‌روزرسانی</button><button type="button" class="sidebar-logout" onclick="location.href='/logout'" data-i18n="logout">خروج</button></div></aside>
<div class="workspace"><header class="top"><div class="abyss-brand-row"><span class="brand-name"><b>AbyssTunnel</b><small>• I T A • · داشبورد مدیریت</small></span></div><div class="mint" data-i18n="tagline">داشبورد مدیریتی خصوصی</div><div id="sectionTitle" class="section-heading">نمای کلی</div><div class="tools"><input class="top-tools-search" id="globalSearch" type="search" placeholder="جست‌وجوی کاربر…" data-i18n-placeholder="search" aria-label="جست‌وجوی کاربر" onkeydown="if(event.key==='Enter'){event.preventDefault();runGlobalSearch()}"><button type="button" class="toolbar-icon" onclick="showSection('events')" title="رویدادهای اخیر" aria-label="رویدادهای اخیر"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg></button> <button id="langBtn" onclick="toggleLanguage()">English</button><button type="button" class="toolbar-icon" onclick="showPanelHelp()" title="راهنمای پنل" aria-label="راهنمای پنل">?</button><span class="account-badge"><span class="account-avatar" aria-hidden="true">◉</span><span class="account-copy"><b id="accountUsername">مدیر پنل</b><small id="accountRole">حساب مدیریت</small></span></span></div></header>
<section id="overviewStats" class="stats" data-section-page="dashboard"><div class="card"><span data-i18n="total">کل کاربران</span><div class="num" id="total">—</div></div><div class="card"><span data-i18n="active">کاربران فعال</span><div class="num" id="active">—</div></div><div class="card"><span data-i18n="xray">وضعیت Xray</span><div class="num" id="xray">—</div></div><div class="card"><span>مصرف ثبت‌شده</span><div class="num" id="dashboardTraffic">—</div><div class="small">ترافیک ثبت‌شدهٔ داشبورد</div></div></section>
<section id="dashboardUsageCard" class="card" data-section-page="dashboard"><div class="usage-chart-head"><div><div class="section-title">نمودار مصرف پهنای باند</div><div class="small">تاریخچهٔ واقعی مصرف ثبت‌شدهٔ سرویس‌ها؛ نمونه‌ها هر دقیقه ذخیره می‌شوند.</div></div><div class="usage-range-tabs" role="group" aria-label="بازهٔ نمودار مصرف"><button type="button" class="is-active" data-traffic-period="24h" aria-pressed="true" onclick="setTrafficChartPeriod('24h')">24h</button><button type="button" data-traffic-period="7d" aria-pressed="false" onclick="setTrafficChartPeriod('7d')">7d</button><button type="button" data-traffic-period="30d" aria-pressed="false" onclick="setTrafficChartPeriod('30d')">30d</button></div></div><div class="stats"><div class="card"><span>CPU</span><div class="num" id="dashCpu">—</div></div><div class="card"><span>RAM</span><div class="num" id="dashRam">—</div></div><div class="card"><span>دیسک</span><div class="num" id="dashDisk">—</div></div></div><canvas id="usageSparkline" height="112" aria-label="نمودار واقعی مصرف ثبت‌شده بر حسب گیگابایت"></canvas><div id="chartLegend" class="chart-legend"><span><i class="net"></i>مصرف ثبت‌شده (GB)</span></div><div id="chartNote" class="small" style="margin-top:7px">تاریخچهٔ واقعی مصرف در حال جمع‌آوری است…</div></section>
<section class="card" data-section-page="clients"><div class="row"><div><div class="section-title" data-i18n="clients">مدیریت کاربران <span class="help-dot" title="ساخت سرویس، مدیریت زمان و حجم و کنترل دسترسی." aria-label="راهنمای مدیریت کاربران">؟</span></div><div class="small" data-i18n="clientHelp">ساخت سرویس، کنترل دسترسی و مدیریت لینک اشتراک</div></div><div class="users-search-actions"><input id="search" placeholder="جست‌وجوی نام یا شناسه…" oninput="renderClients()" data-i18n-placeholder="search"><button class="primary" type="button" onclick="showSection('create')">افزودن کاربر +</button></div></div>
<div class="clients-layout"><div id="clients" class="clients-table-wrap" style="margin-top:12px"></div><aside id="clientDetailsPanel" class="client-details-panel" aria-live="polite"><div class="small">یک سرویس را انتخاب کن تا جزئیاتش نمایش داده شود.</div></aside></div></section><section class="card" id="createServiceCard" data-section-page="create"><div class="reference-page-head"><div><div class="section-title">ساخت سرویس جدید <span class="help-dot" title="برای سرویس زمان، حجم و پروفایل‌های اتصال را مشخص کن." aria-label="راهنمای ساخت سرویس">؟</span></div><div class="small">سرویس را برای کاربر بساز؛ هر تغییری در محدودیت‌ها و پروفایل‌ها به همین سرویس اعمال می‌شود.</div></div></div><div class="creation-tabs" role="tablist" aria-label="بخش‌های ساخت سرویس"><button type="button" class="creation-tab" role="tab" aria-selected="false" aria-controls="creationPanelGeneral" id="creationTabGeneral" onclick="switchCreationTab('general')">عمومی</button><button type="button" class="creation-tab" role="tab" aria-selected="false" aria-controls="creationPanelLimits" id="creationTabLimits" onclick="switchCreationTab('limits')">محدودیت‌ها</button><button type="button" class="creation-tab is-active" role="tab" aria-selected="true" aria-controls="creationPanelProfiles" id="creationTabProfiles" onclick="switchCreationTab('profiles')">پروتکل‌ها</button></div><div class="creation-tab-panel" id="creationPanelGeneral" role="tabpanel" aria-labelledby="creationTabGeneral" data-creation-panel="general" hidden><div class="fields creation-fields-general"><input id="name" maxlength="64" placeholder="نام کاربر" data-i18n-placeholder="name" title="نام نمایشی سرویس"><input id="note" maxlength="300" placeholder="یادداشت (اختیاری)" data-i18n-placeholder="note"></div><p class="small creation-hint">نام سرویس الزامی است؛ یادداشت برای شناسایی داخلی اختیاری است.</p></div><div class="creation-tab-panel" id="creationPanelLimits" role="tabpanel" aria-labelledby="creationTabLimits" data-creation-panel="limits" hidden><div class="fields creation-fields-limits"><input id="days" type="number" min="1" max="3650" placeholder="مدت (روز، اختیاری)" data-i18n-placeholder="days" title="خالی گذاشتن یعنی بدون انقضا"><input id="quota" type="number" min="1" max="100000" placeholder="حجم (GB، اختیاری)" data-i18n-placeholder="quota" title="خالی گذاشتن یعنی بدون محدودیت حجم"></div><p class="small creation-hint">خالی گذاشتن مدت و حجم یعنی نامحدود؛ محدودیت‌های پشتیبانی‌نشده نمایش داده نمی‌شوند.</p></div><div class="creation-tab-panel is-active" id="creationPanelProfiles" role="tabpanel" aria-labelledby="creationTabProfiles" data-creation-panel="profiles"><div class="section-title creation-panel-title">پروفایل‌های قابل ارائه <span class="help-dot" title="چند پروفایل را هم‌زمان انتخاب کن. فقط پروفایل‌های فعال سراسری قابل ارائه‌اند." aria-label="راهنمای انتخاب پروفایل‌ها">؟</span></div><div id="clientProfileChoices" class="profile-grid"></div></div><div class="row creation-submit-row"><span class="small" id="creationFormHint">برای ساخت، نام سرویس را در بخش عمومی وارد کن و دست‌کم یک پروفایل فعال را انتخاب کن.</span><button class="primary" onclick="add()" data-i18n="create">+ ساخت کاربر</button></div></section>

<section class="card" id="serversPage" data-section-page="servers">
  <div class="reference-page-head"><div><div class="section-title">مدیریت سرورها</div><div class="small">وضعیت همین استقرار را می‌خواند؛ آدرس یا سرور فرضی نمایش داده نمی‌شود.</div></div><button type="button" onclick="loadServerStatus()">به‌روزرسانی</button></div>
  <div class="server-identity"><div><div class="small">سرور جاری · Railway</div><strong id="serverHost">در حال دریافت دامنه…</strong></div><span class="state-chip neutral" id="serverOverall">در انتظار بررسی</span></div>
  <div class="server-table-wrap"><table class="server-table"><thead><tr><th>نام سرور</th><th>آی‌پی / دامنه</th><th>Xray</th><th>وضعیت</th><th>عملیات</th></tr></thead><tbody id="serverTableBody"><tr><td colspan="5">در حال دریافت وضعیت…</td></tr></tbody></table></div>
  <div class="server-grid" id="serverStatusGrid"><article class="server-state"><div class="small">در حال خواندن وضعیت اجزای واقعی…</div></article></div>
  <div class="small" id="serverStatusNote" style="margin-top:14px;line-height:1.9">آزمون مسیر داخلی، تست واقعی اتصال از سیم‌کارت یا دستگاه مقصد نیست.</div>
</section>
<section class="card" id="protocolsPage" data-section-page="protocols">
  <div class="reference-page-head"><div><div class="section-title">پروتکل‌ها</div><div class="small">پروفایل‌های واقعی موجود در همین نسخه؛ روشن و خاموش کردن هر گزینه از تنظیمات Xray عبور می‌کند.</div></div><button type="button" onclick="loadProtocolCatalog()">به‌روزرسانی</button></div>
  <div id="protocolCatalog" class="protocol-catalog"><article class="protocol-state"><div class="small">در حال دریافت پروفایل‌ها…</div></article></div>
</section>
<section class="card" id="reportsPage" data-section-page="reports">
  <div class="reference-page-head"><div><div class="section-title">گزارش‌ها</div><div class="small">نتایج اعتبارسنجی Xray و مسیرهای داخلی، به‌همراه رویدادهای ثبت‌شدهٔ پنل.</div></div><button type="button" onclick="loadReports()">اجرای بررسی</button></div>
  <div class="report-summary" id="reportSummary">هنوز بررسی اجرا نشده است.</div>
  <div class="section-title" style="margin-top:4px">رویدادهای اخیر</div><div class="report-events" id="reportEvents"><div class="small">در انتظار رویدادها…</div></div>
  <div class="section-title" style="margin-top:18px">موارد نیازمند توجه</div><div class="report-issues" id="reportIssues"><div class="small">در انتظار بررسی…</div></div>
  <div class="section-title" style="margin-top:18px">وضعیت پروفایل‌های اتصال</div><div class="report-profiles" id="reportProfiles"></div>
  <div class="small" style="margin-top:12px;line-height:1.9">نکته: پاسخ دادن پورت و مسیر وب، اتصال واقعی کانفیگ یا پینگ کاربر را اثبات نمی‌کند؛ آن بخش باید با کلاینت و شبکهٔ مقصد بررسی شود.</div>
</section>
<section class="card" id="backupCard" data-section-page="backup"><div class="section-title">پشتیبان‌گیری و بازیابی <span class="help-dot" title="نسخهٔ پشتیبان شامل اطلاعات حساس و لینک‌های دسترسی است؛ محرمانه نگهش دار." aria-label="راهنمای پشتیبان‌گیری">؟</span></div><div class="small">فایل پشتیبان شامل اطلاعات حساس کاربران است؛ آن را محرمانه نگه دار.</div><div class="tools" style="margin-top:12px"><button class="primary" onclick="location.href='/api/backup'">دریافت نسخه پشتیبان</button><input id="restoreFile" type="file" accept=".sqlite3,.db,application/vnd.sqlite3"><button class="danger" onclick="restoreBackup()">بازیابی از فایل</button></div></section><section class="card" id="resellerCard" data-section-page="reseller"><div class="section-title">حساب‌های نمایندگی و تقسیم حجم</div><div class="small">بخشی از حجم تخصیص‌یافته‌ات را به یک نماینده بده. مجموع حجم سرویس‌ها و حساب‌های نمایندگی از سهمیه‌ات بیشتر نمی‌شود.</div><div class="fields"><input id="resellerUsername" maxlength="48" placeholder="نام کاربری نماینده"><input id="resellerPassword" type="password" placeholder="رمز عبور حداقل ۱۴ نویسه"><input id="resellerQuota" type="number" min="0.1" step="0.1" placeholder="حجم اختصاصی (GB)"><button class="primary" onclick="addReseller()">ساخت نماینده</button></div><div id="resellerList" style="margin-top:12px"></div><div id="allocationStatus" class="small"></div></section><section class="card" id="settingsCard" data-section-page="settings"><div class="section-title" data-i18n="settings">تنظیمات اتصال</div><div class="settings-tabs" role="group" aria-label="بخش‌های تنظیمات">
<button type="button" class="settings-tab active" data-settings-tab="settings" onclick="showSection('settings')">پروفایل‌ها</button>
<button type="button" class="settings-tab" data-settings-tab="backup" onclick="showSection('backup')">پشتیبان‌گیری</button>
<button type="button" class="settings-tab" data-settings-tab="reports" onclick="showSection('reports')">گزارش‌ها</button>
<button type="button" class="settings-tab" data-settings-tab="apikeys" onclick="showSection('apikeys')">API</button>
<button type="button" class="settings-tab" data-settings-tab="admins" onclick="showSection('admins')">مدیران</button>
<button type="button" class="settings-tab" data-settings-tab="metrics" onclick="showSection('metrics')">پایش</button>
</div><div class="small" data-i18n="settingsHelp">پروفایل‌های قابل ارائه در اشتراک و Xray را فعال یا غیرفعال کن.</div><div class="small" style="margin-top:8px">پروفایل‌های XHTTP با حالت‌های stream-up/stream-one و مسیرهای جایگزین آزمایشی‌اند؛ چون در آزمون تونل از درگاه HTTP/1.1 تایم‌اوت داشتند، پیش‌فرض خاموش‌اند. فقط برای آزمون دستی فعال‌شان کن.</div><div id="profileSettings" class="profile-grid"></div></section><section class="card" id="diagnosticsCard" data-section-page="diagnostics"><div class="section-title">عیب‌یابی هوشمند و پیشنهاد اتصال</div><div class="small">اعتبارسنجی Xray و Nginx، بررسی مسیرهای داخلی و پیشنهاد پروفایل بر پایهٔ گزارش واقعی کاربران هر اپراتور. این بررسی داخلی به‌تنهایی پینگ واقعی تونل را ثابت نمی‌کند.</div><div class="tools" style="margin-top:12px"><label class="small" for="diagnosticCarrier">اپراتور</label><select id="diagnosticCarrier"><option value="auto">نامشخص / انتخاب خودکار</option><option value="mci">همراه اول</option><option value="irancell">ایرانسل</option><option value="rightel">رایتل</option><option value="wifi">وای‌فای</option></select><button class="primary" onclick="runDiagnostics()">بررسی همه پروفایل‌ها</button><button data-owner-only class="danger" onclick="repairDiagnostics()">تعمیر امن و راه‌اندازی مجدد</button></div><div id="diagnosticSummary" class="small" style="margin-top:12px">هنوز بررسی اجرا نشده است.</div><div id="diagnosticResults" class="diag-grid"></div><div class="small" style="margin-top:12px">گزارش‌های تست از صفحهٔ اشتراک بر اساس اپراتور جمع می‌شوند؛ پیشنهادها پس از رسیدن به حداقل ۳ گزارش نمایش داده می‌شوند.</div></section><section class="card" id="metricsCard" data-section-page="metrics"><div class="section-title">پایش زنده سرویس</div><div class="small">آمار منابع همین کانتینر و ترافیک ثبت‌شده؛ سرعت و پینگ واقعی اینترنت کاربر نیست.</div><div class="stats"><div class="card"><span>CPU</span><div class="num" id="metricCpu">—</div></div><div class="card"><span>RAM</span><div class="num" id="metricRam">—</div></div><div class="card"><span>دیسک</span><div class="num" id="metricDisk">—</div></div><div class="card"><span>سرعت ثبت‌شده</span><div class="num" id="metricSpeed">—</div></div><div class="card"><span>Load</span><div class="num" id="metricLoad">—</div></div><div class="card"><span>مصرف ثبت‌شده</span><div class="num" id="metricTraffic">—</div></div></div><div class="tools"><button onclick="loadMetrics()">به‌روزرسانی آمار</button></div><div id="profileChecks" class="small" style="margin-top:12px">بررسی هنوز اجرا نشده است. وضعیت مسیر HTTP با اتصال واقعی تونل متفاوت است.</div></section>
<section class="card" id="adminUsersCard" data-section-page="admins" data-owner-only><div class="section-title">مدیریت حساب‌های مدیر</div><div class="small">برای همکاران حساب جدا بساز. مشاهده‌گر فقط می‌تواند اطلاعات را ببیند.</div><div class="fields"><input id="adminUsername" maxlength="32" placeholder="نام کاربری"><input id="adminPassword" type="password" placeholder="رمز قوی، حداقل ۱۴ نویسه"><select id="adminRole"><option value="admin">مدیر</option><option value="viewer">مشاهده‌گر</option></select><button class="primary" onclick="createPanelAdmin()">ساخت حساب</button></div><div id="adminUsersList" style="margin-top:12px"></div></section>
<section class="card" id="apiKeysCard" data-section-page="apikeys" data-owner-only><div class="section-title">API و اتصال ربات</div><div class="small">کلید کامل فقط یک بار نمایش داده می‌شود؛ آن را در متغیر امن ربات نگه دار و داخل GitHub نگذار.</div><div class="fields"><input id="apiKeyName" maxlength="48" placeholder="نام کلید API"><select id="apiKeyExpiry"><option value="">بدون انقضا</option><option value="30">۳۰ روز</option><option value="90">۹۰ روز</option><option value="365">یک سال</option></select><button class="primary" onclick="createApiKey()">ساخت کلید API</button></div><div class="small" style="margin-top:8px">مجوزها: <label><input type="checkbox" class="apiScope" value="clients:read" checked> مشاهده کاربران</label> <label><input type="checkbox" class="apiScope" value="clients:write" checked> مدیریت کاربران</label> <label><input type="checkbox" class="apiScope" value="subscriptions:read" checked> لینک اشتراک</label> <label><input type="checkbox" class="apiScope" value="metrics:read" checked> آمار</label></div><div id="apiKeysList" style="margin-top:12px"></div><a class="button-link" href="/api-docs" target="_blank" rel="noopener">مستندات تعاملی API ↗</a><div class="small">GET/POST /api/v1/clients · PATCH/DELETE /api/v1/clients/{id} · GET /api/v1/system/metrics</div></section>
<section id="panelHealthCard" class="card" data-section-page="dashboard"><div class="section-title">وضعیت سرویس‌ها</div><div id="status" class="small">در حال بررسی اتصال داشبورد…</div><div class="dashboard-component-list" id="dashboardComponentStatus"><div class="small">در حال دریافت وضعیت Nginx، Xray، Database و Panel…</div></div></section><section id="dashboardQuickCard" class="card" data-section-page="dashboard"><div class="section-title" data-i18n="quickDetails">جزئیات سریع</div><div id="dashboardQuickDetails" class="quick-detail-list" role="list" aria-label="جزئیات سریع"><div class="quick-detail-row" role="listitem"><span class="quick-detail-copy"><span class="small" data-quick-label="latestService">آخرین سرویس ساخته‌شده</span><small class="quick-detail-meta">در انتظار دریافت اطلاعات…</small></span><strong>—</strong></div><div class="quick-detail-row" role="listitem"><span class="quick-detail-copy"><span class="small" data-quick-label="latestPanelChange">آخرین تغییر پنل</span><small class="quick-detail-meta">در انتظار دریافت اطلاعات…</small></span><strong>—</strong></div><div class="quick-detail-row" role="listitem"><span class="quick-detail-copy"><span class="small" data-quick-label="latestBackup">آخرین پشتیبان</span><small class="quick-detail-meta">در انتظار دریافت اطلاعات…</small></span><strong>—</strong></div></div><div id="dashboardStatusAccessible" class="quick-detail-list dashboard-status-sr-only" role="status" aria-live="polite"><div class="quick-detail-row"><span class="small">وضعیت Xray</span><strong>در حال بررسی</strong></div><div class="quick-detail-row"><span class="small">کاربران فعال</span><strong>در انتظار اطلاعات</strong></div></div><div id="recentActivityList" class="report-events" hidden aria-hidden="true"><div class="small">در انتظار دریافت اطلاعات…</div></div></section>
<section class="card" data-section-page="events"><div class="section-title" data-i18n="events">رویدادهای اخیر</div><div id="events"></div></section></div></main><dialog id="subDialog"><div class="modal-top"><div><h2 data-i18n="subTitle">مدیریت لینک اشتراک</h2><div id="subClientName" class="small"></div></div><button onclick="closeSub()" aria-label="بستن">✕</button></div><div class="sub-layout"><div><div class="sub-field"><label for="pageUrl">لینک واحد اشتراک (مرورگر + برنامهٔ سازگار)</label><input id="pageUrl" readonly></div><div class="sub-buttons"><button class="primary" onclick="copyField('pageUrl',this)" aria-label="کپی لینک واحد">⧉</button><span id="copyStatus" class="small" aria-live="polite"></span><a class="button-link" id="openPage" target="_blank" rel="noopener">باز کردن صفحه اشتراک</a></div><p class="small">برای برنامهٔ سازگار هم همین لینک را وارد کن؛ حجم و زمان از هدر استاندارد اشتراک به برنامه‌های سازگار ارسال می‌شود.</p></div><div><img id="subQr" class="qr-preview" alt="QR code" width="170" height="170"><div class="small" style="text-align:center" data-i18n="qrHint">برای واردکردن سریع، QR را اسکن کن.</div></div></div></dialog><dialog id="profilesDialog"><div class="modal-top"><div><h2>پروفایل‌های این سرویس</h2><div id="profilesClientName" class="small"></div></div><button onclick="document.getElementById('profilesDialog').close()" aria-label="بستن">✕</button></div><div class="small">چند پروفایل را هم‌زمان فعال کن. پروفایل خاموش در تنظیمات اصلی قابل انتخاب نیست.</div><div id="editClientProfileChoices" class="profile-grid"></div><div class="tools" style="margin-top:16px"><button class="primary" onclick="saveClientProfiles()">ذخیرهٔ پروفایل‌ها</button><button onclick="document.getElementById('profilesDialog').close()">انصراف</button></div></dialog><dialog id="panelHelpDialog"><div class="modal-top"><div><h2>راهنمای پنل</h2><div class="small">راهنمای سریع بخش‌های اصلی</div></div><button type="button" onclick="document.getElementById('panelHelpDialog').close()" aria-label="بستن">✕</button></div><div class="help-dialog-grid"><article><b>کاربران</b><p class="small">مشاهده و جست‌وجوی سرویس‌ها، وضعیت مصرف و لینک اشتراک.</p></article><article><b>ساخت سرویس</b><p class="small">نام، مدت، حجم و پروفایل‌های فعال را انتخاب کن.</p></article><article><b>سرورها و پروتکل‌ها</b><p class="small">وضعیت واقعی همین استقرار و پروفایل‌های موجود را ببین.</p></article><article><b>گزارش‌ها</b><p class="small">خطاهای پیکربندی و مسیرهای داخلی را بررسی کن. پاسخ مسیر وب به‌تنهایی اتصال واقعی کاربر را ثابت نمی‌کند.</p></article><article><b>اشتراک</b><p class="small">از جزئیات هر سرویس، لینک اشتراک و QR Code را باز یا کپی کن.</p></article></div></dialog><script src="/dashboard.js?v=20261018-chart-stallfix1" defer></script></body></html>'''

DASH_JS=r'''let csrf='',allClients=[],latestOverview=null,lang=localStorage.getItem('abyss-lang')||'fa';
const words={
fa:{tagline:'داشبورد مدیریتی خصوصی',quickDetails:'جزئیات سریع',latestService:'آخرین سرویس ساخته‌شده',latestPanelChange:'آخرین تغییر پنل',latestBackup:'آخرین پشتیبان',notRecorded:'در رویدادهای اخیر ثبت نشده',noneRecorded:'ثبت نشده',quickProfileChange:'پروفایل‌های اتصال به‌روزرسانی شدند',quickServiceChange:'تنظیمات سرویس به‌روزرسانی شد',quickAccountChange:'اطلاعات حساب به‌روزرسانی شد',quickAccountCreate:'حساب جدید ساخته شد',quickApiKeyChange:'کلید API تغییر کرد',quickConfigChange:'تنظیمات پنل تغییر کرد',quickBackupReady:'نسخهٔ پشتیبان آماده شد',quickBackupRestored:'بازیابی پشتیبان انجام شد',changePassword:'تغییر رمز عبور',refresh:'به‌روزرسانی',logout:'خروج',total:'کل کاربران',active:'کاربران فعال',xray:'وضعیت Xray',clients:'مدیریت کاربران',clientHelp:'ساخت سرویس، کنترل دسترسی و مدیریت لینک اشتراک',search:'جست‌وجوی نام یا شناسه…',name:'نام کاربر',days:'مدت (روز، اختیاری)',quota:'حجم (GB، اختیاری)',note:'یادداشت (اختیاری)',optional:'خالی گذاشتن مدت و حجم یعنی نامحدود.',create:'+ ساخت کاربر',events:'رویدادهای اخیر',settings:'تنظیمات اتصال',settingsHelp:'پروفایل‌های قابل ارائه در اشتراک و Xray را فعال یا غیرفعال کن.',profileWs:'WebSocket',profileUpgrade:'HTTPUpgrade',profileXhttpAuto:'XHTTP · auto',profileXhttpPacket:'XHTTP · packet-up',online:'فعال',starting:'در حال راه‌اندازی',notInstalled:'نصب نیست',paused:'متوقف',used:'مصرف‌شده',unlimited:'نامحدود',expires:'انقضا',noExpiry:'بدون انقضا',subscription:'لینک اشتراک',copy:'کپی لینک',edit:'ویرایش',resetUsage:'ریست مصرف',subTitle:'مدیریت لینک اشتراک',sharePage:'صفحه اشتراک برای کاربر',rawSubscription:'لینک خام اشتراک برای کلاینت',copyPage:'کپی لینک صفحه',copiedPage:'لینک صفحه کپی شد.',copyRaw:'کپی لینک خام',openPage:'باز کردن صفحه',qrHint:'برای واردکردن سریع، QR را اسکن کن.',editName:'نام کاربر:',editNote:'یادداشت:',editDays:'مدت از امروز به روز (خالی = نامحدود):',editQuota:'حجم GB (خالی = نامحدود):',editSuccess:'مشخصات کاربر به‌روزرسانی شد.',resetConfirm:'مصرف ثبت‌شده این کاربر صفر شود؟',resetSuccess:'مصرف کاربر صفر شد.',pause:'توقف',enable:'فعال‌سازی',revoke:'حذف',noClients:'کاربری ثبت نشده است.',noResults:'موردی پیدا نشد.',connected:'اتصال داشبورد برقرار است.',apiError:'خطای API داشبورد: ',confirmRevoke:'این کاربر و دسترسی او حذف شود؟',copied:'لینک اشتراک کپی شد.',copyFail:'کپی خودکار ممکن نبود؛ لینک را کپی کن:',currentPassword:'رمز عبور فعلی:',newPassword:'رمز جدید (حداقل ۱۴ نویسه و شامل حرف و عدد):',passwordChanged:'رمز عبور تغییر کرد.',passwordRule:'رمز باید حداقل ۱۴ نویسه و شامل حروف و اعداد باشد.',createError:'ساخت کاربر ناموفق بود: ',changeError:'تغییر رمز ناموفق بود: ',xrayError:'آفلاین',subscriptionError:'دریافت لینک ناموفق بود: '},
en:{tagline:'PRIVATE CONTROL CENTER',quickDetails:'Quick details',latestService:'Latest service created',latestPanelChange:'Latest panel change',latestBackup:'Latest backup',notRecorded:'Not found in recent events',noneRecorded:'Not recorded',quickProfileChange:'Connection profiles were updated',quickServiceChange:'Service settings were updated',quickAccountChange:'Account details were updated',quickAccountCreate:'A new account was created',quickApiKeyChange:'An API key was changed',quickConfigChange:'Panel settings changed',quickBackupReady:'A database backup is ready',quickBackupRestored:'A database backup was restored',changePassword:'Change password',refresh:'Refresh',logout:'Sign out',total:'Total clients',active:'Active clients',xray:'Xray status',clients:'Client management',clientHelp:'Create services, control access and manage subscription links',search:'Search by name or ID…',name:'Client name',days:'Duration (days, optional)',quota:'Quota (GB, optional)',note:'Note (optional)',optional:'Leave duration and quota empty for unlimited access.',create:'+ Create client',events:'Recent events',settings:'Connection settings',settingsHelp:'Enable or disable the profiles available in Xray and client subscriptions.',profileWs:'WebSocket',profileUpgrade:'HTTPUpgrade',profileXhttpAuto:'XHTTP · auto',profileXhttpPacket:'XHTTP · packet-up',online:'Online',starting:'Starting',notInstalled:'Not installed',paused:'Paused',used:'Used',unlimited:'Unlimited',expires:'Expires',noExpiry:'No expiry',subscription:'Subscription',copy:'Copy link',edit:'Edit',resetUsage:'Reset usage',subTitle:'Subscription links',sharePage:'Share page for the client',rawSubscription:'Raw subscription URL for clients',copyPage:'Copy page link',copiedPage:'Page link copied.',copyRaw:'Copy raw link',openPage:'Open page',qrHint:'Scan the QR code to import quickly.',editName:'Client name:',editNote:'Note:',editDays:'Duration from today in days (blank = unlimited):',editQuota:'Quota in GB (blank = unlimited):',editSuccess:'Client details updated.',resetConfirm:'Reset this client’s recorded usage to zero?',resetSuccess:'Client usage reset to zero.',pause:'Pause',enable:'Enable',revoke:'Revoke',noClients:'No clients yet.',noResults:'No matches found.',connected:'Dashboard connected successfully.',apiError:'Dashboard API error: ',confirmRevoke:'Revoke this client and remove access?',copied:'Subscription link copied.',copyFail:'Could not copy automatically. Copy this URL:',currentPassword:'Current password:',newPassword:'New password (14+ characters, letters and numbers):',passwordChanged:'Password changed.',passwordRule:'Password must be at least 14 characters and include letters and numbers.',createError:'Could not create client: ',changeError:'Could not change password: ',xrayError:'Offline',subscriptionError:'Could not get subscription: '}
};
function tr(k){return (words[lang]||words.fa)[k]||k}
function applyLanguage(){document.documentElement.lang=lang;document.documentElement.dir=lang==='fa'?'rtl':'ltr';document.querySelectorAll('[data-i18n]').forEach(el=>el.textContent=tr(el.dataset.i18n));document.querySelectorAll('[data-i18n-placeholder]').forEach(el=>el.placeholder=tr(el.dataset.i18nPlaceholder));const langBtn=document.getElementById('langBtn');if(langBtn)langBtn.textContent=lang==='fa'?'English':'فارسی';const status=document.getElementById('status');if(status)status.textContent=tr('connected');renderClients();renderDashboardQuickDetails()}
function toggleLanguage(){lang=lang==='fa'?'en':'fa';localStorage.setItem('abyss-lang',lang);applyLanguage()}
async function api(u,o={}){const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),20000);try{const r=await fetch(u,{...o,headers:{...(o.headers||{}),'Content-Type':'application/json','X-CSRF-Token':csrf},signal:controller.signal}),d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.detail||'Request failed');return d}catch(e){if(controller.signal.aborted)throw Error('درخواست API پس از ۲۰ ثانیه پاسخ نداد.');throw e}finally{clearTimeout(timeout)}}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function renderDashboardQuickDetails(data=latestOverview){
 const host=document.getElementById('dashboardQuickDetails');
 if(!host)return;
 const events=Array.isArray(data?.events)?data.events:[];
 const clients=Array.isArray(data?.clients)?data.clients.slice():[];
 const latestClient=clients.sort((a,b)=>Date.parse(b.created_at||'')-Date.parse(a.created_at||''))[0]||null;
 const panelChange=events.find(e=>/Updated enabled connection profiles|Updated panel account |Updated client |Account password changed|Created panel account |Created reseller |Created bot API key |Revoked bot API key /i.test(String(e.message||'')))||null;
 const backup=events.find(e=>/Administrator created a database backup|Administrator downloaded a database backup|Database restore completed|Administrator restored a panel database backup/i.test(String(e.message||'')))||null;
 const when=value=>value?String(value).replace('T',' ').slice(0,16):tr('notRecorded');
 const eventTitle=(event,kind)=>{
  if(!event)return tr('notRecorded');
  const message=String(event.message||'');
  if(kind==='backup')return /restore/i.test(message)?tr('quickBackupRestored'):tr('quickBackupReady');
  if(/Updated enabled connection profiles/i.test(message))return tr('quickProfileChange');
  if(/Updated client /i.test(message))return tr('quickServiceChange');
  if(/Updated panel account |Account password changed/i.test(message))return tr('quickAccountChange');
  if(/Created panel account |Created reseller /i.test(message))return tr('quickAccountCreate');
  if(/bot API key/i.test(message))return tr('quickApiKeyChange');
  return tr('quickConfigChange');
 };
 const rows=[
  {key:'latestService',value:latestClient?.name||tr('noneRecorded'),meta:latestClient?when(latestClient.created_at):tr('noneRecorded')},
  {key:'latestPanelChange',value:eventTitle(panelChange,'change'),meta:when(panelChange?.at)},
  {key:'latestBackup',value:eventTitle(backup,'backup'),meta:when(backup?.at)}
 ];
 host.innerHTML=rows.map(row=>'<div class="quick-detail-row" role="listitem"><span class="quick-detail-copy"><span class="small">'+esc(tr(row.key))+'</span><small class="quick-detail-meta">'+esc(row.meta)+'</small></span><strong>'+esc(row.value)+'</strong></div>').join('');
}
function renderClients(){
 const term=(document.getElementById('search')?.value||'').trim().toLowerCase();
 const rows=allClients.filter(c=>(c.name+' '+c.id+' '+(c.note||'')).toLowerCase().includes(term));
 const pageSize=6;
 if(window.clientSearchTerm!==term){window.clientPage=1;window.clientSearchTerm=term;window.selectedClientId=null;}
 const selectedMatch=rows.find(c=>c.id===window.selectedClientId)||null;
 const pageCount=Math.max(1,Math.ceil(rows.length/pageSize));
 window.clientPage=Math.max(1,Math.min(pageCount,Number(window.clientPage)||1));
 if(selectedMatch)window.clientPage=Math.floor(rows.findIndex(c=>c.id===selectedMatch.id)/pageSize)+1;
 const pageRows=rows.slice((window.clientPage-1)*pageSize,window.clientPage*pageSize);
 const selected=pageRows.find(c=>c.id===window.selectedClientId)||pageRows[0]||null;
 window.selectedClientId=selected?selected.id:null;
 const host=document.getElementById('clients');
 if(host){
  host.innerHTML=rows.length?'<div class="clients-table-scroll"><table class="clients-table"><thead><tr><th>نام کاربر</th><th>وضعیت</th><th>مصرف / حجم</th><th>اعتبار</th><th>عملیات</th></tr></thead><tbody>'+pageRows.map(c=>'<tr class="'+(selected&&selected.id===c.id?'selected':'')+'" onclick="showClientDetails(\''+c.id+'\')"><td><div class="client-table-name">'+esc(c.name)+'</div><small>'+esc(c.id.slice(0,8))+'</small></td><td><span class="client-status '+(c.enabled?'good':'paused')+'">'+(c.enabled?'فعال':'متوقف')+'</span></td><td><strong><bdi dir="ltr">'+ (Number(c.used_bytes||0)/1073741824).toFixed(2)+' GB</bdi></strong><small>از <bdi dir="ltr">'+(c.quota_bytes===null?'نامحدود':(c.quota_bytes/1073741824).toFixed(2)+' GB')+'</bdi></small></td><td>'+(c.expires_at?esc(String(c.expires_at).slice(0,10)):'بدون انقضا')+'</td><td><div class="actions"><button class="copy-icon-btn" title="کپی لینک اشتراک" aria-label="کپی لینک اشتراک" onclick="event.stopPropagation();copyClientSub(\''+c.id+'\',this)">⧉</button><button title="جزئیات اشتراک" aria-label="جزئیات اشتراک" onclick="event.stopPropagation();sub(\''+c.id+'\')">↗</button><button title="ویرایش سرویس" aria-label="ویرایش سرویس" onclick="event.stopPropagation();editClient(\''+c.id+'\')">✎</button><button title="پروفایل‌ها" aria-label="پروفایل‌ها" onclick="event.stopPropagation();editClientProfiles(\''+c.id+'\')">⚙</button><button title="صفرکردن مصرف" aria-label="صفرکردن مصرف" onclick="event.stopPropagation();resetUsage(\''+c.id+'\')">↺</button><button title="'+(c.enabled?'توقف سرویس':'فعال‌سازی سرویس')+'" aria-label="'+(c.enabled?'توقف سرویس':'فعال‌سازی سرویس')+'" onclick="event.stopPropagation();toggle(\''+c.id+'\','+(!c.enabled)+')">'+(c.enabled?'Ⅱ':'▶')+'</button><button class="danger" title="حذف سرویس" aria-label="حذف سرویس" onclick="event.stopPropagation();revoke(\''+c.id+'\')">⌫</button></div></td></tr>').join('')+'</tbody></table></div><div class="client-pagination"><span>نمایش '+(((window.clientPage-1)*pageSize)+1)+' تا '+Math.min(window.clientPage*pageSize,rows.length)+' از '+rows.length+' کاربر</span><div><button type="button" '+(window.clientPage<=1?'disabled':'')+' onclick="setClientPage(-1)" aria-label="صفحه قبل">‹</button><span>صفحه '+window.clientPage+' از '+pageCount+'</span><button type="button" '+(window.clientPage>=pageCount?'disabled':'')+' onclick="setClientPage(1)" aria-label="صفحه بعد">›</button></div></div>':(allClients.length?(term?'<p class="small">'+tr('noResults')+'</p>':''):'<p class="small">'+tr('noClients')+'</p>');
 }
 const panel=document.getElementById('clientDetailsPanel');
 if(panel){
  if(!selected){panel.innerHTML='<div class="small">برای مشاهده جزئیات، نام کاربر را جست‌وجو یا انتخاب کن.</div>';return}
  const quota=selected.quota_bytes===null?'نامحدود':'<bdi dir="ltr">'+(selected.quota_bytes/1073741824).toFixed(2)+' GB</bdi>';
  const used='<bdi dir="ltr">'+(Number(selected.used_bytes||0)/1073741824).toFixed(3)+' GB</bdi>';
  const expires=selected.expires_at?esc(String(selected.expires_at).replace('T',' ').slice(0,16)):'بدون انقضا';
  panel.innerHTML='<div class="client-detail-head"><div class="client-detail-avatar">'+esc(String(selected.name||'?').slice(0,1).toUpperCase())+'</div><div><b>'+esc(selected.name)+'</b><div class="small">'+esc(selected.id.slice(0,12))+'</div></div><span class="client-status '+(selected.enabled?'good':'paused')+'">'+(selected.enabled?'فعال':'متوقف')+'</span></div><div class="client-detail-list"><div><span>وضعیت</span><b>'+(selected.enabled?'فعال':'متوقف')+'</b></div><div><span>مصرف ثبت‌شده</span><b>'+used+'</b></div><div><span>حجم کل</span><b>'+quota+'</b></div><div><span>تاریخ انقضا</span><b>'+expires+'</b></div><div><span>یادداشت</span><b>'+esc(selected.note||'—')+'</b></div></div><div class="client-detail-actions"><button type="button" onclick="sub(\''+selected.id+'\')">لینک اشتراک</button><button type="button" onclick="editClient(\''+selected.id+'\')">ویرایش سرویس</button><button type="button" onclick="editClientProfiles(\''+selected.id+'\')">پروفایل‌ها</button><button type="button" onclick="toggle(\''+selected.id+'\','+(!selected.enabled)+')">'+(selected.enabled?'توقف سرویس':'فعال‌سازی')+'</button></div>';
 }
}
function showClientDetails(id){window.selectedClientId=id;renderClients()}
function setClientPage(delta){const term=(document.getElementById('search')?.value||'').trim().toLowerCase();const count=allClients.filter(c=>(c.name+' '+c.id+' '+(c.note||'')).toLowerCase().includes(term)).length;const max=Math.max(1,Math.ceil(count/6));window.clientPage=Math.max(1,Math.min(max,(Number(window.clientPage)||1)+Number(delta||0)));window.selectedClientId=null;renderClients()}
async function copyClientSub(id,button){const before=button.innerHTML;try{const d=await api('/api/clients/'+id+'/subscription');const url=d.subscription_url||d.url||d.page_url;await navigator.clipboard.writeText(url);button.classList.add('copied');button.innerHTML='✓';button.title='کپی شد';setTimeout(()=>{button.classList.remove('copied');button.innerHTML=before;button.title='کپی لینک اشتراک'},1200)}catch(e){if(e.name==='NotAllowedError'){sub(id)}else alert(tr('subscriptionError')+e.message)}}
function renderSettings(profiles){const labels={ws:'profileWs',httpupgrade:'profileUpgrade',xhttp_auto:'profileXhttpAuto',xhttp_packet_up:'profileXhttpPacket'};document.getElementById('profileSettings').innerHTML=(profiles||[]).map(p=>'<label class="profile-setting"><input type="checkbox" '+(p.enabled?'checked':'')+' onchange="setProfile(\''+p.key+'\',this.checked)"><span>'+tr(labels[p.key]||p.label)+'</span></label>').join('')}

function renderProtocolCatalog(profiles){
 const el=document.getElementById('protocolCatalog');if(!el)return;
 const rows=profiles||[];
 el.innerHTML=rows.length?'<div class="protocol-table-scroll"><table class="protocol-table"><thead><tr><th>نام پروفایل</th><th>پروتکل</th><th>نوع اتصال / مسیر</th><th>پورت</th><th>وضعیت</th><th>عملیات</th></tr></thead><tbody>'+rows.map(p=>'<tr><td><b>'+esc(p.label)+'</b><small>'+esc(p.key)+'</small>'+(p.experimental?'<small class="experimental-label">آزمایشی · پیش‌فرض خاموش</small>':'')+'</td><td><strong>'+esc(p.protocol||'VLESS')+'</strong></td><td>'+esc(p.network||'—')+'<small>'+esc(p.path||'—')+(p.mode?' · '+esc(p.mode):'')+'</small></td><td>'+esc(p.port??'—')+'</td><td><span class="state-chip '+(p.enabled?'good':'neutral')+'">'+(p.enabled?'فعال':'خاموش')+'</span></td><td><label class="protocol-table-toggle"><input type="checkbox" '+(p.enabled?'checked':'')+' onchange="setProfile(\''+esc(p.key)+'\',this.checked)" aria-label="فعال یا خاموش کردن '+esc(p.label)+'"><span>فعال در Xray</span></label></td></tr>').join('')+'</tbody></table></div>':'<div class="small">پروفایلی در دسترس نیست.</div>';
}
async function loadProtocolCatalog(){try{const d=await api('/api/settings');renderProtocolCatalog(d.profiles||[])}catch(e){const el=document.getElementById('protocolCatalog');if(el)el.innerHTML='<div class="report-issue bad">دریافت پروفایل‌ها ناموفق بود: '+esc(e.message)+'</div>'}}
async function loadServerStatus(){const host=document.getElementById('serverHost'),grid=document.getElementById('serverStatusGrid'),overall=document.getElementById('serverOverall'),note=document.getElementById('serverStatusNote');if(host)host.textContent=location.host||'—';if(grid)grid.innerHTML='<article class="server-state"><div class="small">در حال بررسی اجزا…</div></article>';try{const [d,m]=await Promise.all([api('/api/system/diagnostics'),api('/api/system/metrics')]);const items=[{title:'پنل مدیریت',value:'در دسترس',ok:true,note:'درخواست احراز هویت‌شده پاسخ داد.'},{title:'Xray',value:d.xray_running?'در حال اجرا':d.xray_installed?'متوقف':'نصب‌نشده',ok:d.xray_running,note:d.xray_installed?'وضعیت پردازش Xray همین سرویس.':'باینری Xray در این کانتینر پیدا نشد.'},{title:'پیکربندی Xray',value:d.config_test?.ok?'معتبر':'نیازمند بررسی',ok:!!d.config_test?.ok,note:d.config_test?.ok?'پیکربندی Xray با موفقیت اعتبارسنجی شد.':String(d.config_test?.detail||'نتیجهٔ اعتبارسنجی در دسترس نیست.').slice(0,180)},{title:'Nginx',value:d.nginx_installed?(d.nginx_ok?'پیکربندی معتبر':'دارای خطا'):'مشخص نیست',ok:d.nginx_installed?!!d.nginx_ok:null,note:d.nginx_installed?(d.nginx_error||'نتیجهٔ آزمون nginx -t.'):'Nginx از مسیر بررسی این کانتینر شناسایی نشد.'},{title:'پایگاه‌داده',value:'قابل‌دسترسی',ok:true,note:'داده‌های وضعیت از API احراز هویت‌شده خوانده شدند.'},{title:'فضای ذخیره‌سازی',value:m.current?.disk_used_percent==null?'نامشخص':'دیسک قابل‌اندازه‌گیری',ok:m.current?.disk_used_percent!=null,note:m.current?.disk_used_percent==null?'آمار دیسک ارائه نشد.':'مصرف دیسک کانتینر: '+m.current.disk_used_percent+'%'}];if(grid)grid.innerHTML=items.map(x=>'<article class="server-state"><div class="state-title"><span>'+esc(x.title)+'</span><span class="state-chip '+(x.ok===true?'good':x.ok===false?'bad':'neutral')+'">'+(x.ok===true?'سالم':x.ok===false?'بررسی لازم':'نامشخص')+'</span></div><strong>'+esc(x.value)+'</strong><div class="small">'+esc(x.note)+'</div></article>').join('');const table=document.getElementById('serverTableBody');if(table)table.innerHTML='<tr><td>سرور جاری</td><td>'+esc(location.host||'—')+'</td><td><span class="state-chip '+(d.xray_running?'good':'bad')+'">'+(d.xray_running?'فعال':'متوقف')+'</span></td><td><span class="state-chip '+(d.ok?'good':'bad')+'">'+(d.ok?'سالم':'بررسی لازم')+'</span></td><td><button type="button" onclick="loadServerStatus()">بررسی مجدد</button></td></tr>';const pass=items.filter(x=>x.ok===true).length;if(overall){overall.className='state-chip '+(items.some(x=>x.ok===false)?'bad':'good');overall.textContent=pass+' از '+items.length+' بررسی موفق'}if(note)note.textContent=(d.note||'')+' · این گزارش وضعیت محلی همین استقرار است و اتصال واقعی از شبکهٔ کاربر را تأیید نمی‌کند.'}catch(e){if(grid)grid.innerHTML='<div class="report-issue bad">گرفتن وضعیت سرور ناموفق بود: '+esc(e.message)+'</div>';if(overall){overall.className='state-chip bad';overall.textContent='بررسی ناموفق'}if(note)note.textContent='پاسخ وضعیت سرور در دسترس نیست: '+e.message}}
async function loadDashboardHealth(){const el=document.getElementById('dashboardComponentStatus');if(!el)return;try{const d=await api('/api/system/diagnostics');const items=[{label:'Nginx',ok:d.nginx_installed?!!d.nginx_ok:null,value:d.nginx_installed?(d.nginx_ok?'فعال':'خطا'):'نامشخص'},{label:'Xray',ok:!!d.xray_running,value:d.xray_running?'فعال':d.xray_installed?'متوقف':'نصب‌نشده'},{label:'Database',ok:true,value:'قابل‌دسترسی'},{label:'Panel',ok:true,value:'فعال'}];el.innerHTML=items.map(x=>'<div class="dashboard-component"><span>'+esc(x.label)+'</span><span class="component-state '+(x.ok===true?'good':x.ok===false?'bad':'')+'">'+esc(x.value)+'</span></div>').join('')}catch(e){el.innerHTML='<div class="report-issue bad">دریافت وضعیت سرویس‌ها ناموفق بود: '+esc(e.message)+'</div>'}}
async function loadReports(){const summary=document.getElementById('reportSummary'),issues=document.getElementById('reportIssues'),profiles=document.getElementById('reportProfiles'),events=document.getElementById('reportEvents');if(summary)summary.textContent='در حال اجرای بررسی‌های واقعی…';try{const [d,o]=await Promise.all([api('/api/system/diagnostics'),api('/api/overview')]);if(summary)summary.textContent=(d.summary||'بررسی انجام شد.')+' · اتصال واقعی تونل از این صفحه تست نمی‌شود.';if(issues)issues.innerHTML=(d.issues||[]).map(x=>'<div class="report-issue '+(String(x).includes('خطا')||String(x).includes('متوقف')||String(x).includes('بسته')?'bad':'')+'">'+esc(x)+'</div>').join('')||'<div class="report-issue good">موردی برای گزارش وجود ندارد.</div>';if(profiles)profiles.innerHTML=(d.profiles||[]).map(p=>'<article class="report-state"><div class="state-title"><span>'+esc(p.label)+'</span><span class="state-chip '+(p.enabled&&p.listener_ok&&p.route_ok?'good':p.enabled?'bad':'neutral')+'">'+(p.enabled?(p.listener_ok&&p.route_ok?'مسیر پاسخ‌گو':'بررسی لازم'):'خاموش')+'</span></div><strong>'+esc(p.status_text||p.status||'—')+'</strong><div class="small">Listener: '+(p.listener_ok?'فعال':'غیرفعال')+' · HTTP '+esc(p.http_status??'—')+' · '+esc(p.latency_ms??'—')+' ms</div><div class="small" style="margin-top:6px">'+esc(p.hint||'')+'</div></article>').join('')||'<div class="small">پروفایلی ثبت نشده است.</div>';if(events){const rows=(o.events||[]).slice(0,12);events.innerHTML=rows.length?'<div class="report-event-table-wrap"><table class="report-event-table"><thead><tr><th scope="col">شرح رویداد</th><th scope="col">سطح</th><th scope="col">زمان</th></tr></thead><tbody>'+rows.map(e=>'<tr><td class="event-message">'+esc(e.message)+'</td><td><span class="event-level">'+esc(e.level)+'</span></td><td class="event-meta">'+esc(e.at)+'</td></tr>').join('')+'</tbody></table></div>':'<div class="small">رویدادی ثبت نشده است.</div>'}}catch(e){if(summary)summary.textContent='گزارش‌گیری ناموفق بود: '+e.message;if(issues)issues.innerHTML='<div class="report-issue bad">'+esc(e.message)+'</div>'}}

function renderClientProfileChoices(profiles){const el=document.getElementById('clientProfileChoices');if(!el)return;el.innerHTML=(profiles||[]).map(p=>'<label class="profile-setting" title="'+esc(p.label)+'"><input type="checkbox" name="clientProfile" value="'+esc(p.key)+'" '+(p.enabled?'checked':'')+(p.enabled?'':' disabled')+'><span>'+esc(p.label)+(p.enabled?'':' · غیرفعال')+'</span><span class="help-dot" title="این گزینه فقط همین پروفایل را برای این سرویس فعال می‌کند؛ پروفایل‌های خاموش سراسری قابل انتخاب نیستند.">؟</span></label>').join('')}

async function setProfile(key,enabled){try{const d=await api('/api/settings/profiles',{method:'PATCH',body:JSON.stringify({profiles:{[key]:enabled}})});renderSettings(d.profiles);renderProtocolCatalog(d.profiles);renderClientProfileChoices(d.profiles);await load()}catch(e){alert(e.message);await load()}}
let editingProfileClientId='';
async function editClientProfiles(id){const c=allClients.find(x=>x.id===id);if(!c)return;editingProfileClientId=id;document.getElementById('profilesClientName').textContent=c.name;try{const d=await api('/api/settings');let selected=null;try{selected=c.profile_keys?JSON.parse(c.profile_keys):null}catch(e){}document.getElementById('editClientProfileChoices').innerHTML=(d.profiles||[]).map(p=>'<label class="profile-setting"><input type="checkbox" name="editClientProfile" value="'+esc(p.key)+'" '+((selected===null?p.enabled:selected.includes(p.key))&&p.enabled?'checked':'')+(p.enabled?'':' disabled')+'><span>'+esc(p.label)+(p.enabled?'':' · غیرفعال')+'</span><span class="help-dot" title="این پروفایل برای همین سرویس فعال یا غیرفعال می‌شود.">؟</span></label>').join('');document.getElementById('profilesDialog').showModal()}catch(e){alert('دریافت پروفایل‌ها ناموفق بود: '+e.message)}}
async function saveClientProfiles(){const profiles=[...document.querySelectorAll('input[name="editClientProfile"]:checked')].map(x=>x.value);if(!profiles.length){alert('حداقل یک پروفایل فعال را انتخاب کن.');return}try{await api('/api/clients/'+editingProfileClientId,{method:'PATCH',body:JSON.stringify({profiles})});document.getElementById('profilesDialog').close();await load()}catch(e){alert('ذخیرهٔ پروفایل‌ها ناموفق بود: '+e.message)}}
function improveFieldLabels(){document.querySelectorAll('.workspace .fields > input[placeholder],.workspace .fields > select').forEach(el=>{if(el.closest('.field'))return;const title=el.getAttribute('placeholder')||el.getAttribute('aria-label')||el.options?.[el.selectedIndex]?.text||'تنظیم';const wrap=document.createElement('label');wrap.className='field';const caption=document.createElement('span');caption.textContent=title;if(el.dataset.i18nPlaceholder)caption.dataset.i18n=el.dataset.i18nPlaceholder;el.parentNode.insertBefore(wrap,el);wrap.append(caption,el);el.removeAttribute('placeholder')})}
async function load(){try{improveFieldLabels();applyLanguage();let d=await api('/api/overview');latestOverview=d;csrf=d.csrf;window.abyssRole=d.role;allClients=d.clients||[];const accountName=document.getElementById('accountUsername');if(accountName)accountName.textContent=d.user?.username||'مدیر پنل';const accountRole=document.getElementById('accountRole');if(accountRole)accountRole.textContent=d.user?.role==='owner'?'مدیر کل':d.user?.role==='reseller'?'نماینده':'مدیر';const backupCard=document.getElementById('backupCard'),settingsCard=document.getElementById('settingsCard');if(backupCard)backupCard.classList.toggle('hidden',d.role!=='root');if(settingsCard)settingsCard.classList.toggle('hidden',d.role!=='root');rootOnly(d.role==='root');const allocation=document.getElementById('allocationStatus');if(allocation)allocation.textContent=d.role==='root'?'مدیریت سهمیه و حساب‌های نمایندگی':('حجم باقی‌مانده برای تخصیص: '+(Number(d.remaining_bytes||0)/1073741824).toFixed(2)+' GB');renderResellers(d.resellers||[]);const total=document.getElementById('total'),active=document.getElementById('active'),xray=document.getElementById('xray'),events=document.getElementById('events');const sideUser=document.getElementById('sidebarAccountUsername'),sideRole=document.getElementById('sidebarAccountRole');if(sideUser)sideUser.textContent=d.user?.username||'admin';if(sideRole)sideRole.textContent=d.role==='root'?'مدیر کل':d.role==='reseller'?'نماینده':'مدیر';if(total)total.textContent=d.total;if(active)active.textContent=d.active;if(xray)xray.textContent=d.xray.running?tr('online'):d.xray.installed?tr('starting'):tr('notInstalled');const eventText=message=>{const value=String(message||''),plain=value.endsWith('.')?value.slice(0,-1):value;if(plain.startsWith('Administrator signed in as ')){if(plain.endsWith('(owner)'))return 'ورود مدیر کل انجام شد';if(plain.endsWith('(viewer)'))return 'ورود ناظر انجام شد';return 'ورود مدیر انجام شد'}if(plain.startsWith('Reseller ')&&plain.endsWith(' signed in'))return 'ورود نماینده انجام شد';if(plain==='Rejected administrator sign-in attempt')return 'تلاش ناموفق برای ورود مدیر ثبت شد';if(plain.startsWith('Visual preview: service created for '))return 'سرویس آزمایشی برای '+plain.slice('Visual preview: service created for '.length)+' ساخته شد';if(plain.startsWith('Created client ')||plain.startsWith('Bot API created client '))return 'سرویس جدید ساخته شد';if(plain.startsWith('Updated client ')||plain.startsWith('Bot API updated client '))return 'تنظیمات سرویس به‌روزرسانی شد';if(plain.startsWith('Reset usage for client ')||plain.startsWith('Bot API reset usage for client '))return 'مصرف ثبت‌شده سرویس صفر شد';if(plain.startsWith('Revoked client ')||plain.startsWith('Bot API revoked client '))return 'سرویس لغو شد';if(plain.startsWith('Client ')&&plain.includes(' automatically disabled: '))return 'سرویس به‌دلیل پایان اعتبار یا سهمیه غیرفعال شد';if(plain==='Updated enabled connection profiles')return 'پروفایل‌های اتصال فعال به‌روزرسانی شدند';if(plain==='Restarting stopped Xray process')return 'پردازش Xray متوقف شده بود و دوباره راه‌اندازی شد';if(plain.startsWith('Xray recovery failed:')||plain.startsWith('Automatic Xray repair failed:'))return 'بازیابی خودکار Xray ناموفق بود';if(plain.startsWith('Profile update rolled back'))return 'تغییر پروفایل‌ها به‌دلیل خطای Xray بازگردانده شد';if(plain.startsWith('Client creation rolled back'))return 'ساخت سرویس به‌دلیل خطای Xray لغو شد';if(plain.startsWith('Client update rolled back'))return 'تغییرات سرویس به‌دلیل خطای Xray بازگردانده شد';if(plain.startsWith('Client revocation rolled back'))return 'لغو سرویس به‌دلیل خطای Xray بازگردانده شد';if(plain==='Administrator created a database backup'||plain==='Administrator downloaded a database backup')return 'نسخه پشتیبان پایگاه داده آماده شد';if(plain==='Database restore completed; a pre-restore database copy was retained'||plain==='Administrator restored a panel database backup')return 'بازیابی پایگاه داده انجام شد و نسخه قبلی نگه‌داری شد';if(plain.startsWith('Created reseller '))return 'حساب نمایندگی با سهمیه ساخته شد';if(plain.startsWith('Created panel account '))return 'حساب مدیریتی جدید ساخته شد';if(plain.startsWith('Updated panel account '))return 'حساب مدیریتی به‌روزرسانی شد';if(plain.startsWith('Owner reset password for panel account '))return 'رمز عبور حساب مدیریتی بازنشانی شد';if(plain.startsWith('Created bot API key '))return 'کلید جدید ربات API ساخته شد';if(plain.startsWith('Revoked bot API key '))return 'کلید ربات API لغو شد';if(plain.startsWith('Safe Xray repair completed:'))return 'تعمیر ایمن Xray انجام شد';if(plain==='Account password changed')return 'رمز عبور حساب تغییر کرد';return value};const eventLevel=level=>({INFO:'اطلاعات',WARNING:'هشدار',WARN:'هشدار',ERROR:'خطا',DEBUG:'اشکال‌زدایی'}[String(level||'').toUpperCase()]||String(level||'—'));if(events)events.innerHTML=(d.events||[]).map(e=>'<div class="small">'+esc(e.at)+' · '+esc(eventLevel(e.level))+' · '+esc(eventText(e.message))+'</div>').join('')||'—';const recent=document.getElementById('recentActivityList');if(recent)recent.innerHTML=(d.events||[]).slice(0,4).map(e=>'<article class="report-event"><span class="event-message"><b>'+esc(eventText(e.message))+'</b></span><span class="event-meta">'+esc(String(e.at||'').replace('T',' ').slice(0,16))+' · '+esc(eventLevel(e.level))+'</span></article>').join('')||'<div class="small">هنوز رویدادی ثبت نشده است.</div>';const quickRows=document.querySelectorAll('#dashboardStatusAccessible .quick-detail-row strong');if(quickRows[0])quickRows[0].textContent=d.xray?.running?'متصل':d.xray?.installed?'متوقف':'نصب نشده';if(quickRows[1])quickRows[1].textContent=String(d.active??0)+' / '+String(d.total??0);renderDashboardQuickDetails(d);renderClients();const settings=await api('/api/settings');renderSettings(settings.profiles);renderProtocolCatalog(settings.profiles);renderClientProfileChoices(settings.profiles);const status=document.getElementById('status');if(status)status.textContent=tr('connected');if(d.role==='root'){await Promise.all([loadAdminUsers(),loadApiKeys()])}await loadMetrics();loadDashboardHealth()}catch(e){const status=document.getElementById('status');if(status)status.textContent=tr('apiError')+e.message;else console.error('Abyss dashboard load failed:',e)}}
function switchCreationTab(tab){const allowed=['general','limits','profiles'];if(!allowed.includes(tab))return;document.querySelectorAll('[data-creation-panel]').forEach(p=>{const active=p.dataset.creationPanel===tab;p.hidden=!active;p.classList.toggle('is-active',active)});document.querySelectorAll('.creation-tab[role="tab"]').forEach(b=>{const active=b.id===({general:'creationTabGeneral',limits:'creationTabLimits',profiles:'creationTabProfiles'}[tab]);b.classList.toggle('is-active',active);b.setAttribute('aria-selected',String(active))})}
async function add(){const input=document.getElementById('name'),days=document.getElementById('days'),quota=document.getElementById('quota'),note=document.getElementById('note');if(!input||!days||!quota||!note){alert('فرم ساخت کاربر با اسکریپت داشبورد هماهنگ نیست. صفحه را یک‌بار کامل تازه‌سازی کن.');return}if(!input.value.trim()){input.focus();alert('برای ساخت سرویس، نام کاربر را وارد کن.');return}const profiles=[...document.querySelectorAll('input[name="clientProfile"]:checked')].map(x=>x.value);if(!profiles.length){alert('حداقل یک پروفایل فعال را انتخاب کن.');return}try{await api('/api/clients',{method:'POST',body:JSON.stringify({name:input.value.trim(),duration_days:days.value?Number(days.value):null,quota_gb:quota.value?Number(quota.value):null,note:note.value,profiles})});input.value='';days.value='';quota.value='';note.value='';await load()}catch(e){alert(tr('createError')+e.message)}}
async function toggle(id,enabled){try{await api('/api/clients/'+id,{method:'PATCH',body:JSON.stringify({enabled})});await load()}catch(e){alert(e.message)}}
async function revoke(id){if(!confirm(tr('confirmRevoke')))return;try{await api('/api/clients/'+id,{method:'DELETE'});await load()}catch(e){alert(e.message)}}
async function sub(id){try{const d=await api('/api/clients/'+id+'/subscription');const c=allClients.find(x=>x.id===id);const url=d.subscription_url||d.url||d.page_url;document.getElementById('subClientName').textContent=c?c.name:id;document.getElementById('pageUrl').value=url;document.getElementById('openPage').href=url;document.getElementById('subQr').src=d.qr_url||'';document.getElementById('subDialog').showModal()}catch(e){alert(tr('subscriptionError')+e.message)}}
function closeSub(){document.getElementById('subDialog').close()}
async function copyField(id,button){const el=document.getElementById(id);try{await navigator.clipboard.writeText(el.value);if(button){const before=button.innerHTML;button.classList.add('copied');button.innerHTML='✓';button.setAttribute('aria-label','کپی شد');setTimeout(()=>{button.innerHTML=before;button.classList.remove('copied')},1100)}else{const note=document.getElementById('copyStatus');if(note)note.textContent=tr('copied')}}catch(e){el.focus();el.select();const note=document.getElementById('copyStatus');if(note)note.textContent=tr('copyFail')}}
async function editClient(id){const c=allClients.find(x=>x.id===id);if(!c)return;const name=prompt(tr('editName'),c.name);if(name===null)return;const note=prompt(tr('editNote'),c.note||'');if(note===null)return;const daysNow=c.expires_at?Math.max(1,Math.ceil((Date.parse(c.expires_at)-Date.now())/86400000)):'';const days=prompt(tr('editDays'),String(daysNow));if(days===null)return;const quotaNow=c.quota_bytes===null?'':String((c.quota_bytes/1073741824).toFixed(2));const quota=prompt(tr('editQuota'),quotaNow);if(quota===null)return;const changes={};if(name!==c.name)changes.name=name;if(note!==(c.note||''))changes.note=note;if(days.trim()!==String(daysNow))changes.duration_days=days.trim()?Number(days):null;if(quota.trim()!==quotaNow)changes.quota_gb=quota.trim()?Number(quota):null;if(!Object.keys(changes).length)return;try{await api('/api/clients/'+id,{method:'PATCH',body:JSON.stringify(changes)});await load();alert(tr('editSuccess'))}catch(e){alert(tr('changeError')+e.message)}}
async function resetUsage(id){if(!confirm(tr('resetConfirm')))return;try{await api('/api/clients/'+id+'/reset-usage',{method:'POST'});await load();alert(tr('resetSuccess'))}catch(e){alert(e.message)}}
async function changePassword(){let current=prompt(tr('currentPassword'));if(current===null)return;let next=prompt(tr('newPassword'));if(next===null)return;if(next.length<14||!/[A-Za-z]/.test(next)||!/[0-9]/.test(next)){alert(tr('passwordRule'));return}try{await api('/api/password',{method:'POST',body:JSON.stringify({current_password:current,new_password:next})});alert(tr('passwordChanged'))}catch(e){alert(tr('changeError')+e.message)}}
function renderResellers(rows){const el=document.getElementById('resellerList');if(!rows.length){el.innerHTML='<div class="small">نماینده‌ای ساخته نشده است.</div>';return}el.innerHTML=rows.map(x=>'<div class="client"><div class="client-info"><b>'+esc(x.username)+'</b><div class="small">'+(x.enabled?'فعال':'متوقف')+' · تخصیص '+(Number(x.quota_bytes)/1073741824).toFixed(2)+' GB · مصرف تخصیص‌یافته '+(Number(x.allocated_bytes||0)/1073741824).toFixed(2)+' GB · باقی‌مانده '+(Number(x.remaining_bytes||0)/1073741824).toFixed(2)+' GB</div></div><div class="actions"><button onclick="editReseller(\''+x.id+'\',\''+esc(x.username)+'\','+(Number(x.quota_bytes)/1073741824).toFixed(2)+')">ویرایش</button><button onclick="toggleReseller(\''+x.id+'\','+(!x.enabled)+')">'+(x.enabled?'توقف':'فعال‌سازی')+'</button><button class="danger" onclick="removeReseller(\''+x.id+'\')">حذف نماینده</button></div></div>').join('')}
async function addReseller(){const username=document.getElementById('resellerUsername').value.trim(),password=document.getElementById('resellerPassword').value,quota=Number(document.getElementById('resellerQuota').value);try{await api('/api/resellers',{method:'POST',body:JSON.stringify({username,password,quota_gb:quota})});document.getElementById('resellerUsername').value='';document.getElementById('resellerPassword').value='';document.getElementById('resellerQuota').value='';await load();alert('نماینده ساخته شد. نام کاربری و رمز را امن به صاحب آن بده.')}catch(e){alert('ساخت نماینده ناموفق بود: '+e.message)}}
async function editReseller(id,currentUsername,currentQuota){const username=prompt('نام کاربری جدید:',currentUsername);if(username===null)return;const quotaText=prompt('سهمیه کل نماینده (GB):',String(currentQuota));if(quotaText===null)return;const quota=Number(quotaText);if(!Number.isFinite(quota)||quota<0.1){alert('سهمیه نامعتبر است.');return}const password=prompt('رمز جدید (حداقل ۱۴ نویسه، خالی برای حفظ رمز):','');if(password===null)return;const body={username:username.trim(),quota_gb:quota};if(password)body.password=password;try{await api('/api/resellers/'+id,{method:'PATCH',body:JSON.stringify(body)});await load();alert('اطلاعات نماینده به‌روزرسانی شد.')}catch(e){alert('ویرایش ناموفق بود: '+e.message)}}
async function toggleReseller(id,enabled){try{await api('/api/resellers/'+id,{method:'PATCH',body:JSON.stringify({enabled})});await load()}catch(e){alert(e.message)}}
async function removeReseller(id){if(!confirm('نماینده حذف شود؟ ابتدا باید سهمیه‌های تخصیص‌یافته‌اش صفر باشد.'))return;try{await api('/api/resellers/'+id,{method:'DELETE'});await load()}catch(e){alert(e.message)}}
async function restoreBackup(){const f=document.getElementById('restoreFile').files[0];if(!f){alert('ابتدا فایل پشتیبان را انتخاب کن.');return}if(!confirm('بازیابی، پایگاه داده فعلی را جایگزین می‌کند. قبل از ادامه مطمئن شو فایل درست است.'))return;try{const fd=new FormData();fd.append('backup',f);const r=await fetch('/api/backup/restore',{method:'POST',headers:{'X-CSRF-Token':csrf},body:fd});const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.detail||'Restore failed');alert(d.message||'بازیابی انجام شد.');await load()}catch(e){alert('بازیابی ناموفق بود: '+e.message)}}
function runGlobalSearch(){const box=document.getElementById('globalSearch'),target=document.getElementById('search');if(!target)return;showSection('clients');target.value=box?box.value.trim():'';renderClients();target.focus()}
function showPanelHelp(){const dialog=document.getElementById('panelHelpDialog');if(dialog&&!dialog.open)dialog.showModal()}
function showSection(name){document.querySelectorAll('[data-section-page]').forEach(el=>{const inactive=el.dataset.sectionPage!==name;el.classList.toggle('nav-hidden',inactive);if(inactive)el.style.setProperty('display','none','important');else el.style.removeProperty('display')});document.querySelectorAll('[data-nav]').forEach(el=>el.classList.toggle('active',el.dataset.nav===name));document.querySelectorAll('[data-settings-tab]').forEach(el=>el.classList.toggle('active',el.dataset.settingsTab===name));const titles={dashboard:'داشبورد',clients:'مدیریت کاربران',create:'ساخت سرویس',servers:'مدیریت سرورها',protocols:'پروتکل‌ها',reports:'گزارش‌ها',reseller:'حساب‌های نمایندگی و سهمیه',settings:'تنظیمات اتصال',diagnostics:'عیب‌یابی هوشمند',backup:'پشتیبان‌گیری و بازیابی',metrics:'پایش زنده سرویس',admins:'مدیریت مدیران داشبورد',apikeys:'API و اتصال ربات',events:'رویدادهای اخیر'};const title=document.getElementById('sectionTitle');if(title)title.textContent=titles[name]||'Abyss Tunnel';const side=document.getElementById('sidebar');if(side&&innerWidth<=850)side.classList.remove('open');if(name==='servers')loadServerStatus();if(name==='reports')loadReports();if(name==='protocols')loadProtocolCatalog()}
function toggleSidebar(){const side=document.getElementById('sidebar');if(side)side.classList.toggle('open')}
function rootOnly(show){document.querySelectorAll('[data-owner-only]').forEach(el=>el.classList.toggle('hidden',!show))}
let trafficChartPeriod='24h';
let trafficMetricsRequestId=0;
async function loadMetrics(period=trafficChartPeriod){
 if(!['24h','7d','30d'].includes(period))period='24h';
 const requestId=++trafficMetricsRequestId;
 trafficChartPeriod=period;
 try{
  const d=await api('/api/system/metrics?period='+encodeURIComponent(period));
  // A slower response for an older period must never overwrite the current chart.
  if(requestId!==trafficMetricsRequestId||period!==trafficChartPeriod)return;
  const m=d.current||{};
  const set=(id,value)=>{const el=document.getElementById(id);if(el)el.textContent=value};
  set('metricCpu',m.cpu_percent==null?'—':m.cpu_percent+'%');
  set('metricRam',m.memory_used_percent==null?'—':m.memory_used_percent+'%');
  set('metricDisk',m.disk_used_percent==null?'—':m.disk_used_percent+'%');
  set('metricSpeed',((Number(m.traffic_bytes_per_second)||0)/1048576).toFixed(3)+' MB/s');
  set('metricLoad',Array.isArray(m.load_average)?m.load_average.join(' / '):'—');
  set('metricTraffic',((Number(m.recorded_traffic_bytes)||0)/1073741824).toFixed(3)+' GB');
  set('dashCpu',m.cpu_percent==null?'—':m.cpu_percent+'%');
  set('dashRam',m.memory_used_percent==null?'—':m.memory_used_percent+'%');
  set('dashDisk',m.disk_used_percent==null?'—':m.disk_used_percent+'%');
  set('dashboardTraffic',((Number(m.recorded_traffic_bytes)||0)/1073741824).toFixed(3)+' GB');
  document.querySelectorAll('[data-traffic-period]').forEach(button=>{
   const active=button.dataset.trafficPeriod===period;
   button.classList.toggle('is-active',active);button.setAttribute('aria-pressed',String(active));
  });
  drawUsageSparkline(d.traffic_history||[],period,Number(d.traffic_history_count)||0);
 }catch(e){
  if(requestId!==trafficMetricsRequestId)return;
  const el=document.getElementById('profileChecks');
  if(el)el.textContent='خطای پایش: '+e.message;
 }
}
function setTrafficChartPeriod(period){
 if(!['24h','7d','30d'].includes(period))return;
 trafficChartPeriod=period;
 document.querySelectorAll('[data-traffic-period]').forEach(button=>{
  const active=button.dataset.trafficPeriod===period;
  button.classList.toggle('is-active',active);button.setAttribute('aria-pressed',String(active));
 });
 loadMetrics(period);
}
function drawUsageSparkline(history,period,totalSamples){
 const c=document.getElementById('usageSparkline');if(!c)return;
 const points=Array.isArray(history)?history:[];
 const w=Math.max(260,Math.floor(c.clientWidth||600)),h=Math.max(108,Math.floor(c.clientHeight||144)),dpr=Math.min(devicePixelRatio||1,1.25);
 c.width=Math.round(w*dpr);c.height=Math.round(h*dpr);
 const ctx=c.getContext('2d');if(!ctx)return;
 ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,w,h);
 const root=getComputedStyle(document.documentElement);
 const grid=root.getPropertyValue('--ab-line').trim()||'rgba(170,174,182,.18)';
 const line=root.getPropertyValue('--chart-cpu').trim()||'#c8cad0';
 const muted=root.getPropertyValue('--ab-muted').trim()||'rgba(200,202,208,.7)';
 const left=43,right=w-8,top=12,bottom=h-22,plotH=bottom-top;
 const values=points.map(v=>Math.max(0,Number(v.recorded_traffic_bytes)||0)/1073741824);
 const rawMax=Math.max(0,...values),power=Math.pow(10,Math.floor(Math.log10(rawMax||1))),ratio=rawMax/power;
 const axisMax=(ratio<=1?1:ratio<=2?2:ratio<=5?5:10)*power;
 ctx.font='10px Vazirmatn,Tahoma,sans-serif';ctx.textAlign='right';ctx.textBaseline='middle';
 ctx.strokeStyle=grid;ctx.lineWidth=.65;
 for(let i=0;i<5;i++){
  const y=top+i*plotH/4,v=axisMax*(1-i/4);
  ctx.beginPath();ctx.moveTo(left,y);ctx.lineTo(right,y);ctx.stroke();
  ctx.fillStyle=muted;ctx.fillText(v.toLocaleString('en-US',{maximumFractionDigits:2})+' GB',left-6,y);
 }
 if(points.length){
  const point=(sample,i)=>{
   const value=Math.max(0,Number(sample.recorded_traffic_bytes)||0)/1073741824;
   return {x:points.length===1?right:left+i*(right-left)/(points.length-1),y:bottom-Math.min(1,value/axisMax)*plotH};
  };
  if(points.length>1){
   ctx.beginPath();points.forEach((sample,i)=>{const p=point(sample,i);if(i===0)ctx.moveTo(p.x,p.y);else ctx.lineTo(p.x,p.y)});
   ctx.lineTo(right,bottom);ctx.lineTo(left,bottom);ctx.closePath();ctx.globalAlpha=.17;ctx.fillStyle=line;ctx.fill();ctx.globalAlpha=1;
  }
  ctx.beginPath();points.forEach((sample,i)=>{const p=point(sample,i);if(i===0)ctx.moveTo(p.x,p.y);else ctx.lineTo(p.x,p.y)});
  ctx.strokeStyle=line;ctx.lineWidth=1.8;ctx.lineJoin='round';ctx.lineCap='round';ctx.stroke();
  const newest=point(points[points.length-1],points.length-1);
  ctx.beginPath();ctx.arc(newest.x,newest.y,2.5,0,Math.PI*2);ctx.fillStyle=line;ctx.fill();
  if(points.length>1){
   const stamp=sample=>{
    const d=new Date(Number(sample.at)*1000);
    return period==='24h'?d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',hourCycle:'h23'}):d.toLocaleDateString([],{month:'2-digit',day:'2-digit'});
   };
   const labels=[{i:0,x:left,align:'left'},{i:Math.floor((points.length-1)/2),x:(left+right)/2,align:'center'},{i:points.length-1,x:right,align:'right'}];
   ctx.fillStyle=muted;ctx.font='10px Vazirmatn,Tahoma,sans-serif';ctx.textBaseline='alphabetic';
   labels.forEach(item=>{ctx.textAlign=item.align;ctx.fillText(stamp(points[item.i]),item.x,h-4)});
  }
 }
 const note=document.getElementById('chartNote');
 const periodLabel={'24h':'۲۴ ساعت اخیر','7d':'۷ روز اخیر','30d':'۳۰ روز اخیر'}[period]||'بازهٔ انتخاب‌شده';
 if(note)note.textContent=totalSamples<2?'تاریخچهٔ مصرف واقعی در حال جمع‌آوری است؛ نمونه‌ها هر دقیقه ثبت می‌شوند.':periodLabel+' · '+totalSamples.toLocaleString('fa-IR')+' نمونهٔ واقعی';
 c.setAttribute('aria-label','نمودار واقعی مصرف ثبت‌شده بر حسب گیگابایت ('+period+'); '+points.length);
}
async function runDiagnostics(){const summary=document.getElementById('diagnosticSummary'),out=document.getElementById('diagnosticResults');if(summary)summary.textContent='در حال بررسی تنظیمات، Xray، Nginx و همه مسیرها…';if(out)out.innerHTML='';try{const carrier=document.getElementById('diagnosticCarrier')?.value||'mci';const d=await api('/api/system/diagnostics?carrier='+encodeURIComponent(carrier));if(summary)summary.textContent=d.summary+' · اپراتور: '+d.carrier_label+' · مسیر داخلی است، نه پینگ واقعی تونل.';if(out)out.innerHTML=(d.profiles||[]).map(p=>'<div class="diag-item"><b>'+esc(p.label)+'</b><div class="small">حالت: '+esc(p.mode||p.network)+' · HTTP '+esc(p.http_status??'—')+' · '+esc(p.latency_ms??'—')+' ms · گزارش: '+esc(p.feedback_reports??0)+' · موفقیت: '+(p.feedback_success_rate==null?'—':esc(p.feedback_success_rate)+'%')+'</div><div class="'+(p.route_ok?'diag-ok':'diag-bad')+'">'+esc(p.status_text||p.hint||p.status)+'</div><div class="small">پیشنهاد: '+esc(p.recommendation||p.hint||'—')+'</div></div>').join('')}catch(e){if(summary)summary.textContent='خطای عیب‌یابی: '+e.message}}
async function repairDiagnostics(){if(!confirm('اعتبارسنجی تنظیمات و راه‌اندازی مجدد امن انجام شود؟'))return;const summary=document.getElementById('diagnosticSummary');if(summary)summary.textContent='در حال اعتبارسنجی و تعمیر…';try{const d=await api('/api/system/diagnostics/repair',{method:'POST',body:JSON.stringify({})});if(summary)summary.textContent=d.message||'تعمیر انجام شد.';await runDiagnostics();await load()}catch(e){if(summary)summary.textContent='تعمیر ناموفق بود: '+e.message}}
async function checkProfileRoutes(){const el=document.getElementById('profileChecks');if(el)el.textContent='در حال بررسی Xray، پورت‌ها و مسیرهای وب…';try{const d=await api('/api/system/diagnostics');const lines=['Xray: '+(d.xray_running?'در حال اجرا':d.xray_installed?'نصب شده ولی اجرا نیست':'نصب نیست'),'آزمون تنظیمات: '+(d.config_test?.ok?'موفق':d.config_test?.status||'نامشخص'),...(d.issues||[]).map(x=>'⚠ '+x),...(d.profiles||[]).map(x=>x.label+': '+(x.status==='disabled'?'غیرفعال':(x.listener_ok?'پورت باز':'پورت بسته')+' · '+(x.route_ok?'مسیر وب پاسخ داد':'خطای مسیر')+' · تونل واقعی: تست نشده'))];if(el)el.textContent=lines.join('\n')}catch(e){if(el)el.textContent='خطای بررسی هوشمند: '+e.message}} async function repairXray(){if(!confirm('تنظیمات Xray بررسی و سرویس در صورت امکان دوباره راه‌اندازی می‌شود؛ اتصال‌های فعال ممکن است برای چند ثانیه قطع شوند. ادامه؟'))return;const el=document.getElementById('profileChecks');if(el)el.textContent='در حال اعتبارسنجی تنظیمات و تلاش برای راه‌اندازی مجدد Xray…';try{const d=await api('/api/system/diagnostics/repair',{method:'POST',body:JSON.stringify({})});if(el)el.textContent=d.message||'عملیات ترمیم تمام شد.';await checkProfileRoutes()}catch(e){if(el)el.textContent='ترمیم انجام نشد: '+e.message}}
async function loadAdminUsers(){const el=document.getElementById('adminUsersList');if(!el)return;try{const d=await api('/api/admin/users');el.innerHTML=(d.users||[]).map(u=>'<div class="client"><div class="client-info"><b>'+esc(u.username)+'</b><div class="small">'+esc(u.role)+' · '+(u.enabled?'فعال':'غیرفعال')+'</div></div><div class="actions"><button onclick="togglePanelAdmin(\''+u.id+'\','+(!u.enabled)+')">'+(u.enabled?'غیرفعال‌کردن':'فعال‌کردن')+'</button></div></div>').join('')||'<div class="small">حساب دیگری ثبت نشده است.</div>'}catch(e){el.textContent='خطای دریافت مدیران: '+e.message}}
async function createPanelAdmin(){const username=document.getElementById('adminUsername').value.trim(),password=document.getElementById('adminPassword').value,role=document.getElementById('adminRole').value;if(!username||password.length<14||!/[A-Za-z]/.test(password)||!/[0-9]/.test(password)){alert('نام کاربری را وارد کن؛ رمز باید حداقل ۱۴ نویسه و شامل حرف و عدد باشد.');return}try{await api('/api/admin/users',{method:'POST',body:JSON.stringify({username,password,role})});document.getElementById('adminUsername').value='';document.getElementById('adminPassword').value='';await loadAdminUsers();alert('حساب مدیر ساخته شد.')}catch(e){alert('ساخت حساب ناموفق بود: '+e.message)}}
async function togglePanelAdmin(id,enabled){try{await api('/api/admin/users/'+id,{method:'PATCH',body:JSON.stringify({enabled})});await loadAdminUsers()}catch(e){alert(e.message)}}
async function loadApiKeys(){const el=document.getElementById('apiKeysList');if(!el)return;try{const d=await api('/api/admin/api-keys');el.innerHTML=(d.keys||[]).map(k=>'<div class="client"><div class="client-info"><b>'+esc(k.name)+'</b><div class="small">'+esc(k.token_prefix)+' · '+esc((k.scopes||[]).join(', '))+' · '+(k.enabled?'فعال':'لغوشده')+'</div></div>'+(k.enabled?'<button class="danger" onclick="revokeApiKey(\''+k.id+'\')">لغو کلید</button>':'')+'</div>').join('')||'<div class="small">کلیدی ساخته نشده است.</div>'}catch(e){el.textContent='خطای دریافت کلیدها: '+e.message}}
async function createApiKey(){const name=document.getElementById('apiKeyName').value.trim(),expiry=document.getElementById('apiKeyExpiry').value,scopes=[...document.querySelectorAll('.apiScope:checked')].map(x=>x.value);if(!name||!scopes.length){alert('نام کلید و حداقل یک مجوز را انتخاب کن.');return}try{const d=await api('/api/admin/api-keys',{method:'POST',body:JSON.stringify({name,scopes,expires_in_days:expiry?Number(expiry):null})});document.getElementById('apiKeyName').value='';alert('این کلید فقط همین یک بار نمایش داده می‌شود؛ آن را در جای امن ذخیره کن:\n\n'+d.token);await loadApiKeys()}catch(e){alert('ساخت کلید ناموفق بود: '+e.message)}}
async function revokeApiKey(id){if(!confirm('این کلید API لغو شود؟'))return;try{await api('/api/admin/api-keys/'+id,{method:'DELETE'});await loadApiKeys()}catch(e){alert(e.message)}}
applyLanguage();showSection('dashboard');load();setInterval(()=>{if(document.visibilityState==='visible')loadMetrics()},15000);'''


# Abyss visual themes: royal-black/gold, angelic-white, and restrained color atmospheres.
ABYSS_THEME_CSS = r"""<style id="abyss-theme-system">
:root{--ab-bg:#050505;--ab-panel:rgba(16,16,18,.94);--ab-line:rgba(150,154,162,.20);--ab-accent:#bfc3ca;--ab-accent-hi:#e7e9ed;--ab-text:#f0f1f3;--ab-muted:#9b9ea5;--ab-glass:rgba(255,255,255,.035);--ab-glow:rgba(160,164,172,.055);--ab-input:rgba(7,7,8,.92);color-scheme:dark}
html[data-abyss-theme="abyss"]{--ab-bg:#050505;--ab-panel:rgba(15,15,17,.96);--ab-line:rgba(158,162,170,.20);--ab-accent:#c0c3ca;--ab-accent-hi:#f0f1f4;--ab-text:#f0f1f3;--ab-muted:#a0a2a8;--ab-glass:rgba(255,255,255,.035);--ab-glow:rgba(165,169,177,.055);--ab-input:rgba(7,7,8,.94);color-scheme:dark}
html[data-abyss-theme="angel"]{--ab-bg:#f4f3ef;--ab-panel:rgba(255,255,253,.97);--ab-line:rgba(163,148,119,.24);--ab-accent:#a8956f;--ab-accent-hi:#c5b48f;--ab-text:#292a2d;--ab-muted:#77766f;--ab-glass:rgba(164,149,119,.055);--ab-glow:rgba(188,173,143,.075);--ab-input:rgba(255,255,252,.98);color-scheme:light}
html[data-abyss-theme="graphite"]{--ab-bg:#111214;--ab-panel:rgba(26,27,30,.98);--ab-line:rgba(185,187,192,.17);--ab-accent:#b8bbc2;--ab-accent-hi:#f0f1f3;--ab-text:#eceef1;--ab-muted:#a3a6ad;--ab-glass:rgba(255,255,255,.025);--ab-glow:rgba(255,255,255,.025);--ab-input:rgba(18,19,21,.98);color-scheme:dark}
html[data-abyss-theme="slate"]{--ab-bg:#121820;--ab-panel:rgba(25,33,43,.98);--ab-line:rgba(151,171,190,.18);--ab-accent:#aebdcb;--ab-accent-hi:#e6edf3;--ab-text:#edf2f6;--ab-muted:#a5b0bb;--ab-glass:rgba(255,255,255,.03);--ab-glow:rgba(151,171,190,.035);--ab-input:rgba(15,21,28,.98);color-scheme:dark}
html[data-abyss-theme="ocean"]{--ab-bg:#071216;--ab-panel:rgba(17,31,37,.98);--ab-line:rgba(117,176,195,.20);--ab-accent:#9ac4ce;--ab-accent-hi:#d8edf1;--ab-text:#eaf4f5;--ab-muted:#a0b8bf;--ab-glass:rgba(255,255,255,.03);--ab-glow:rgba(57,133,157,.05);--ab-input:rgba(7,17,21,.98);color-scheme:dark}
html[data-abyss-theme="emerald"]{--ab-bg:#0c130e;--ab-panel:rgba(20,32,24,.98);--ab-line:rgba(135,181,145,.20);--ab-accent:#b0c9a8;--ab-accent-hi:#e0eedb;--ab-text:#edf4ed;--ab-muted:#a8b8aa;--ab-glass:rgba(255,255,255,.03);--ab-glow:rgba(87,140,91,.05);--ab-input:rgba(8,15,10,.98);color-scheme:dark}
html[data-abyss-theme="paper"]{--ab-bg:#f3f4f5;--ab-panel:rgba(255,255,255,.98);--ab-line:rgba(65,74,84,.15);--ab-accent:#5e6b79;--ab-accent-hi:#34404b;--ab-text:#252a30;--ab-muted:#6f7881;--ab-glass:rgba(30,40,50,.025);--ab-glow:rgba(90,100,110,.035);--ab-input:rgba(255,255,255,.99);color-scheme:light}
html,body{min-height:100%;background:var(--ab-bg)!important;color:var(--ab-text)!important}
body{position:relative;background-image:radial-gradient(ellipse at 82% 14%,var(--ab-glow),transparent 37%),radial-gradient(ellipse at 14% 78%,var(--ab-glow),transparent 42%)!important;background-size:100% 100%;animation:none!important}
body:before{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.14;background:radial-gradient(ellipse at 18% 20%,var(--ab-glow),transparent 32%),radial-gradient(ellipse at 82% 80%,var(--ab-glow),transparent 38%);animation:none!important}
body:after{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.075;background-image:radial-gradient(1px 1px at 12% 18%,var(--ab-accent-hi) 98%,transparent),radial-gradient(1px 1px at 79% 32%,var(--ab-text) 98%,transparent),radial-gradient(1px 1px at 37% 72%,var(--ab-accent) 98%,transparent),radial-gradient(1px 1px at 88% 86%,var(--ab-text) 98%,transparent),radial-gradient(1px 1px at 55% 14%,var(--ab-accent-hi) 98%,transparent);background-size:370px 310px}
body>*{position:relative;z-index:1}
.app-shell,.workspace{background:transparent!important}
.sidebar,.card,.panel,.box,.hero,.metric,.extra-box,.metric-pill,.profile-setting,.profile,.carrier-tools,.client{background:var(--ab-panel)!important;border-color:var(--ab-line)!important;backdrop-filter:blur(8px) saturate(108%);-webkit-backdrop-filter:blur(8px) saturate(108%);box-shadow:0 10px 28px rgba(0,0,0,.08)}
.sidebar{background:linear-gradient(165deg,var(--ab-panel),color-mix(in srgb,var(--ab-bg) 80%,transparent))!important}
input,select,textarea,.linkbox{background:var(--ab-input)!important;color:var(--ab-text)!important;border-color:var(--ab-line)!important}
button,.btn,a.button,.button-link,.nav-item,.profile-marks button{background:var(--ab-glass)!important;color:var(--ab-text)!important;border:1px solid var(--ab-line)!important;backdrop-filter:blur(5px) saturate(108%);-webkit-backdrop-filter:blur(5px) saturate(108%);box-shadow:inset 0 1px 0 rgba(255,255,255,.025),0 5px 14px rgba(0,0,0,.06);transition:background .16s ease,border-color .16s ease,transform .16s ease,box-shadow .16s ease}
button.primary,.btn.primary,.button-link.primary{background:linear-gradient(135deg,var(--ab-glass),color-mix(in srgb,var(--ab-accent) 16%,transparent))!important;color:var(--ab-accent-hi)!important;border-color:color-mix(in srgb,var(--ab-accent) 58%,transparent)!important}
button:hover,.btn:hover,a.button:hover,.button-link:hover,.nav-item:hover,.profile:hover{border-color:color-mix(in srgb,var(--ab-accent) 68%,transparent)!important;background:color-mix(in srgb,var(--ab-accent) 15%,transparent)!important;transform:translateY(-1px)}
.nav-item.active{color:var(--ab-accent-hi)!important;border-color:var(--ab-line)!important;background:color-mix(in srgb,var(--ab-accent) 14%,transparent)!important;box-shadow:inset -3px 0 var(--ab-accent),0 8px 24px rgba(0,0,0,.08)!important}
.mint,.eyebrow,.brand,.side-brand,.nav-item.active,.profile-open,#status,.section-title{color:var(--ab-accent)!important}
.muted,small,.small,.side-caption,.field,.sub-field label{color:var(--ab-muted)!important}
.badge{color:var(--ab-accent-hi)!important;border-color:var(--ab-line)!important;background:var(--ab-glass)!important}
.gauge{background:conic-gradient(var(--ab-accent) calc(var(--value)*1%),var(--ab-line) 0)!important}.gauge:before{background:var(--ab-bg)!important;border-color:var(--ab-line)!important}
dialog{background:var(--ab-bg)!important;color:var(--ab-text)!important;border-color:var(--ab-line)!important}dialog::backdrop{background:rgba(0,0,0,.48)!important;backdrop-filter:blur(12px)}
#abyssThemeDock{display:inline-flex;align-items:center;gap:8px;max-width:100%;padding:6px 10px;border:1px solid var(--ab-line);border-radius:999px;background:var(--ab-glass);color:var(--ab-text);backdrop-filter:blur(18px) saturate(140%);-webkit-backdrop-filter:blur(18px) saturate(140%);box-shadow:0 8px 28px rgba(0,0,0,.10);font:12px system-ui,sans-serif;white-space:nowrap}
#abyssThemeDock .theme-mark{color:var(--ab-accent);font-size:14px}#abyssThemeSelect{width:auto;max-width:165px;min-width:0;margin:0;padding:4px 19px 4px 5px;border:0!important;outline:none;background:transparent!important;color:var(--ab-text)!important;font:inherit;box-shadow:none!important}#abyssThemeSelect option{background:var(--ab-bg);color:var(--ab-text)}
#abyssThemeDock.floating{position:fixed;top:14px;right:14px;z-index:9999}
@keyframes abyssAtmosphere{0%{background-position:0% 0%}100%{background-position:100% 100%}}@keyframes abyssOrbit{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
html[data-abyss-theme="angel"] body:before{opacity:.55;background:radial-gradient(circle at 72% 23%,transparent 0 49px,rgba(163,146,111,.27) 50px,transparent 54px),radial-gradient(circle at 72% 23%,transparent 0 82px,rgba(163,146,111,.16) 83px,transparent 85px),radial-gradient(ellipse at 48% 8%,rgba(255,255,255,.94),transparent 52%),radial-gradient(ellipse at 12% 86%,rgba(207,215,232,.60),transparent 40%)}
html[data-abyss-theme="angel"] body:after{opacity:.23;background-image:radial-gradient(1px 1px at 12% 18%,#b29c6b 98%,transparent),radial-gradient(1px 1px at 79% 32%,#a9b4c8 98%,transparent),radial-gradient(1px 1px at 37% 72%,#c1ad7b 98%,transparent)}
html[data-abyss-theme="angel"] .card,html[data-abyss-theme="angel"] .panel,html[data-abyss-theme="angel"] .hero,html[data-abyss-theme="angel"] .sidebar{box-shadow:0 18px 48px rgba(74,77,93,.08),inset 0 1px rgba(255,255,255,.75)}
@media(max-width:700px){#abyssThemeDock{gap:5px;padding:5px 8px}#abyssThemeSelect{max-width:130px;font-size:11px}#abyssThemeDock.floating{top:10px;right:10px}}
@media(prefers-reduced-motion:reduce){body{animation:none!important}body:before{animation:none!important}*,*:before,*:after{transition:none!important}}
.abyss-logo-image{display:block;width:30px;height:30px;flex:0 0 30px;object-fit:cover;object-position:center;border-radius:50%;overflow:hidden;mix-blend-mode:screen;filter:brightness(1.25) contrast(1.12) drop-shadow(0 0 6px rgba(205,210,218,.25))}
.abyss-logo-mark:before{content:"";position:absolute;inset:-2px;border-radius:50%;background:repeating-conic-gradient(from 0deg,rgba(210,213,218,.6) 0deg .55deg,transparent .7deg 3.2deg);mask:radial-gradient(circle,transparent 0 27%,#000 30% 63%,transparent 76%);opacity:.62}
.abyss-brand-row{display:flex;align-items:center;gap:9px;letter-spacing:.14em;min-width:0;overflow:visible}.abyss-brand-row .brand-name{display:grid;gap:3px;min-width:0;overflow:visible;line-height:1.35}.abyss-brand-row small{font-size:9px;letter-spacing:.18em;opacity:.8;line-height:1.5}.side-brand.abyss-brand-row{gap:10px;min-height:56px;padding-inline:10px;overflow:visible}.side-brand .abyss-logo-image{width:40px;height:40px;flex:0 0 40px}.side-brand .abyss-logo-mark{display:block;width:30px;height:30px;flex:0 0 30px;border-radius:50%;position:relative}.side-brand .brand-name{white-space:nowrap;font-size:12px;letter-spacing:.09em}.side-brand .brand-name small{font-size:8px;letter-spacing:.16em}.login-brand{justify-content:center;margin:8px 0 22px;font-size:14px}.login-brand .abyss-logo-image{width:56px;height:56px;flex-basis:56px}.login-brand .abyss-logo-mark:before{inset:-4px}
#abyssThemeDock{box-shadow:none!important;backdrop-filter:none!important;background:var(--ab-panel)!important}
#abyssParticleCanvas{position:fixed!important;inset:0;width:100%;height:100%;pointer-events:none;z-index:0!important;opacity:.68}
.sidebar-quick-actions{display:grid;grid-template-columns:1fr 1fr;gap:7px;margin:16px 4px 6px;padding-top:14px;border-top:1px solid var(--ab-line)}.sidebar-quick-actions button{min-width:0;min-height:38px;padding:8px 7px;border:1px solid var(--ab-line);border-radius:10px;background:var(--ab-glass);color:var(--ab-text);font:inherit;font-size:11px;white-space:normal;overflow-wrap:anywhere}.sidebar-quick-actions button[data-i18n="changePassword"]{grid-column:1/-1}.sidebar-quick-actions .sidebar-logout{border-color:#583434;color:#e2aaaa;background:linear-gradient(145deg,#211414,#110c0c)}.abyss-utility-links{display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-top:16px;margin-bottom:12px}
.abyss-utility-links a{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:8px 10px;min-height:34px;border:1px solid var(--ab-line);border-radius:10px;background:var(--ab-glass);color:var(--ab-muted);font-size:11px;text-decoration:none;transition:border-color .16s ease,color .16s ease}
.abyss-utility-links a:hover{border-color:var(--ab-accent);color:var(--ab-text)}
.help-dot{display:inline-grid;place-items:center;width:17px;height:17px;margin-inline-start:5px;border:1px solid var(--ab-line);border-radius:50%;font-size:10px;color:var(--ab-accent);cursor:help;vertical-align:middle}
.client .actions button{min-width:38px;padding:7px 9px;font-size:12px}
.copy-icon-btn{width:38px;min-width:38px!important;padding:6px!important}
.copy-icon-btn.copied{color:#72d7a0!important;border-color:#72d7a0!important}
#usageSparkline{width:100%;height:88px;display:block}.workspace .stats>.card{min-width:0;max-width:100%}.workspace .stats>.card .num{min-width:0;max-width:100%;overflow-wrap:anywhere;word-break:normal;line-height:1.35}#dashboardTraffic{display:block;width:100%;min-width:0;max-width:100%;font-size:clamp(18px,2vw,26px)!important;letter-spacing:-.035em;line-height:1.3;direction:ltr;unicode-bidi:isolate;text-align:right;overflow-wrap:anywhere}.side-brand .abyss-logo-image{filter:drop-shadow(0 0 7px rgba(205,210,218,.28))}
@media(min-width:851px){.app-shell{width:100%;max-width:none;grid-template-columns:260px minmax(0,1fr)}.workspace{width:100%;max-width:none;padding-inline:clamp(20px,2.2vw,42px)}.workspace>section.card,.workspace>.stats{width:100%}}
@media(max-width:850px){.abyss-utility-links a{min-height:40px}.workspace{max-width:100%}.sidebar{backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}}
@media(prefers-reduced-motion:reduce){#abyssParticleCanvas{display:none!important}}

/* Use the exact user-approved AbyssTunnel image, including compact sidebar and subscription marks. */
.abyss-logo-mark{background-image:url('/brand/abyss-tunnel-logo.jpg')!important;background-size:150% 150%!important;background-position:center top!important;background-repeat:no-repeat!important;background-color:#050505!important;overflow:hidden!important}
.abyss-logo-mark:before{content:none!important;display:none!important}
</style>"""
ABYSS_THEME_POLISH_CSS = r"""<style id="abyss-theme-polish">
:root{--ab-radius-xl:25px;--ab-radius-lg:20px;--ab-radius-md:14px;--ab-radius-sm:11px;--ab-motion:.24s}
html{scroll-behavior:smooth;scroll-padding-top:20px}
body{background-image:radial-gradient(ellipse at 12% 8%,color-mix(in srgb,var(--ab-accent) 10%,transparent),transparent 36%),radial-gradient(ellipse at 88% 72%,var(--ab-glow),transparent 43%),radial-gradient(ellipse at 48% 110%,color-mix(in srgb,var(--ab-text) 4%,transparent),transparent 48%),linear-gradient(145deg,var(--ab-bg),color-mix(in srgb,var(--ab-bg) 82%,var(--ab-accent) 4%));background-size:160% 160%;animation:abyssGlowDrift 38s ease-in-out infinite alternate}
body:before{opacity:.43}
body:after{opacity:.13;background-size:370px 310px}
@keyframes abyssGlowDrift{0%{background-position:0% 0%}50%{background-position:65% 25%}100%{background-position:100% 100%}}
.card,.panel,.box,.section,.stat,.metric,.hero,.extra-box,.metric-pill,.profile-setting,.profile,.app,.client,.client-card,.section-head,.api-key-row{border-radius:var(--ab-radius-lg)!important;border-color:var(--ab-line)!important;background:linear-gradient(145deg,color-mix(in srgb,var(--ab-panel) 92%,var(--ab-accent) 3%),var(--ab-panel))!important;box-shadow:0 16px 42px rgba(0,0,0,.10),inset 0 1px 0 color-mix(in srgb,var(--ab-text) 5%,transparent)!important;transition:background var(--ab-motion) ease,border-color var(--ab-motion) ease,box-shadow var(--ab-motion) ease,transform var(--ab-motion) ease}
.card,.panel,.box,.hero,.extra-box,.metric,.metric-pill,.profile-setting,.profile,.app,.client,.client-card{backdrop-filter:blur(20px) saturate(125%);-webkit-backdrop-filter:blur(20px) saturate(125%)}
.card:hover,.panel:hover,.box:hover,.profile:hover,.app:hover,.client-card:hover{border-color:color-mix(in srgb,var(--ab-accent) 34%,var(--ab-line))!important;box-shadow:0 18px 46px rgba(0,0,0,.13),0 0 24px color-mix(in srgb,var(--ab-glow) 70%,transparent)!important}
.stats>.card:first-child,.stats>.card:nth-child(3),.hero,.subscription-hero,.usage-card,.highlight,.featured,.metric-pill{background:radial-gradient(ellipse at 95% 0%,color-mix(in srgb,var(--ab-accent) 12%,transparent),transparent 62%),linear-gradient(145deg,color-mix(in srgb,var(--ab-panel) 86%,var(--ab-accent) 6%),var(--ab-panel))!important;border-color:color-mix(in srgb,var(--ab-accent) 32%,var(--ab-line))!important;box-shadow:0 16px 42px rgba(0,0,0,.12),0 0 28px color-mix(in srgb,var(--ab-glow) 55%,transparent),inset 0 1px 0 color-mix(in srgb,var(--ab-text) 7%,transparent)!important}
.sidebar{border-radius:0!important;box-shadow:inset -1px 0 color-mix(in srgb,var(--ab-line) 80%,transparent),10px 0 42px rgba(0,0,0,.08)!important}
.section-heading,.section-title,.section-head h2{letter-spacing:-.015em}
.section-title:before,.section-heading:before,.section-head h2:before{content:"";display:inline-block;width:4px;height:1em;margin-left:10px;vertical-align:-.13em;border-radius:99px;background:var(--ab-accent);box-shadow:0 0 14px var(--ab-glow)}
button,.btn,a.button,.button-link,.nav-item,.profile-marks button{min-height:40px;border-radius:13px!important;transition:background var(--ab-motion) ease,border-color var(--ab-motion) ease,box-shadow var(--ab-motion) ease,transform var(--ab-motion) ease!important}
button:hover,.btn:hover,a.button:hover,.button-link:hover,.nav-item:hover,.profile:hover{transform:translateY(-1px)}
button.primary,.btn.primary,.button-link.primary{box-shadow:0 8px 24px color-mix(in srgb,var(--ab-glow) 80%,transparent),inset 0 1px 0 rgba(255,255,255,.08)!important}
input,select,textarea,.linkbox{border-radius:13px!important;min-height:42px;transition:border-color var(--ab-motion) ease,box-shadow var(--ab-motion) ease,background var(--ab-motion) ease}
input:focus,select:focus,textarea:focus,.linkbox:focus{border-color:color-mix(in srgb,var(--ab-accent) 68%,var(--ab-line))!important;box-shadow:0 0 0 3px color-mix(in srgb,var(--ab-accent) 13%,transparent)!important;outline:none}
:focus-visible{outline:2px solid var(--ab-accent)!important;outline-offset:3px}
.badge,.pill,.tag{border-radius:999px!important}
dialog{border-radius:25px!important;box-shadow:0 28px 100px rgba(0,0,0,.25),0 0 40px color-mix(in srgb,var(--ab-glow) 55%,transparent)!important}
#abyssThemeDock{border-radius:999px!important}
html[data-abyss-theme="angel"] body:before{opacity:.28}
html[data-abyss-theme="angel"] body:after{opacity:.075}
html[data-abyss-theme="angel"] .card,html[data-abyss-theme="angel"] .panel,html[data-abyss-theme="angel"] .box,html[data-abyss-theme="angel"] .hero,html[data-abyss-theme="angel"] .profile,html[data-abyss-theme="angel"] .app{box-shadow:0 15px 40px rgba(75,79,96,.075),inset 0 1px 0 rgba(255,255,255,.78)!important}
html[data-abyss-theme="angel"] button.primary,html[data-abyss-theme="angel"] .btn.primary,html[data-abyss-theme="angel"] .button-link.primary{color:var(--ab-accent)!important;border-color:color-mix(in srgb,var(--ab-accent) 45%,transparent)!important;background:linear-gradient(135deg,rgba(255,255,255,.85),color-mix(in srgb,var(--ab-accent) 10%,white))!important}
@media(max-width:700px){:root{--ab-radius-xl:22px;--ab-radius-lg:18px}.card,.panel,.box,.hero,.extra-box,.metric,.profile,.app,.client,.client-card{padding:clamp(12px,3.5vw,18px)}button,.btn,a.button,.button-link{min-height:42px}.stats>.card:first-child,.stats>.card:nth-child(3){box-shadow:0 12px 30px rgba(0,0,0,.10),0 0 18px color-mix(in srgb,var(--ab-glow) 50%,transparent)!important}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}body{animation:none!important}*,*:before,*:after{transition:none!important;animation:none!important;scroll-behavior:auto!important}}
.diag-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-top:12px}.diag-item{padding:13px;border:1px solid var(--ab-line);border-radius:15px;background:var(--ab-panel);min-width:0}.diag-item b{display:block;margin-bottom:7px;overflow-wrap:anywhere}.diag-ok{color:#8de8b0}.diag-bad{color:#ffb2b2}
/* Reference-led finish: Abyss is true black/graphite; Angel is ivory with aged gold and silver. */
html[data-abyss-theme="abyss"] body{
 background-image:
  linear-gradient(118deg,transparent 0 18%,rgba(190,194,202,.022) 18.1%,transparent 18.35% 56%,rgba(190,194,202,.028) 56.1%,transparent 56.4%),
  linear-gradient(164deg,transparent 0 38%,rgba(255,255,255,.018) 38.1%,transparent 38.32% 76%,rgba(180,184,192,.02) 76.1%,transparent 76.35%),
  radial-gradient(ellipse at 12% 10%,rgba(185,189,198,.055),transparent 34%),
  radial-gradient(ellipse at 88% 78%,rgba(110,113,120,.045),transparent 38%),
  linear-gradient(145deg,#030303,#09090a 58%,#040404)!important;
 background-size:180% 180%;animation:abyssGlowDrift 42s ease-in-out infinite alternate!important
}
html[data-abyss-theme="abyss"] body:before{
 opacity:.34!important;
 background-image:linear-gradient(128deg,transparent 0 24%,rgba(190,194,202,.055) 24.08%,transparent 24.22% 68%,rgba(190,194,202,.04) 68.08%,transparent 68.24%),radial-gradient(ellipse at 82% 12%,rgba(210,213,220,.07),transparent 42%)!important
}
html[data-abyss-theme="abyss"] .card,
html[data-abyss-theme="abyss"] .panel,
html[data-abyss-theme="abyss"] .hero,
html[data-abyss-theme="abyss"] .metric,
html[data-abyss-theme="abyss"] .profile,
html[data-abyss-theme="abyss"] .client,
html[data-abyss-theme="abyss"] .sidebar{
 border-color:rgba(174,178,187,.19)!important;
 background:linear-gradient(145deg,rgba(20,20,22,.96),rgba(8,8,9,.97))!important;
 box-shadow:0 20px 55px rgba(0,0,0,.30),inset 0 1px 0 rgba(255,255,255,.035)!important
}
html[data-abyss-theme="abyss"] .mint,
html[data-abyss-theme="abyss"] .brand,
html[data-abyss-theme="abyss"] .side-brand,
html[data-abyss-theme="abyss"] .nav-item.active,
html[data-abyss-theme="abyss"] .section-title,
html[data-abyss-theme="abyss"] .profile-open{color:#d0d2d7!important}
html[data-abyss-theme="abyss"] button.primary,
html[data-abyss-theme="abyss"] .btn.primary,
html[data-abyss-theme="abyss"] .button-link.primary{
 color:#f0f0f2!important;border-color:rgba(196,199,205,.42)!important;
 background:linear-gradient(145deg,rgba(225,227,232,.13),rgba(95,97,103,.08))!important
}
html[data-abyss-theme="abyss"] .nav-item.active{box-shadow:inset -3px 0 #c4c7cd,0 8px 24px rgba(0,0,0,.15)!important}
html[data-abyss-theme="abyss"] .abyss-logo-mark:before{background:repeating-conic-gradient(from 0deg,rgba(213,216,222,.7) 0deg .55deg,transparent .7deg 3.2deg)}
html[data-abyss-theme="angel"] body{
 background-image:linear-gradient(122deg,transparent 0 20%,rgba(174,151,104,.045) 20.1%,transparent 20.3% 62%,rgba(172,179,193,.055) 62.1%,transparent 62.35%),radial-gradient(ellipse at 78% 5%,rgba(255,255,255,.98),transparent 44%),radial-gradient(ellipse at 12% 86%,rgba(209,214,225,.46),transparent 42%),linear-gradient(145deg,#faf9f5,#efede6 68%,#f8f7f2)!important
}
html[data-abyss-theme="angel"] body:before{
 opacity:.4!important;background-image:linear-gradient(128deg,transparent 0 25%,rgba(170,146,99,.10) 25.08%,transparent 25.22% 70%,rgba(164,174,190,.12) 70.08%,transparent 70.24%),radial-gradient(ellipse at 76% 20%,rgba(255,255,255,.95),transparent 52%)!important
}
html[data-abyss-theme="angel"] .card,
html[data-abyss-theme="angel"] .panel,
html[data-abyss-theme="angel"] .hero,
html[data-abyss-theme="angel"] .metric,
html[data-abyss-theme="angel"] .profile,
html[data-abyss-theme="angel"] .client,
html[data-abyss-theme="angel"] .sidebar{
 border-color:rgba(160,139,97,.24)!important;
 background:linear-gradient(145deg,rgba(255,255,253,.98),rgba(247,245,238,.97))!important;
 box-shadow:0 18px 48px rgba(91,83,65,.09),inset 0 1px 0 rgba(255,255,255,.94)!important
}
html[data-abyss-theme="angel"] .mint,
html[data-abyss-theme="angel"] .brand,
html[data-abyss-theme="angel"] .side-brand,
html[data-abyss-theme="angel"] .nav-item.active,
html[data-abyss-theme="angel"] .section-title,
html[data-abyss-theme="angel"] .profile-open{color:#9d875d!important}
html[data-abyss-theme="angel"] button.primary,
html[data-abyss-theme="angel"] .btn.primary,
html[data-abyss-theme="angel"] .button-link.primary{
 color:#887249!important;border-color:rgba(164,141,95,.4)!important;
 background:linear-gradient(145deg,rgba(255,255,255,.98),rgba(228,218,193,.35))!important
}
html[data-abyss-theme="angel"] .nav-item.active{box-shadow:inset -3px 0 #b5a071,0 8px 24px rgba(100,90,67,.06)!important}
html[data-abyss-theme="angel"] input,
html[data-abyss-theme="angel"] select,
html[data-abyss-theme="angel"] textarea,
html[data-abyss-theme="angel"] .linkbox{background:rgba(255,255,252,.98)!important;border-color:rgba(160,139,97,.25)!important}
html[data-abyss-theme="angel"] .abyss-logo-mark{background:radial-gradient(circle at center,#f6f4ed 0 27%,transparent 29%)}
html[data-abyss-theme="angel"] .abyss-logo-mark:before{background:repeating-conic-gradient(from 0deg,rgba(166,144,100,.72) 0deg .55deg,transparent .7deg 3.2deg)}
/* Login and subscription pages use the same theme tokens as the dashboard. */
html[data-abyss-theme="abyss"] body:has(.login-brand) .card{
 background:linear-gradient(150deg,rgba(19,19,21,.98),rgba(5,5,6,.98))!important;border-color:rgba(174,178,187,.22)!important
}
html[data-abyss-theme="abyss"] body:has(.login-brand) button{
 color:#f0f0f2!important;background:linear-gradient(145deg,rgba(225,227,232,.14),rgba(95,97,103,.08))!important;border:1px solid rgba(196,199,205,.38)!important
}
html[data-abyss-theme="angel"] body:has(.login-brand) .card{
 background:linear-gradient(150deg,rgba(255,255,253,.99),rgba(245,242,233,.98))!important;border-color:rgba(160,139,97,.25)!important
}
html[data-abyss-theme="angel"] body:has(.login-brand) button{
 color:#887249!important;background:linear-gradient(145deg,#fff,#e8dfca)!important;border:1px solid rgba(164,141,95,.4)!important
}
@media(max-width:700px){
 body{animation:none!important;background-size:100% 100%!important}
 #abyssParticleCanvas{opacity:.2!important}
 .card,.panel,.hero,.metric,.profile,.client{backdrop-filter:none!important;-webkit-backdrop-filter:none!important}
}

/* Bidi-safe data amounts on the subscription panel. */
.usage-detail b{direction:ltr!important;unicode-bidi:isolate!important;display:block!important;text-align:left!important}
</style>"""
ABYSS_THEME_JS = r"""<script id="abyss-theme-controller">(()=>{const presets={abyss:'Abyss · مشکی و خاکستری',angel:'Angel · سفید و طلایی کمرنگ',graphite:'Graphite · خاکستری ساده',slate:'Slate · ذغالی ساده',ocean:'Ocean · آبی ساده',emerald:'Emerald · سبز ساده',paper:'Paper · روشن ساده'};let saved='abyss';try{saved=localStorage.getItem('abyss-visual-theme')||'abyss'}catch(e){}if(!presets[saved])saved='abyss';const apply=t=>{if(!presets[t])t='abyss';document.documentElement.dataset.abyssTheme=t;try{localStorage.setItem('abyss-visual-theme',t)}catch(e){}const meta=document.querySelector('meta[name="theme-color"]');if(meta)meta.content=(t==='angel'||t==='paper')?(t==='angel'?'#f4f3ef':'#f3f4f5'):t==='slate'?'#121820':t==='graphite'?'#111214':t==='ocean'?'#071216':t==='emerald'?'#0c130e':'#050505'};apply(saved);const init=()=>{if(document.getElementById('abyssThemeDock'))return;const dock=document.createElement('label');dock.id='abyssThemeDock';dock.innerHTML='<span class="theme-mark" aria-hidden="true">◉</span><span>تم</span><select id="abyssThemeSelect" aria-label="انتخاب تم">'+Object.entries(presets).map(([k,v])=>'<option value="'+k+'">'+v+'</option>').join('')+'</select>';const target=document.querySelector('.top .tools')||document.querySelector('.top');if(target)target.appendChild(dock);else{dock.classList.add('floating');document.body.appendChild(dock)}const select=dock.querySelector('select');select.value=document.documentElement.dataset.abyssTheme;select.addEventListener('change',()=>apply(select.value));if(!document.getElementById('abyssParticleCanvas')&&!matchMedia('(prefers-reduced-motion: reduce)').matches){const canvas=document.createElement('canvas');canvas.id='abyssParticleCanvas';canvas.setAttribute('aria-hidden','true');document.body.prepend(canvas);const ctx=canvas.getContext('2d',{alpha:true});if(ctx){let w=0,h=0,points=[],raf=0,dirty=true;const resize=()=>{const coarse=matchMedia('(pointer:coarse), (max-width:700px)').matches;const dpr=Math.min(devicePixelRatio||1,coarse?1:1.25);w=innerWidth;h=innerHeight;canvas.width=Math.floor(w*dpr);canvas.height=Math.floor(h*dpr);canvas.style.width=w+'px';canvas.style.height=h+'px';ctx.setTransform(dpr,0,0,dpr,0,0);const count=coarse?12:Math.min(72,Math.max(28,Math.round(w*h/22000)));points=Array.from({length:count},()=>({x:Math.random()*w,y:Math.random()*h,r:.45+Math.random()*.7,a:.14+Math.random()*.22,dx:(Math.random()-.5)*.08,dy:(Math.random()-.5)*.08}));dirty=true};let ripple=null;const paint=()=>{raf=0;ctx.clearRect(0,0,w,h);const theme=document.documentElement.dataset.abyssTheme;const light=theme==='angel'||theme==='paper';for(const p of points){p.x+=p.dx;p.y+=p.dy;if(p.x<0||p.x>w)p.dx*=-1;if(p.y<0||p.y>h)p.dy*=-1;ctx.beginPath();ctx.fillStyle=light?'rgba(145,130,99,'+p.a*.38+')':'rgba(195,199,207,'+p.a+')';ctx.arc(p.x,p.y,p.r,0,Math.PI*2);ctx.fill()}if(ripple){ripple.r+=2.2;ripple.a*=.965;ctx.beginPath();ctx.strokeStyle=light?'rgba(166,148,108,'+ripple.a+')':'rgba(195,199,207,'+ripple.a+')';ctx.lineWidth=1;ctx.arc(ripple.x,ripple.y,ripple.r,0,Math.PI*2);ctx.stroke();if(ripple.a<.025)ripple=null}if(document.visibilityState==='visible')raf=requestAnimationFrame(paint)};resize();addEventListener('resize',()=>{cancelAnimationFrame(raf);resize()},{passive:true});document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible'&&!raf)raf=requestAnimationFrame(paint);else if(document.visibilityState!=='visible'&&raf){cancelAnimationFrame(raf);raf=0}},{passive:true});document.addEventListener('click',e=>{if(e.target.closest('button,a,select,input,label')){ripple={x:e.clientX,y:e.clientY,r:2,a:.24}}},{passive:true});raf=requestAnimationFrame(paint)}}};if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init,{once:true});else init()})();</script>"""
ABYSS_LAYOUT_REPAIR_CSS = r"""<style id="abyss-layout-repair">
/* Abyss reference-led layout: absolute black, quiet contrast, one section at a time. */
:root{--chart-cpu:#c8cad0;--chart-ram:#8e85b8;--chart-net:#a2b0ba;--ab-bg:#020202;--ab-panel:rgba(13,13,14,.94);--ab-line:rgba(178,181,187,.18);--ab-accent:#b9bbc1;--ab-accent-hi:#f0f0f2;--ab-text:#eeeef0;--ab-muted:#a2a2a7;--ab-glass:rgba(230,230,235,.035);--ab-glow:rgba(180,182,189,.055);--ab-input:rgba(5,5,6,.95)}
html[data-abyss-theme="abyss"]{--ab-bg:#020202;--ab-panel:rgba(13,13,14,.94);--ab-line:rgba(178,181,187,.18);--ab-accent:#b9bbc1;--ab-accent-hi:#f0f0f2;--ab-text:#eeeef0;--ab-muted:#a2a2a7;--ab-glass:rgba(230,230,235,.035);--ab-glow:rgba(180,182,189,.055);--ab-input:rgba(5,5,6,.95)}
html,body{min-height:100%;background-color:#020202!important}
html{scroll-behavior:auto!important;scroll-padding-top:12px}
body{overflow-x:hidden!important;overflow-y:auto!important;background-color:var(--ab-bg)!important;background-image:radial-gradient(ellipse at 22% 8%,rgba(160,163,170,.035),transparent 32%),radial-gradient(ellipse at 82% 76%,rgba(126,128,134,.028),transparent 38%),linear-gradient(145deg,#020202,#070707 58%,#030303)!important;animation:none!important}
body:before{content:"";position:fixed;inset:-5%;z-index:0!important;pointer-events:none;opacity:.36;background-image:linear-gradient(118deg,transparent 0 16%,rgba(200,202,208,.045) 16.08%,transparent 16.24% 43%,rgba(185,188,194,.025) 43.08%,transparent 43.24% 72%,rgba(220,221,225,.035) 72.08%,transparent 72.22%),linear-gradient(164deg,transparent 0 28%,rgba(190,193,199,.027) 28.08%,transparent 28.22% 61%,rgba(210,212,216,.023) 61.08%,transparent 61.25%);background-size:100% 100%;will-change:transform;animation:abyssStreakDrift 34s ease-in-out infinite alternate!important}
body:after{z-index:0!important;opacity:.075}
@keyframes abyssStreakDrift{0%{transform:translate3d(-.7%,-.25%,0)}50%{transform:translate3d(.55%,.4%,0)}100%{transform:translate3d(-.25%,.7%,0)}}
body>*{position:relative;z-index:1}
.app-shell{display:block!important;width:100%!important;max-width:none!important;min-height:100dvh;background:transparent!important}
.workspace{width:100%!important;max-width:1540px!important;margin:0 auto!important;padding:78px clamp(12px,2.4vw,36px) 42px!important;min-width:0}
.sidebar{position:fixed!important;top:0!important;left:0!important;right:auto!important;bottom:0!important;z-index:10011!important;width:min(330px,88vw)!important;height:100dvh!important;overflow-y:auto!important;overscroll-behavior:contain;background:rgba(9,9,10,.97)!important;border-right:1px solid rgba(185,188,194,.2)!important;border-left:0!important;border-radius:0!important;backdrop-filter:blur(16px)!important;-webkit-backdrop-filter:blur(16px)!important;transform:translateX(-105%)!important;transition:transform .22s cubic-bezier(.2,.75,.25,1)!important;box-shadow:18px 0 60px rgba(0,0,0,.32)!important}
.sidebar.open{transform:translateX(0)!important}
#menuToggle{display:inline-flex!important;position:fixed!important;top:14px!important;left:14px!important;right:auto!important;z-index:10021!important;align-items:center!important;justify-content:center!important;gap:9px!important;width:auto!important;min-width:48px!important;min-height:44px!important;margin:0!important;padding:10px 15px!important;border:1px solid rgba(194,197,204,.25)!important;border-radius:14px!important;background:rgba(14,14,15,.93)!important;color:#ececef!important;box-shadow:0 9px 30px rgba(0,0,0,.28)!important;backdrop-filter:blur(12px)!important;-webkit-backdrop-filter:blur(12px)!important;cursor:pointer}
#abyssMenuShade{position:fixed;inset:0;z-index:10010;background:rgba(0,0,0,.56);opacity:0;visibility:hidden;pointer-events:none;transition:opacity .2s ease,visibility .2s ease;backdrop-filter:blur(2px);-webkit-backdrop-filter:blur(2px)}
body.abyss-menu-open #abyssMenuShade{opacity:1;visibility:visible;pointer-events:auto}
body.abyss-menu-open{overflow:hidden}
.nav-item{width:100%;min-height:44px;white-space:normal;line-height:1.5}
.nav-item.active{border-color:rgba(195,198,205,.28)!important;background:rgba(205,207,213,.085)!important;box-shadow:inset 3px 0 #c7c9ce!important}
.top{padding-top:6px}
.section-heading{font-size:clamp(20px,2.2vw,25px)!important}
.stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
.workspace [data-section-page]{min-width:0;scroll-margin-top:14px}
.workspace .card,.workspace .panel,.workspace .box{background:linear-gradient(145deg,rgba(16,16,17,.96),rgba(8,8,9,.97))!important;border-color:rgba(165,168,175,.16)!important;box-shadow:0 12px 32px rgba(0,0,0,.22),inset 0 1px 0 rgba(255,255,255,.018)!important;backdrop-filter:none!important;-webkit-backdrop-filter:none!important}
.workspace button,.workspace .button-link,.nav-item{backdrop-filter:none!important;-webkit-backdrop-filter:none!important}
.workspace table{width:100%;font-size:13px}
.workspace .client{gap:12px}
.workspace .client-info{min-width:0;overflow-wrap:anywhere}
.workspace input,.workspace select,.workspace textarea{max-width:100%;min-width:0}
.workspace .fields{grid-template-columns:repeat(auto-fit,minmax(min(100%,210px),1fr))}
.workspace .profile-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
.abyss-brand-row{letter-spacing:.12em}
.abyss-logo-svg{display:block;width:48px;height:48px;flex:0 0 48px;filter:drop-shadow(0 0 12px rgba(190,192,199,.13))}
.sidebar .abyss-logo-svg{width:30px;height:30px;flex-basis:30px}
.login-brand .abyss-logo-svg{width:54px;height:54px;flex-basis:54px}
.login-layout{position:relative;display:grid;grid-template-columns:minmax(0,1.05fr) minmax(360px,.95fr);gap:clamp(22px,4vw,64px);align-items:stretch;width:min(1220px,100%);min-height:min(740px,calc(100dvh - 52px));margin:auto;direction:rtl}
.login-visual{position:relative;isolation:isolate;overflow:hidden;display:flex;flex-direction:column;justify-content:center;align-items:flex-start;padding:clamp(28px,5vw,72px);border:1px solid rgba(174,177,184,.12);border-radius:30px;background:linear-gradient(145deg,rgba(13,13,14,.72),rgba(4,4,4,.62));box-shadow:inset 0 1px rgba(255,255,255,.025),0 30px 100px rgba(0,0,0,.26);min-width:0}
.login-visual:before{content:"";position:absolute;inset:-10%;z-index:-1;background:radial-gradient(ellipse at 45% 43%,rgba(185,188,195,.09),transparent 25%),linear-gradient(133deg,transparent 0 37%,rgba(198,200,206,.05) 37.1%,transparent 37.4% 65%,rgba(200,202,208,.035) 65.1%,transparent 65.4%);transform:rotate(-4deg)}
.login-visual .visual-eyebrow{font-size:10px;letter-spacing:.23em;color:#aeb0b6;font-weight:800;direction:ltr}
.login-visual h2{font-size:clamp(30px,4vw,50px);line-height:1.5;letter-spacing:-.035em;margin:24px 0 12px;color:#f0f0f2}
.login-visual p{max-width:410px;line-height:2.05;color:#a7a8ae;font-size:14px}
.login-visual .visual-orbit{width:min(245px,70%);aspect-ratio:1;position:relative;align-self:center;margin:0 auto 40px;border-radius:50%;border:1px solid rgba(185,188,196,.14);box-shadow:0 0 60px rgba(180,183,190,.035),inset 0 0 50px rgba(180,183,190,.025)}
.login-visual .visual-orbit:before,.login-visual .visual-orbit:after{content:"";position:absolute;inset:12%;border:1px solid rgba(188,191,198,.23);border-radius:50%;transform:rotate(-27deg) scaleX(.54)}
.login-visual .visual-orbit:after{inset:22% 35%;border-color:rgba(225,226,230,.48);transform:rotate(21deg) scaleX(1.3);box-shadow:0 0 24px rgba(205,207,214,.08)}
.login-layout>.card{width:100%;max-width:560px;align-self:center;margin:0;padding:clamp(24px,4vw,48px);border-radius:27px;background:linear-gradient(155deg,rgba(17,17,18,.97),rgba(7,7,8,.97))!important;border-color:rgba(179,182,189,.19)!important;box-shadow:0 30px 100px rgba(0,0,0,.37),inset 0 1px rgba(255,255,255,.025)!important;backdrop-filter:none!important}
.login-layout>.card h1{font-size:clamp(28px,3vw,38px);letter-spacing:-.025em}
.login-layout>.card form{margin-top:25px}
.login-layout>.card input{min-height:48px}
.login-layout>.card button{min-height:48px;background:linear-gradient(145deg,#d0d1d5,#9c9ea5)!important;color:#101011!important;border:1px solid rgba(255,255,255,.22)!important;box-shadow:0 10px 28px rgba(180,182,189,.1)!important}
html[data-abyss-theme="angel"] .login-visual,html[data-abyss-theme="paper"] .login-visual{background:linear-gradient(145deg,rgba(255,255,255,.73),rgba(249,246,237,.8));border-color:rgba(166,148,109,.2)}
html[data-abyss-theme="angel"] .login-visual h2,html[data-abyss-theme="paper"] .login-visual h2{color:#3b3529}
html[data-abyss-theme="angel"] .login-visual p,html[data-abyss-theme="paper"] .login-visual p{color:#746d60}
@media(max-width:900px){.login-layout{grid-template-columns:minmax(0,1fr) minmax(310px,.9fr);gap:18px;min-height:calc(100dvh - 36px)}.login-visual{padding:26px}.login-visual .visual-orbit{width:min(190px,70%);margin-bottom:22px}}
@media(max-width:700px){body{overflow:auto!important}.login-layout{display:block;width:min(480px,100%);min-height:0;margin:28px auto 16px;padding:0}.login-visual{display:none}.login-layout>.card{width:100%;max-width:none;padding:24px 20px;border-radius:22px}.login-brand{margin-top:4px}.workspace{padding:70px 12px 30px!important}.stats{grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.stats>.card{padding:13px!important}.workspace>section.card{padding:15px!important}.workspace .profile-grid{grid-template-columns:1fr}.workspace .fields{grid-template-columns:minmax(0,1fr)}.workspace .top .tools{gap:7px}.workspace .top .tools>*{max-width:100%;flex:0 1 auto}#abyssThemeDock.floating{top:14px;right:10px;left:auto;max-width:calc(100vw - 140px)}#abyssThemeSelect{max-width:95px}}
@media(max-width:390px){.stats{grid-template-columns:minmax(0,1fr)}.workspace{padding-inline:10px!important}.workspace .card{padding:12px!important}#menuToggle{top:10px!important;left:10px!important;right:auto!important}#abyssThemeDock.floating{right:10px;left:auto;top:10px}}
@media(hover:none),(pointer:coarse){.workspace .card,.workspace .panel,.workspace .box,.login-layout>.card{backdrop-filter:none!important;-webkit-backdrop-filter:none!important}.workspace button:hover,.nav-item:hover{transform:none!important}}
/* Reference correction: centered login card over a full-screen black, atmospheric background. */
.login-layout{position:relative!important;isolation:isolate!important;display:grid!important;grid-template-columns:minmax(0,1fr)!important;place-items:center!important;align-content:center!important;gap:0!important;width:100%!important;max-width:none!important;min-height:100dvh!important;margin:0!important;padding:30px 14px!important;direction:rtl!important}
.login-visual{position:fixed!important;inset:0!important;z-index:0!important;display:block!important;pointer-events:none!important;padding:0!important;border:0!important;border-radius:0!important;background:transparent!important;box-shadow:none!important;overflow:hidden!important;backdrop-filter:none!important;-webkit-backdrop-filter:none!important}
.login-visual .visual-eyebrow,.login-visual h2,.login-visual p{display:none!important}
.login-visual .visual-orbit{position:absolute!important;top:4%!important;left:4%!important;width:min(56vw,610px)!important;max-width:none!important;aspect-ratio:1!important;margin:0!important;opacity:.68!important;border-color:rgba(184,187,195,.11)!important;box-shadow:0 0 110px rgba(178,181,190,.03),inset 0 0 80px rgba(178,181,190,.02)!important}
.login-visual .visual-orbit:before{inset:10%!important;border-color:rgba(194,196,202,.13)!important}
.login-visual .visual-orbit:after{inset:24% 39%!important;border-color:rgba(218,220,225,.18)!important;box-shadow:none!important}
.login-layout>.card{position:relative!important;z-index:2!important;align-self:center!important;width:min(432px,calc(100vw - 28px))!important;max-width:432px!important;margin:0 auto!important;padding:clamp(24px,4vw,38px)!important;border-radius:25px!important;background:linear-gradient(155deg,rgba(16,16,17,.93),rgba(6,6,7,.96))!important;border-color:rgba(183,186,192,.21)!important;box-shadow:0 30px 100px rgba(0,0,0,.46),inset 0 1px 0 rgba(255,255,255,.025)!important;backdrop-filter:blur(12px)!important;-webkit-backdrop-filter:blur(12px)!important}
.login-layout>.card .login-brand{margin:0 auto 24px!important}
.login-layout>.card .login-brand .abyss-logo-svg{width:58px!important;height:58px!important;flex-basis:58px!important}
.login-layout>.card h1{font-size:clamp(27px,4vw,35px)!important;text-align:center!important;margin-top:10px!important}
.login-layout>.card>p{text-align:center!important}
.login-layout>.card label{margin-top:17px!important}
.login-layout>.card input{min-height:47px!important}
.login-layout>.card button{min-height:48px!important;background:linear-gradient(145deg,#d3d4d8,#9699a1)!important;color:#0a0a0b!important;border:1px solid rgba(255,255,255,.22)!important;box-shadow:0 10px 28px rgba(180,182,189,.08)!important}
.workspace{display:grid!important;grid-template-columns:repeat(12,minmax(0,1fr))!important;gap:15px!important;align-content:start!important}
.workspace>.top{grid-column:1/-1!important;width:100%!important;min-width:0!important;margin:0!important}
.workspace>section{min-width:0!important;margin:0!important;grid-column:1/-1}
.workspace>#overviewStats{grid-column:1/-1!important;display:grid!important;grid-template-columns:repeat(4,minmax(0,1fr))!important;gap:13px!important;margin:0!important}
.workspace>#overviewStats>.card{min-width:0!important;margin:0!important;padding:19px!important}
.workspace>#dashboardUsageCard{grid-column:span 8!important;min-width:0!important}
.workspace>#panelHealthCard{grid-column:span 4!important;min-width:0!important;display:flex;align-items:flex-start}
.workspace>#dashboardUsageCard .stats{grid-template-columns:repeat(3,minmax(0,1fr))!important;gap:10px!important}
.workspace>#dashboardUsageCard .stats>.card{min-width:0!important;margin:0!important;padding:13px!important}
.workspace>#usageSparkline{display:block;width:100%;max-width:100%;height:144px;margin-top:10px}.chart-legend{display:flex;gap:15px;flex-wrap:wrap;margin-top:8px;color:var(--ab-muted);font-size:11px}.chart-legend span{display:inline-flex;align-items:center;gap:6px}.chart-legend i{display:inline-block;width:8px;height:8px;border-radius:50%}.chart-legend .cpu{background:var(--chart-cpu,#c8cad0)}.chart-legend .ram{background:var(--chart-ram,#8e85b8)}.chart-legend .net{background:var(--chart-net,#a2b0ba)}
.workspace .section-title{line-height:1.6}
.workspace #panelHealthCard #status{line-height:2!important;overflow-wrap:anywhere}
@media(max-width:980px){
 .workspace>#overviewStats{grid-template-columns:repeat(2,minmax(0,1fr))!important}
 .workspace>#dashboardUsageCard,.workspace>#panelHealthCard{grid-column:1/-1!important}
}
@media(max-width:700px){
 .login-layout{min-height:100svh!important;padding:76px 12px 22px!important}
 .login-layout>.card{width:min(440px,100%)!important;padding:23px 19px!important;border-radius:21px!important}
 .login-visual .visual-orbit{top:5%!important;left:-18%!important;width:84vw!important;opacity:.16!important}
 .workspace{grid-template-columns:minmax(0,1fr)!important;gap:11px!important;padding:72px 11px 26px!important}
 .workspace>.top,.workspace>section,.workspace>#overviewStats,.workspace>#dashboardUsageCard,.workspace>#panelHealthCard{grid-column:1/-1!important}
 .workspace>#overviewStats{grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:9px!important}
 .workspace>#overviewStats>.card{padding:13px!important;min-height:88px}
 .workspace>#dashboardUsageCard .stats{grid-template-columns:repeat(3,minmax(0,1fr))!important}
 .workspace>#dashboardUsageCard .stats>.card{padding:10px 8px!important}
 .workspace #dashboardUsageCard .num{font-size:clamp(18px,5vw,24px)}
 .workspace .top{display:flex;align-items:flex-start;flex-direction:column!important;gap:10px!important}
 .workspace .top .tools{width:100%;display:flex;gap:7px!important;flex-wrap:wrap!important}
 .workspace .top .tools button{flex:1 1 auto!important;width:auto!important}
}
@media(max-width:380px){
 .workspace>#overviewStats{grid-template-columns:minmax(0,1fr)!important}
 .workspace>#dashboardUsageCard .stats{grid-template-columns:repeat(3,minmax(0,1fr))!important}
 .login-layout>.card{padding:21px 16px!important}
}
@media(hover:none),(pointer:coarse){
 .login-layout>.card{backdrop-filter:none!important;-webkit-backdrop-filter:none!important}
 .workspace .card:hover,.workspace button:hover{transform:none!important}
}
/* Low-contrast marble atmosphere: soft smoke veins, never a blue/navy wash. */
/* Angel stays genuinely light: warm ivory, aged gold, and the same restrained composition. */
html[data-abyss-theme="angel"],html[data-abyss-theme="paper"]{--chart-cpu:#9c8859;--chart-ram:#9e9ab1;--chart-net:#718675}
html[data-abyss-theme="angel"] body,html[data-abyss-theme="paper"] body{background-color:#f1eee6!important;background-image:linear-gradient(145deg,#f6f4ee,#e7e1d4 58%,#f4f1e9)!important;color:#332e25!important}
html[data-abyss-theme="angel"] body:before,html[data-abyss-theme="paper"] body:before{opacity:.3!important;background-image:linear-gradient(118deg,transparent 0 16%,rgba(156,132,82,.055) 16.08%,transparent 16.24% 43%,rgba(145,124,79,.035) 43.08%,transparent 43.24% 72%,rgba(160,138,91,.045) 72.08%,transparent 72.22%),linear-gradient(164deg,transparent 0 28%,rgba(160,139,94,.03) 28.08%,transparent 28.22% 61%,rgba(160,139,94,.025) 61.08%,transparent 61.25%)}
html[data-abyss-theme="angel"] body:after,html[data-abyss-theme="paper"] body:after{opacity:.055!important;mix-blend-mode:multiply;background-image:radial-gradient(ellipse at 14% 23%,rgba(157,126,62,.11),transparent 30%),radial-gradient(ellipse at 78% 60%,rgba(171,148,102,.075),transparent 35%),repeating-linear-gradient(137deg,transparent 0 96px,rgba(126,102,55,.02) 97px,transparent 100px 181px)}
html[data-abyss-theme="angel"] .login-visual:before,html[data-abyss-theme="paper"] .login-visual:before{background:radial-gradient(ellipse at 14% 30%,rgba(165,137,79,.105),transparent 34%),radial-gradient(ellipse at 83% 63%,rgba(154,130,82,.075),transparent 32%),linear-gradient(127deg,transparent 0 21%,rgba(180,157,104,.075) 21.1%,transparent 21.45% 48%,rgba(151,130,81,.045) 48.1%,transparent 48.45% 72%,rgba(180,157,104,.045) 72.1%,transparent 72.35%)!important}
html[data-abyss-theme="angel"] .login-visual .visual-orbit,html[data-abyss-theme="paper"] .login-visual .visual-orbit{border-color:rgba(160,131,67,.2)!important;box-shadow:0 0 90px rgba(160,131,67,.045),inset 0 0 70px rgba(160,131,67,.025)!important}
html[data-abyss-theme="angel"] .login-layout>.card,html[data-abyss-theme="paper"] .login-layout>.card{background:linear-gradient(155deg,rgba(255,254,250,.97),rgba(243,239,229,.97))!important;border-color:rgba(166,140,78,.29)!important;color:#302b22!important;box-shadow:0 28px 85px rgba(82,67,37,.13),inset 0 1px rgba(255,255,255,.8)!important}
html[data-abyss-theme="angel"] .login-layout>.card h1,html[data-abyss-theme="paper"] .login-layout>.card h1{color:#312b21!important}
html[data-abyss-theme="angel"] .login-layout>.card .small,html[data-abyss-theme="paper"] .login-layout>.card .small,html[data-abyss-theme="angel"] .login-layout>.card label,html[data-abyss-theme="paper"] .login-layout>.card label{color:#766b54!important}
html[data-abyss-theme="angel"] .login-layout>.card input,html[data-abyss-theme="paper"] .login-layout>.card input{background:rgba(255,255,255,.72)!important;color:#302b22!important;border-color:rgba(155,132,80,.27)!important}
html[data-abyss-theme="angel"] .login-layout>.card button,html[data-abyss-theme="paper"] .login-layout>.card button{background:linear-gradient(145deg,#c5ad73,#a58b4e)!important;color:#17130b!important;border-color:rgba(125,100,48,.25)!important;box-shadow:0 8px 24px rgba(149,121,57,.11)!important}
html[data-abyss-theme="angel"] .workspace .card,html[data-abyss-theme="paper"] .workspace .card,html[data-abyss-theme="angel"] .workspace .panel,html[data-abyss-theme="paper"] .workspace .panel,html[data-abyss-theme="angel"] .workspace .box,html[data-abyss-theme="paper"] .workspace .box{background:linear-gradient(145deg,rgba(255,254,250,.97),rgba(241,237,227,.96))!important;border-color:rgba(164,140,83,.22)!important;color:#332e25!important;box-shadow:0 10px 28px rgba(75,63,37,.075),inset 0 1px rgba(255,255,255,.9)!important}
html[data-abyss-theme="angel"] .workspace .small,html[data-abyss-theme="paper"] .workspace .small{color:#756b58!important}
html[data-abyss-theme="angel"] .workspace input,html[data-abyss-theme="paper"] .workspace input,html[data-abyss-theme="angel"] .workspace select,html[data-abyss-theme="paper"] .workspace select,html[data-abyss-theme="angel"] .workspace textarea,html[data-abyss-theme="paper"] .workspace textarea{background:rgba(255,255,255,.83)!important;color:#302b22!important;border-color:rgba(160,137,84,.3)!important}
html[data-abyss-theme="angel"] .sidebar,html[data-abyss-theme="paper"] .sidebar{background:rgba(246,243,234,.985)!important;border-right:1px solid rgba(164,140,83,.23)!important;color:#332e25!important;box-shadow:18px 0 60px rgba(67,54,29,.12)!important}
html[data-abyss-theme="angel"] .nav-item,html[data-abyss-theme="paper"] .nav-item{color:#4b4538!important}
html[data-abyss-theme="angel"] .nav-item.active,html[data-abyss-theme="paper"] .nav-item.active{background:rgba(175,147,83,.13)!important;border-color:rgba(164,140,83,.25)!important;box-shadow:inset 3px 0 #a38a50!important}
html[data-abyss-theme="angel"] #menuToggle,html[data-abyss-theme="paper"] #menuToggle{background:rgba(250,248,241,.96)!important;color:#3b3529!important;border-color:rgba(164,140,83,.3)!important}

body{display:block!important;place-items:initial!important;padding:0!important}

body:after{opacity:.105!important;mix-blend-mode:screen;background-image:radial-gradient(ellipse at 13% 21%,rgba(195,197,204,.075),transparent 27%),radial-gradient(ellipse at 78% 18%,rgba(145,148,155,.055),transparent 24%),radial-gradient(ellipse at 63% 77%,rgba(168,170,177,.05),transparent 31%),radial-gradient(ellipse at 26% 83%,rgba(130,132,139,.038),transparent 25%),repeating-linear-gradient(137deg,transparent 0 96px,rgba(214,216,221,.015) 97px,transparent 100px 181px);background-size:100% 100%}
.login-visual:before{content:""!important;position:absolute!important;inset:-8%!important;z-index:0!important;pointer-events:none!important;opacity:.88!important;background:radial-gradient(ellipse at 14% 30%,rgba(186,189,196,.09),transparent 34%),radial-gradient(ellipse at 83% 63%,rgba(126,128,136,.065),transparent 32%),radial-gradient(ellipse at 52% 46%,rgba(130,132,139,.035),transparent 42%),linear-gradient(127deg,transparent 0 21%,rgba(220,222,227,.055) 21.1%,transparent 21.45% 48%,rgba(190,192,199,.035) 48.1%,transparent 48.45% 72%,rgba(225,226,230,.035) 72.1%,transparent 72.35%),linear-gradient(163deg,transparent 0 37%,rgba(200,202,208,.035) 37.1%,transparent 37.4% 69%,rgba(170,172,180,.035) 69.1%,transparent 69.4%);background-size:100% 100%;animation:abyssStreakDrift 34s ease-in-out infinite alternate!important}
.login-visual .visual-orbit{z-index:1!important}
@media(prefers-reduced-motion:reduce){body:before{animation:none!important}#abyssParticleCanvas{display:none!important}*,*:before,*:after{transition:none!important;animation:none!important}}

/* Reference-led finishing pass: split desktop login, eclipse/ray mark, and compact reusable page grids. */
.login-layout{display:grid!important;grid-template-columns:minmax(0,1fr) minmax(350px,.96fr)!important;place-items:stretch!important;align-content:stretch!important;width:min(1380px,100%)!important;max-width:none!important;min-height:100svh!important;margin:0 auto!important;padding:clamp(22px,4vw,58px)!important;gap:clamp(24px,4.2vw,72px)!important;direction:ltr!important}
.login-visual{position:relative!important;inset:auto!important;z-index:1!important;display:flex!important;pointer-events:auto!important;flex-direction:column!important;justify-content:center!important;align-items:center!important;text-align:center!important;min-width:0!important;padding:24px!important;border:0!important;border-radius:0!important;background:transparent!important;box-shadow:none!important;overflow:visible!important;direction:ltr!important}
.login-visual:before{content:""!important;position:absolute!important;inset:-8%!important;z-index:-1!important;pointer-events:none!important;opacity:.9!important;background:radial-gradient(ellipse at 48% 45%,rgba(188,190,197,.09),transparent 33%),radial-gradient(ellipse at 15% 20%,rgba(130,132,140,.035),transparent 35%),linear-gradient(133deg,transparent 0 35%,rgba(205,207,214,.035) 35.1%,transparent 35.35% 65%,rgba(205,207,214,.025) 65.1%,transparent 65.35%)!important}
.login-visual .visual-eyebrow,.login-visual h2,.login-visual p{display:block!important}
.login-visual .visual-eyebrow{direction:ltr!important;font-size:11px!important;letter-spacing:.24em!important;color:var(--ab-muted)!important}
.login-visual h2{margin:24px 0 5px!important;font-size:clamp(28px,3vw,42px)!important;line-height:1.45!important;letter-spacing:.12em!important;color:var(--ab-text)!important;direction:ltr!important}
.login-visual p{max-width:100%!important;margin:5px 0 0!important;color:var(--ab-muted)!important;font-size:11px!important;letter-spacing:.14em!important;line-height:1.8!important;direction:ltr!important}
.login-visual .visual-orbit{position:relative!important;top:auto!important;left:auto!important;width:min(340px,78%)!important;max-width:340px!important;aspect-ratio:1!important;align-self:center!important;margin:0 auto 14px!important;border:1px solid rgba(190,192,199,.14)!important;border-radius:50%!important;opacity:.98!important;background:radial-gradient(circle at center,#020202 0 11%,rgba(4,4,5,.98) 11.8% 12.8%,transparent 13.5%),repeating-conic-gradient(from 0deg,rgba(208,210,216,.38) 0deg .36deg,transparent .7deg 3deg)!important;box-shadow:0 0 80px rgba(188,190,197,.055),inset 0 0 38px rgba(188,190,197,.035)!important;mask-image:radial-gradient(circle,#000 0 65%,rgba(0,0,0,.78) 76%,transparent 100%)!important}
.login-visual .visual-orbit:before{inset:12%!important;border:1px solid rgba(199,201,207,.17)!important;box-shadow:0 0 34px rgba(185,187,195,.04)!important;background:transparent!important}
.login-visual .visual-orbit:after{inset:39%!important;border:1px solid rgba(215,216,222,.2)!important;background:#020202!important;box-shadow:0 0 25px rgba(0,0,0,.9)!important;transform:none!important}
.login-layout>.card{position:relative!important;z-index:2!important;align-self:center!important;justify-self:center!important;width:min(460px,100%)!important;max-width:460px!important;margin:0!important;direction:rtl!important}
.login-layout>.card .login-brand{justify-content:center!important}
@media(max-width:900px){.login-layout{grid-template-columns:minmax(0,1fr) minmax(300px,.95fr)!important;gap:18px!important;padding:22px!important}.login-visual{padding:10px!important}.login-visual .visual-orbit{width:min(280px,82%)!important}}
@media(max-width:700px){.login-layout{display:grid!important;grid-template-columns:minmax(0,1fr)!important;width:100%!important;min-height:100svh!important;padding:76px 12px 22px!important;gap:0!important}.login-visual{display:none!important}.login-layout>.card{width:min(440px,100%)!important;max-width:440px!important;padding:23px 19px!important;border-radius:21px!important}}
@media(prefers-reduced-motion:reduce){.login-visual .visual-orbit{animation:none!important}}
/* Dashboard detail pages share the same black glass, restrained silver highlight, and responsive grid. */
.workspace .reference-page-head{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:16px}
.workspace .reference-page-head .small{max-width:780px;line-height:1.9}
.workspace .reference-page-head button{width:auto;min-width:120px}
.server-identity{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin:14px 0;padding:17px 19px;border:1px solid var(--ab-line);border-radius:16px;background:var(--ab-glass)}
.server-identity strong{font-size:clamp(17px,2vw,23px);letter-spacing:.015em;overflow-wrap:anywhere}
.server-grid,.protocol-catalog,.report-profiles{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}
.server-state,.protocol-state,.report-state{min-width:0;padding:16px;border:1px solid var(--ab-line);border-radius:15px;background:var(--ab-panel);box-shadow:0 12px 30px rgba(0,0,0,.12)}
.server-state .state-title,.protocol-state .state-title,.report-state .state-title{display:flex;justify-content:space-between;align-items:center;gap:10px;font-size:13px;font-weight:750}
.server-state strong,.protocol-state strong,.report-state strong{display:block;margin:11px 0 6px;font-size:18px;overflow-wrap:anywhere}
.state-chip{display:inline-flex;align-items:center;gap:6px;padding:4px 8px;border:1px solid var(--ab-line);border-radius:999px;font-size:10px;white-space:nowrap}
.state-chip:before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor;box-shadow:0 0 10px currentColor}
.state-chip.good{color:#73cba0}.state-chip.bad{color:#e48e8e}.state-chip.neutral{color:var(--ab-muted)}
.protocol-state{display:grid;align-content:start;gap:7px}
.protocol-state .protocol-meta{display:flex;flex-wrap:wrap;gap:6px}
.protocol-state .protocol-meta span{display:inline-block;padding:5px 8px;border:1px solid var(--ab-line);border-radius:8px;color:var(--ab-muted);font-size:10px;overflow-wrap:anywhere}
.protocol-state .protocol-switch{display:flex;align-items:center;justify-content:space-between;gap:10px;padding-top:10px;border-top:1px solid var(--ab-line);font-size:12px}
.protocol-state .protocol-switch input{width:18px;min-height:18px;accent-color:var(--ab-accent);cursor:pointer}
.protocol-state .experimental-label{color:#d7b87a;font-size:10px}
.report-summary{padding:15px;border:1px solid var(--ab-line);border-radius:15px;background:var(--ab-glass);line-height:1.9;margin-bottom:14px}
.report-issues{display:grid;gap:8px;margin:10px 0 18px}
.report-issue{padding:11px 13px;border:1px solid var(--ab-line);border-radius:11px;background:var(--ab-panel);line-height:1.75;overflow-wrap:anywhere}
.report-issue.good{border-color:rgba(115,203,160,.24)}.report-issue.bad{border-color:rgba(228,142,142,.34)}
.report-events{display:grid;gap:8px;margin-top:10px}
.report-event{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:7px 14px;padding:11px 12px;border:1px solid var(--ab-line);border-radius:11px;background:var(--ab-panel);min-width:0}
.report-event .event-message{overflow-wrap:anywhere}.report-event .event-meta{font-size:10px;color:var(--ab-muted);white-space:nowrap}
@media(max-width:980px){.server-grid,.protocol-catalog,.report-profiles{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:700px){.server-grid,.protocol-catalog,.report-profiles{grid-template-columns:minmax(0,1fr)}.server-state,.protocol-state,.report-state{padding:14px}.report-event{grid-template-columns:minmax(0,1fr)}.report-event .event-meta{white-space:normal}.server-identity{align-items:flex-start;flex-direction:column}}
html[data-abyss-theme="angel"] .server-state,html[data-abyss-theme="angel"] .protocol-state,html[data-abyss-theme="angel"] .report-state,html[data-abyss-theme="angel"] .report-issue,html[data-abyss-theme="angel"] .report-event{background:rgba(255,254,250,.91);box-shadow:0 10px 28px rgba(74,60,33,.05)}

.login-input-wrap{position:relative!important;display:flex!important;align-items:center!important;min-width:0!important;margin:0!important}
.login-input-wrap input{width:100%!important;padding-left:48px!important;padding-right:13px!important}
.login-input-icon{position:absolute!important;z-index:2!important;left:15px!important;top:50%!important;transform:translateY(-50%)!important;color:var(--ab-muted)!important;pointer-events:none!important;font-size:15px!important;line-height:1!important}
.login-password-toggle{position:absolute!important;z-index:3!important;left:5px!important;top:50%!important;transform:translateY(-50%)!important;width:36px!important;min-width:36px!important;height:36px!important;min-height:36px!important;margin:0!important;padding:0!important;border:1px solid transparent!important;border-radius:9px!important;background:transparent!important;color:var(--ab-muted)!important;box-shadow:none!important;font-size:15px!important;line-height:1!important}
.login-password-toggle:hover{transform:translateY(-50%)!important;background:var(--ab-glass)!important;filter:none!important}

.users-search-actions{display:flex;align-items:center;gap:8px;min-width:min(100%,300px);flex-wrap:wrap}
.users-search-actions input{flex:1 1 170px;min-width:0}
.users-search-actions button{flex:0 0 auto;width:auto;min-height:40px;margin:0}
.dashboard-component-list{display:grid;gap:8px;margin-top:13px}
.dashboard-component{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:9px 10px;border:1px solid var(--ab-line);border-radius:10px;background:var(--ab-glass);font-size:12px}
.dashboard-component .component-state{display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.dashboard-component .component-state:before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor;box-shadow:0 0 8px currentColor}
.dashboard-component .component-state.good{color:#73cba0}
.dashboard-component .component-state.bad{color:#e48e8e}
.server-table-wrap{width:100%;max-width:100%;overflow-x:auto;border:1px solid var(--ab-line);border-radius:14px;margin:12px 0 18px}
.workspace table.server-table{display:table!important;width:100%;min-width:560px;border-collapse:collapse;overflow:visible;background:transparent!important}
.server-table th,.server-table td{padding:13px 12px;text-align:right;white-space:nowrap;border-bottom:1px solid var(--ab-line);font-size:12px}
.server-table th{font-weight:650;color:var(--ab-muted);background:var(--ab-glass)}
.server-table tbody tr:last-child td{border-bottom:0}
.server-table td button{margin:0;padding:7px 10px;min-height:34px;width:auto;white-space:nowrap}
html[data-abyss-theme="angel"] .dashboard-component,html[data-abyss-theme="angel"] .server-table th{background:rgba(255,254,250,.85)}
@media(max-width:700px){.users-search-actions{width:100%;min-width:0}.users-search-actions button{flex:1 1 100%}.dashboard-component{font-size:11px}.server-table th,.server-table td{padding:11px 9px}}

.top .tools{align-items:center!important;gap:8px!important}
.top-tools-search{width:clamp(145px,18vw,230px)!important;min-width:130px!important;height:39px!important;min-height:39px!important;margin:0!important;padding:9px 12px!important;border:1px solid var(--ab-line)!important;border-radius:12px!important;background:var(--ab-glass)!important;color:var(--ab-text)!important;font-size:12px!important}
.toolbar-icon{display:inline-grid!important;place-items:center!important;flex:0 0 38px!important;width:38px!important;min-width:38px!important;height:38px!important;min-height:38px!important;margin:0!important;padding:0!important;border:1px solid var(--ab-line)!important;border-radius:12px!important;background:var(--ab-glass)!important;color:var(--ab-text)!important;font-size:15px!important}
.toolbar-icon svg{width:17px;height:17px;display:block}
.account-badge{display:inline-flex;align-items:center;gap:8px;min-width:0;padding:5px 8px;border:1px solid var(--ab-line);border-radius:12px;background:var(--ab-glass);color:var(--ab-text)}
.account-avatar{display:grid;place-items:center;flex:0 0 30px;width:30px;height:30px;border:1px solid var(--ab-line);border-radius:50%;color:var(--ab-accent);font-size:16px}
.account-copy{display:grid;gap:2px;min-width:0}.account-copy b{max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px}.account-copy small{font-size:9px;white-space:nowrap}
#panelHelpDialog{width:min(560px,calc(100vw - 24px));max-width:560px;padding:20px;border:1px solid var(--ab-line);border-radius:20px;background:var(--ab-bg);color:var(--ab-text)}
.help-dialog-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:14px}
.help-dialog-grid article{padding:13px;border:1px solid var(--ab-line);border-radius:13px;background:var(--ab-glass)}
.help-dialog-grid article b{font-size:12px;color:var(--ab-accent)}.help-dialog-grid article p{margin:7px 0 0;line-height:1.8}
html[data-abyss-theme="angel"] .top-tools-search,html[data-abyss-theme="angel"] .toolbar-icon,html[data-abyss-theme="angel"] .account-badge,html[data-abyss-theme="angel"] .help-dialog-grid article{background:rgba(255,254,250,.82)!important}
@media(max-width:700px){.top .tools{display:flex!important;align-items:center;gap:7px!important}.top-tools-search{width:100%!important;min-width:0!important;flex:1 1 100%!important;order:-1}.account-badge{flex:1 1 auto;justify-content:center}.account-copy b{max-width:90px}.help-dialog-grid{grid-template-columns:minmax(0,1fr)}}

.login-layout>.card form>label[for="username"],.login-layout>.card form>label[for="password"]{position:absolute!important;width:1px!important;height:1px!important;padding:0!important;margin:-1px!important;overflow:hidden!important;clip:rect(0,0,0,0)!important;white-space:nowrap!important;border:0!important}
.login-layout>.card .login-input-wrap{margin-top:12px!important}
.login-layout>.card .login-input-wrap input::placeholder{color:var(--ab-muted)!important;opacity:.95}
.login-extra-row{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:13px;font-size:11px}
.login-extra-row .remember-option{display:flex!important;align-items:center;gap:8px;margin:0!important;color:var(--ab-muted);cursor:pointer}
.login-extra-row .remember-option input{width:15px!important;min-width:15px!important;height:15px!important;min-height:15px!important;margin:0!important;padding:0!important;accent-color:var(--ab-accent);cursor:pointer}
.login-extra-row a{color:var(--ab-muted);text-decoration:none;border-bottom:1px solid var(--ab-line);padding-bottom:2px}
.login-extra-row a:hover{color:var(--ab-text);border-color:var(--ab-accent)}
#loginHelpDialog{width:min(440px,calc(100vw - 24px));max-width:440px;padding:20px;border:1px solid var(--ab-line);border-radius:20px;background:var(--ab-bg);color:var(--ab-text)}

/* Reference login eclipse: a dark solar disc with fine monochrome corona rays. */
.login-visual{background-color:#030303!important;background-image:radial-gradient(ellipse at 50% 50%,rgba(230,231,234,.045),transparent 48%),radial-gradient(1px 1px at 12% 16%,rgba(235,236,239,.8) 98%,transparent),radial-gradient(1px 1px at 81% 23%,rgba(235,236,239,.65) 98%,transparent),radial-gradient(1px 1px at 74% 82%,rgba(235,236,239,.55) 98%,transparent),radial-gradient(1px 1px at 26% 77%,rgba(235,236,239,.5) 98%,transparent),linear-gradient(145deg,#050505,#010101 68%,#070707)!important;background-size:100% 100%,310px 260px,370px 300px,290px 330px,410px 350px,100% 100%!important}
.login-visual .visual-orbit{border:0!important;box-shadow:none!important;background:repeating-conic-gradient(from -4deg at 50% 50%,rgba(214,216,221,.26) 0deg .22deg,transparent .24deg 3.4deg);filter:drop-shadow(0 0 18px rgba(220,222,226,.07));}
.login-visual .visual-orbit:before{inset:0!important;border:0!important;border-radius:50%!important;transform:none!important;background:radial-gradient(circle at 50% 50%,#000 0 15.5%,rgba(0,0,0,.97) 16% 18%,transparent 18.7%);box-shadow:inset 0 0 32px rgba(0,0,0,.95),0 0 0 1px rgba(235,236,239,.08);}
.login-visual .visual-orbit:after{inset:13%!important;border:1px solid rgba(220,222,226,.14)!important;border-radius:50%!important;transform:none!important;box-shadow:0 0 26px rgba(225,226,230,.08),inset 0 0 22px rgba(220,222,226,.035)!important;background:transparent!important;}
.login-visual .visual-eyebrow{letter-spacing:.25em}
@media(max-width:700px){.login-visual{display:none!important}}

/* Desktop reference layout: persistent left rail; drawer only on mobile. */
@media(min-width:851px){
 #menuToggle{display:none!important} #abyssMenuShade{display:none!important}
 .app-shell{display:block!important;min-height:100vh!important}
 .sidebar{position:fixed!important;left:0!important;right:auto!important;top:0!important;bottom:0!important;width:248px!important;height:100dvh!important;max-height:100dvh!important;transform:translateX(0)!important;visibility:visible!important;overflow-y:auto!important;border-right:1px solid rgba(185,188,194,.18)!important;padding:22px 14px!important;z-index:100!important}
 .workspace{width:calc(100% - 248px)!important;max-width:none!important;margin:0 0 0 248px!important;padding:28px clamp(18px,2vw,34px) 42px!important;min-width:0!important}
 .workspace .top{display:flex;align-items:center;gap:18px;flex-wrap:wrap;padding-top:0!important;margin-bottom:22px}
 .workspace .top .abyss-brand-row{margin-right:auto}
 .workspace .top .section-heading{flex:1 0 100%;margin:8px 0 0}
 .workspace .top .tools{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
 .stats{grid-template-columns:repeat(4,minmax(0,1fr))!important;gap:12px!important}
 .workspace [data-section-page],.workspace .card,.workspace .panel,.workspace .box{min-width:0}
}
@media(min-width:851px) and (max-width:1150px){
 .sidebar{width:220px!important}
 .workspace{width:calc(100% - 220px)!important;margin-left:220px!important;padding-inline:18px!important}
 .stats{grid-template-columns:repeat(2,minmax(0,1fr))!important}
}
@media(max-width:850px){
 #menuToggle{display:inline-flex!important}
 .sidebar{transform:translateX(-105%)!important;visibility:visible!important}
 .sidebar.open{transform:translateX(0)!important}
 .workspace{width:100%!important;max-width:none!important;margin:0!important}
}
@media(prefers-reduced-motion:reduce){.sidebar,#menuToggle,#abyssMenuShade{transition:none!important}}

/* Keep the usage chart focused on traffic only; system resource metrics belong on the diagnostics page, not inside this dashboard card. */
html body main.app-shell>.workspace>#dashboardUsageCard>.stats{display:none!important}
html body main.app-shell>.workspace>#dashboardUsageCard>#usageSparkline{margin-top:12px!important}
html body main.app-shell>.workspace>#dashboardUsageCard>#chartNote{margin-top:6px!important}

/* Reference correction: restore the quiet starfield and make the rays genuinely subtle. */
body:before{opacity:.16!important;background-image:linear-gradient(118deg,transparent 0 18%,rgba(205,207,214,.025) 18.08%,transparent 18.22% 54%,rgba(185,188,194,.018) 54.08%,transparent 54.22% 79%,rgba(220,221,225,.02) 79.08%,transparent 79.2%),linear-gradient(164deg,transparent 0 32%,rgba(190,193,199,.016) 32.08%,transparent 32.22% 68%,rgba(210,212,216,.014) 68.08%,transparent 68.2%)!important;animation:abyssStreakDrift 46s ease-in-out infinite alternate!important}
body:after{content:""!important;position:fixed!important;inset:0!important;z-index:0!important;pointer-events:none!important;opacity:.46!important;mix-blend-mode:screen!important;background-image:radial-gradient(1px 1px at 4% 12%,rgba(245,246,250,.82) 55%,transparent 100%),radial-gradient(1px 1px at 11% 68%,rgba(228,230,236,.62) 55%,transparent 100%),radial-gradient(1.2px 1.2px at 18% 31%,rgba(245,246,250,.72) 55%,transparent 100%),radial-gradient(1px 1px at 25% 84%,rgba(228,230,236,.58) 55%,transparent 100%),radial-gradient(1px 1px at 31% 19%,rgba(245,246,250,.68) 55%,transparent 100%),radial-gradient(1.3px 1.3px at 39% 57%,rgba(228,230,236,.7) 55%,transparent 100%),radial-gradient(1px 1px at 46% 9%,rgba(245,246,250,.64) 55%,transparent 100%),radial-gradient(1px 1px at 53% 76%,rgba(228,230,236,.62) 55%,transparent 100%),radial-gradient(1.2px 1.2px at 61% 39%,rgba(245,246,250,.72) 55%,transparent 100%),radial-gradient(1px 1px at 68% 15%,rgba(228,230,236,.62) 55%,transparent 100%),radial-gradient(1px 1px at 74% 88%,rgba(245,246,250,.66) 55%,transparent 100%),radial-gradient(1.2px 1.2px at 82% 49%,rgba(228,230,236,.72) 55%,transparent 100%),radial-gradient(1px 1px at 89% 24%,rgba(245,246,250,.64) 55%,transparent 100%),radial-gradient(1px 1px at 96% 72%,rgba(228,230,236,.7) 55%,transparent 100%),radial-gradient(ellipse at 16% 20%,rgba(185,187,194,.025),transparent 28%),radial-gradient(ellipse at 78% 72%,rgba(160,162,170,.022),transparent 32%)!important;background-size:100% 100%!important}
.sidebar{width:190px!important}
</style>"""
ABYSS_LAYOUT_REPAIR_JS = r"""<script id="abyss-layout-repair-js">
(()=> {
  const init=()=>{
    const sidebar=document.getElementById('sidebar');
    const menu=document.getElementById('menuToggle');
    if(!sidebar || !menu) return;
    let shade=document.getElementById('abyssMenuShade');
    if(!shade){shade=document.createElement('div');shade.id='abyssMenuShade';shade.setAttribute('aria-hidden','true');const shell=document.querySelector('.app-shell');(shell||document.body).appendChild(shade);}
    const setOpen=(open)=>{
      sidebar.classList.toggle('open',open);
      document.body.classList.toggle('abyss-menu-open',open);
      menu.setAttribute('aria-expanded',String(open));
      menu.setAttribute('aria-label',open?'بستن منو':'باز کردن منو');
      menu.innerHTML=open?'✕ <span>بستن</span>':'☰ <span>منو</span>';
    };
    window.toggleSidebar=()=>setOpen(!sidebar.classList.contains('open'));
    menu.removeAttribute('onclick');menu.addEventListener('click',e=>{e.preventDefault();setOpen(!sidebar.classList.contains('open'));});
    shade.addEventListener('click',()=>setOpen(false));
    sidebar.querySelectorAll('[data-nav]').forEach(item=>item.addEventListener('click',()=>setOpen(false)));
    document.addEventListener('keydown',e=>{if(e.key==='Escape')setOpen(false);});
    const original=window.showSection;
    if(typeof original==='function'){
      window.showSection=(name)=>{original(name);setOpen(false);};
      original('dashboard');
    } else {
      document.querySelectorAll('[data-section-page]').forEach(el=>el.classList.toggle('nav-hidden',el.dataset.sectionPage!=='dashboard'));
    }
    menu.style.display='inline-flex';
  };
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init,{once:true});else init();
})();
</script>"""
LOGIN = LOGIN.replace('<body><main class="card">','<body><div class="login-layout"><aside class="login-visual" aria-label="Abyss Tunnel"><img class="visual-orbit" src="/brand/abyss-tunnel-logo.jpg" alt="AbyssTunnel · I.T.A."></aside><main class="card">').replace('</form></main></body>','</form></main><dialog id="loginHelpDialog"><div class="modal-top"><div><h2>بازیابی رمز عبور</h2><div class="small">راهنمای دسترسی امن</div></div><button type="button" onclick="document.getElementById(\'loginHelpDialog\').close()" aria-label="بستن">✕</button></div><p class="small">بازیابی از طریق ایمیل در این استقرار پیکربندی نشده است. اگر رمز عبور را تغییر داده‌ای و فراموش کرده‌ای، از مالک پنل برای بازنشانی امن کمک بگیر.</p></dialog></div></body>').replace('</dialog></div></body>','</dialog><footer class="login-reference-footer"><div class="login-footer-links"><a href="https://github.com/bodisbos-cmd/Void" target="_blank" rel="noopener">⌘ GitHub ↗</a><a href="#support-link-not-configured" onclick="if(this.getAttribute(&quot;href&quot;)==&quot;#support-link-not-configured&quot;){alert(&quot;لینک حمایت مالی هنوز تنظیم نشده است؛ متغیر SUPPORT_URL را در Railway تنظیم کن.&quot;);return false}">◇ حمایت از پروژه</a></div><div class="login-footer-brand">AbyssTunnel · I.T.A.<small>Secure · Private · Unlimited</small></div></footer></div></body>')
ABYSS_FINAL_LAYOUT_CSS = r"""<style id="abyss-final-layout">
/* Final cascade layer: deliberately last so the reference layout wins over legacy inline templates. */
.login-layout{position:relative!important;isolation:isolate!important;display:grid!important;grid-template-columns:minmax(0,1fr)!important;place-items:center!important;align-content:center!important;gap:0!important;width:100%!important;max-width:none!important;min-height:100dvh!important;margin:0!important;padding:28px 14px!important;direction:rtl!important}
.login-visual{position:fixed!important;inset:0!important;z-index:0!important;display:block!important;pointer-events:none!important;padding:0!important;border:0!important;border-radius:0!important;background:transparent!important;box-shadow:none!important;overflow:hidden!important;backdrop-filter:none!important;-webkit-backdrop-filter:none!important}
.login-visual .visual-eyebrow,.login-visual h2,.login-visual p{display:none!important}
.login-visual .visual-orbit{position:absolute!important;top:4%!important;left:4%!important;width:min(56vw,610px)!important;max-width:none!important;aspect-ratio:1!important;margin:0!important;opacity:.21!important;pointer-events:none!important}
.login-layout>.card{position:relative!important;z-index:2!important;width:min(100%,430px)!important;max-width:430px!important;margin:0 auto!important;justify-self:center!important;align-self:center!important}
.login-layout:before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;background:radial-gradient(circle at 50% 42%,rgba(205,207,213,.075),transparent 38%),radial-gradient(circle at 50% 50%,#050505 0,#020202 72%)}
[data-section-page].nav-hidden{display:none!important}
[data-section-page]:not(.nav-hidden){display:block}
#abyssMenuShade{position:fixed;inset:0;z-index:49;background:rgba(0,0,0,.62);opacity:0;pointer-events:none;transition:opacity .2s ease}
body.abyss-menu-open #abyssMenuShade{opacity:1;pointer-events:auto}
@media(max-width:850px){.login-layout{padding:20px 14px!important}.login-layout>.card{width:min(100%,420px)!important}.login-visual .visual-orbit{width:90vw!important;left:-20vw!important;top:-8%!important;opacity:.15!important}}
/* Ensure the section state wins over legacy display:grid!important rules. */
html body .workspace [data-section-page].nav-hidden,
html body .workspace .stats[data-section-page].nav-hidden,
html body .workspace section.card[data-section-page].nav-hidden{display:none!important;visibility:hidden!important;pointer-events:none!important}
html body .workspace [data-section-page]:not(.nav-hidden){visibility:visible}
html body .workspace #overviewStats[data-section-page="dashboard"]{display:grid!important;grid-template-columns:repeat(4,minmax(0,1fr))!important}
html body .workspace #dashboardUsageCard[data-section-page="dashboard"]{display:block!important;width:100%;max-width:100%;margin-top:16px}
html body .workspace #dashboardUsageCard>.stats{display:grid!important;grid-template-columns:repeat(3,minmax(0,1fr))!important}
html body .workspace #dashboardUsageCard>.stats>.card{min-width:0!important}
html body .workspace #dashboardUsageCard canvas{display:block;width:100%!important;max-width:100%!important}
@media(max-width:850px){
 html body .workspace #overviewStats[data-section-page="dashboard"]{grid-template-columns:repeat(2,minmax(0,1fr))!important}
 html body .workspace #dashboardUsageCard>.stats{grid-template-columns:repeat(3,minmax(0,1fr))!important}
}
@media(min-width:851px) and (max-width:1150px){html body .workspace #overviewStats[data-section-page="dashboard"]{grid-template-columns:repeat(2,minmax(0,1fr))!important}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;animation-duration:.01ms!important;transition-duration:.01ms!important}}

/* ID-specific hiding is required because legacy #id rules have higher specificity than generic section selectors. */
html body .workspace>#overviewStats.nav-hidden,
html body .workspace>#dashboardUsageCard.nav-hidden,
html body .workspace>#panelHealthCard.nav-hidden,
html body .workspace>section#clientsCard.nav-hidden,
html body .workspace>section#userManagement.nav-hidden,
html body .workspace>section#protocolsCard.nav-hidden,
html body .workspace>section#serversCard.nav-hidden,
html body .workspace>section#reportsCard.nav-hidden,
html body .workspace>section#settingsCard.nav-hidden{display:none!important}
html body .workspace>#overviewStats:not(.nav-hidden){display:grid!important}
html body .workspace>#dashboardUsageCard:not(.nav-hidden){display:block!important}
html body .workspace>#panelHealthCard:not(.nav-hidden){display:block!important}

/* High-specificity section state overrides legacy ID-based display:grid rules. */
html body .workspace>#overviewStats.nav-hidden,
html body .workspace>#dashboardUsageCard.nav-hidden,
html body .workspace>#panelHealthCard.nav-hidden,
html body .workspace>section.card.nav-hidden,
html body .workspace>section.nav-hidden{display:none!important;visibility:hidden!important;pointer-events:none!important}
html body .workspace>#overviewStats:not(.nav-hidden),
html body .workspace>#dashboardUsageCard:not(.nav-hidden),
html body .workspace>#panelHealthCard:not(.nav-hidden){visibility:visible!important}

/* Navigation visibility must outrank legacy ID selectors carrying display:grid!important. */
html body .workspace>#overviewStats.nav-hidden,
html body .workspace>#dashboardUsageCard.nav-hidden,
html body .workspace>#panelHealthCard.nav-hidden,
html body .workspace>#createServiceCard.nav-hidden,
html body .workspace>section[id].nav-hidden{display:none!important;visibility:hidden!important;pointer-events:none!important}
html body .workspace>#overviewStats:not(.nav-hidden){display:grid!important}
html body .workspace>#dashboardUsageCard:not(.nav-hidden){display:block!important}

/* Reference fidelity pass: denser raised dashboard cards and restrained monochrome atmosphere. */
@media(min-width:851px){
 .workspace .stats{gap:10px!important}
 .workspace .stats>.card{padding:14px 16px!important;border-radius:14px!important;min-height:82px!important}
 .workspace .stats .num{font-size:25px!important;line-height:1.25!important}
 .workspace .section-heading{font-size:20px!important}
 .workspace .card,.workspace .panel,.workspace .box{box-shadow:0 8px 24px rgba(0,0,0,.22),inset 0 1px rgba(255,255,255,.035)!important}
}
@media(min-width:851px) and (max-height:900px){
 .workspace{padding-top:68px!important}
 .workspace .stats>.card{min-height:72px!important}
}
body:before{opacity:.19!important}

/* Reference match pass: restore the two-column eclipse login composition from the supplied screenshots. */
@media(min-width:851px){
 .login-layout{direction:ltr!important;grid-template-columns:minmax(0,1fr) minmax(0,1fr)!important;grid-template-rows:minmax(0,1fr)!important;place-items:center!important;align-content:stretch!important;gap:clamp(24px,4vw,72px)!important;padding:5vh clamp(26px,5vw,86px)!important;min-height:100vh!important}
 .login-layout>.login-visual{position:relative!important;inset:auto!important;grid-column:1!important;grid-row:1!important;width:100%!important;height:100%!important;min-height:620px!important;display:flex!important;flex-direction:column!important;align-items:center!important;justify-content:center!important;overflow:visible!important;pointer-events:none!important}
 .login-layout>.login-visual .visual-orbit{position:absolute!important;top:50%!important;left:50%!important;transform:translate(-50%,-50%)!important;width:min(43vw,610px)!important;opacity:.75!important}
 .login-layout>.card{grid-column:2!important;grid-row:1!important;justify-self:center!important;align-self:center!important;width:min(100%,430px)!important}
 .login-layout:before{background:radial-gradient(ellipse at 24% 50%,rgba(160,163,171,.04),transparent 34%),#020202!important}
}
@media(max-width:850px){
 .login-layout{direction:rtl!important;grid-template-columns:minmax(0,1fr)!important}
 .login-layout>.login-visual{position:fixed!important;inset:0!important;min-height:0!important}
 .login-layout>.login-visual .visual-orbit{top:8%!important;left:50%!important;transform:translateX(-50%)!important;width:82vw!important;opacity:.28!important}
 .login-layout>.card{grid-column:1!important;grid-row:1!important}
}
/* Dashboard components follow the compact reference dashboard proportions. */
@media(min-width:1151px){
 .workspace>#dashboardUsageCard{grid-column:span 7!important}
 .workspace>#panelHealthCard{grid-column:span 5!important}
}
.workspace>#panelHealthCard{padding:18px!important}
.workspace>#panelHealthCard #status{gap:7px!important}
.workspace>#panelHealthCard #status>*{padding:9px 11px!important;border-radius:11px!important}
.sidebar{width:218px!important}
.workspace{max-width:calc(100% - 218px)!important}
@media(max-width:850px){
 .sidebar{width:min(290px,84vw)!important}
 .workspace{max-width:100%!important}
}


/* Explicit ID-level section hiding: legacy ID selectors with !important otherwise keep hidden sections in the grid. */
html body .workspace>#overviewStats.nav-hidden,
html body .workspace>#dashboardUsageCard.nav-hidden,
html body .workspace>#panelHealthCard.nav-hidden,
html body .workspace>#createServiceCard.nav-hidden{display:none!important;visibility:hidden!important;pointer-events:none!important}
html body .workspace>#overviewStats:not(.nav-hidden){display:grid!important}
html body .workspace>#dashboardUsageCard:not(.nav-hidden),
html body .workspace>#panelHealthCard:not(.nav-hidden),
html body .workspace>#createServiceCard:not(.nav-hidden){display:block!important}
html body .workspace>#dashboardUsageCard:not(.nav-hidden){grid-column:span 8!important}
html body .workspace>#panelHealthCard:not(.nav-hidden){grid-column:span 4!important}
@media(max-width:980px){
 html body .workspace>#dashboardUsageCard:not(.nav-hidden),
 html body .workspace>#panelHealthCard:not(.nav-hidden){grid-column:1/-1!important}
}
/* Hide ID-targeted dashboard sections even against legacy ID selectors using display:grid!important. */
html body .workspace>#overviewStats.nav-hidden,
html body .workspace>#dashboardUsageCard.nav-hidden,
html body .workspace>#panelHealthCard.nav-hidden{display:none!important;visibility:hidden!important;pointer-events:none!important}
html body .workspace>#overviewStats:not(.nav-hidden){display:grid!important}
html body .workspace>#dashboardUsageCard:not(.nav-hidden),
html body .workspace>#panelHealthCard:not(.nav-hidden){display:block!important}
/* Critical section visibility fix: ID-level dashboard display rules must not override navigation state. */
html body .workspace #overviewStats.nav-hidden,
html body .workspace #dashboardUsageCard.nav-hidden,
html body .workspace #panelHealthCard.nav-hidden{display:none!important;visibility:hidden!important;pointer-events:none!important}
html body .workspace #overviewStats:not(.nav-hidden){display:grid!important}
html body .workspace #dashboardUsageCard:not(.nav-hidden),
html body .workspace #panelHealthCard:not(.nav-hidden){display:block!important}

/* ID selectors from the legacy dashboard had higher specificity than the generic hidden-state rule. */
html body .workspace>#overviewStats.nav-hidden,
html body .workspace>#dashboardUsageCard.nav-hidden,
html body .workspace>#panelHealthCard.nav-hidden,
html body .workspace>#createServiceCard.nav-hidden,
html body .workspace>section.card.nav-hidden{display:none!important;visibility:hidden!important;pointer-events:none!important}
html body .workspace>#overviewStats:not(.nav-hidden){display:grid!important}
html body .workspace>#dashboardUsageCard:not(.nav-hidden),
html body .workspace>#panelHealthCard:not(.nav-hidden){display:block!important}
/* Final screenshot-driven repairs: keep the dashboard health panel readable and prevent mobile overflow. */
/* Keep the theme selector inside the dashboard toolbar; it is not part of the login composition. */
body:has(.login-layout) #abyssThemeDock{display:none!important}
body:has(.login-layout) .login-layout>.card{border-top:1px solid rgba(205,208,214,.2)!important}
body:has(.login-layout) .login-layout>.card:before{background:linear-gradient(90deg,transparent,rgba(200,202,207,.18),transparent)!important}
.workspace>#dashboardUsageCard>.section-title{color:#d4d5d8!important}
.workspace>#panelHealthCard>.section-title{color:#e4e5e7!important}

:root{--ab-mint:#a9b9b0!important;--abyss-mint:#a9b9b0!important}
html,body{max-width:100%;overflow-x:clip!important}
input[type=checkbox],input[type=radio],.profile-option input{accent-color:#a9b9b0!important}
.login-layout>.card{border-top-color:rgba(205,208,214,.22)!important}
.login-layout>.card button{background:linear-gradient(145deg,#c8c9cc,#96989e)!important;color:#09090a!important}
.workspace>#dashboardUsageCard{grid-column:1/-1!important;width:100%!important}
.workspace>#panelHealthCard{grid-column:1/-1!important;width:100%!important;display:block!important;min-width:0!important;overflow:hidden!important}
.workspace>#panelHealthCard #status{display:grid!important;grid-template-columns:repeat(4,minmax(0,1fr))!important;gap:10px!important;width:100%!important;min-width:0!important}
.workspace>#panelHealthCard #status>*{min-width:0!important;max-width:100%!important;overflow-wrap:anywhere!important;white-space:normal!important}
.workspace>#panelHealthCard .section-title,.workspace>#panelHealthCard .small{max-width:100%!important;overflow-wrap:anywhere!important}
.workspace>#dashboardUsageCard>.stats{margin-top:14px!important}
.workspace>#dashboardUsageCard>.stats>.card{border-radius:16px!important}
@media(max-width:850px){
 body:not(.abyss-menu-open) .sidebar{transform:translateX(-110%)!important;visibility:hidden!important;pointer-events:none!important}
 body.abyss-menu-open .sidebar{transform:translateX(0)!important;visibility:visible!important;pointer-events:auto!important}
 .workspace{width:100%!important;max-width:100%!important;min-width:0!important;margin:0!important;overflow-x:clip!important}
 .workspace .top,.workspace .top>*{max-width:100%!important;min-width:0!important}
 .workspace .abyss-brand-row{max-width:100%!important;overflow:hidden!important}
 .workspace .brand-name{min-width:0!important;max-width:100%!important}
 .workspace .top .tools{min-width:0!important}
 .workspace .top .tools>*{min-width:0!important;max-width:100%!important}
 .workspace>#panelHealthCard #status{grid-template-columns:repeat(2,minmax(0,1fr))!important}
}
/* Final compact section placement and neutral palette cleanup. */
.workspace{grid-auto-flow:row!important;grid-auto-rows:max-content!important;align-content:start!important}
.workspace>section[data-section-page]{align-self:start!important;min-height:0!important}
html body .workspace>#createServiceCard:not(.nav-hidden){margin-block-start:0!important;grid-column:1/-1!important}
html body .workspace>#createServiceCard .reference-page-head{margin-block-start:0!important}
.login-layout>.card{border-top:1px solid rgba(210,212,216,.19)!important;box-shadow:0 22px 70px rgba(0,0,0,.42),inset 0 1px rgba(255,255,255,.025)!important}
.login-layout>.card:before{display:none!important}
.login-layout .login-brand .abyss-logo-svg{filter:grayscale(1)!important}
@media(max-width:850px){
 .workspace>section[data-section-page]{grid-column:1/-1!important}
 html body .workspace>#createServiceCard:not(.nav-hidden){width:100%!important}
}
@media(max-width:390px){
 .workspace{padding-left:10px!important;padding-right:10px!important}
 .workspace .brand-name b{font-size:14px!important;letter-spacing:.08em!important}
 .workspace .top .tools button{flex:1 1 calc(33.333% - 7px)!important}
 .workspace>#panelHealthCard #status{grid-template-columns:repeat(2,minmax(0,1fr))!important}
}


/* Recent activity cards keep long event messages readable inside the narrower status column. */
.workspace #recentActivityList .report-event{display:grid!important;grid-template-columns:minmax(0,1fr)!important;gap:5px!important;align-items:start!important;min-width:0!important;padding:10px 12px!important}
.workspace #recentActivityList .event-message{display:block!important;min-width:0!important;max-width:100%!important;white-space:normal!important;overflow-wrap:anywhere!important;word-break:normal!important;line-height:1.55!important}
.workspace #recentActivityList .event-meta{display:block!important;min-width:0!important;max-width:100%!important;direction:ltr!important;text-align:left!important;white-space:normal!important;overflow-wrap:anywhere!important;font-size:10px!important;line-height:1.45!important;color:var(--ab-muted)!important}

/* Compact mobile toolbar: keep essential controls usable without pushing the dashboard far below the fold. */
@media(max-width:700px){
 html body .workspace .top{gap:7px!important;padding-bottom:10px!important}
 html body .workspace .top .tools{display:grid!important;grid-template-columns:repeat(4,minmax(0,1fr))!important;grid-auto-flow:row!important;gap:5px!important;width:100%!important;align-items:stretch!important}
 html body .workspace .top .tools #globalSearch,
 html body .workspace .top .tools .top-tools-search{grid-column:1/-1!important;width:100%!important;min-height:36px!important}
 html body .workspace .top .tools button{flex:none!important;width:100%!important;min-width:0!important;min-height:34px!important;padding:6px 4px!important;font-size:11px!important;white-space:normal!important}
 html body .workspace .top .tools .account-badge{grid-column:span 2!important;min-width:0!important;max-width:100%!important;padding:4px 7px!important;justify-content:center!important}
 html body .workspace .top .tools .account-copy{min-width:0!important;max-width:100%!important;overflow-wrap:anywhere!important}
 html body .workspace .top .tools #abyssThemeDock{grid-column:span 2!important;width:100%!important;max-width:100%!important;min-width:0!important;display:flex!important;justify-content:center!important;gap:5px!important;padding:5px 7px!important}
 html body .workspace .top .tools #abyssThemeDock select{min-width:0!important;width:auto!important;max-width:calc(100% - 34px)!important;font-size:10px!important}
}

/* Visual review fix: non-dashboard sections must occupy the first available workspace row.
   Older layout rules left their actual forms/tables below a large empty dashboard-sized grid area. */
@media(min-width:851px){
 html body .workspace>[data-section-page]:not(.nav-hidden):not(#overviewStats):not(#dashboardUsageCard):not(#panelHealthCard):not(#dashboardQuickCard){
   grid-row:auto!important;
   grid-column:1/-1!important;
   align-self:start!important;
   min-height:0!important;
   height:auto!important;
   margin-block:0 14px!important;
 }
 html body .workspace>[data-section-page]:not(.nav-hidden):not(#overviewStats):not(#dashboardUsageCard):not(#panelHealthCard):not(#dashboardQuickCard)>.reference-page-head{
   margin-block-start:0!important;
 }
}
@media(max-width:850px){
 html body .workspace>[data-section-page]:not(.nav-hidden):not(#overviewStats):not(#dashboardUsageCard):not(#panelHealthCard):not(#dashboardQuickCard){
   grid-row:auto!important;
   grid-column:1/-1!important;
   align-self:start!important;
   min-height:0!important;
   height:auto!important;
   margin-block:0 12px!important;
 }
}

/* Screenshot-review follow-up: restore the reference dashboard's side-by-side monitoring
   and service-health cards; keep recent activity from stretching the entire page. */
@media(min-width:1151px){
 html body .workspace>#dashboardUsageCard[data-section-page="dashboard"]{
   grid-column:span 7!important;width:auto!important;min-width:0!important;margin-top:0!important;
 }
 html body .workspace>#panelHealthCard[data-section-page="dashboard"]{
   grid-column:span 5!important;width:auto!important;min-width:0!important;align-self:start!important;
 }
}
html body .workspace>#panelHealthCard #recentActivityList{
 max-height:260px!important;overflow-y:auto!important;overscroll-behavior:contain!important;
 scrollbar-width:thin!important;
}
html body .workspace>#panelHealthCard #dashboardComponentStatus{width:100%!important;min-width:0!important}
html body .workspace>#panelHealthCard .section-title{line-height:1.45!important}
@media(min-width:851px) and (max-width:1150px){
 html body .workspace>#dashboardUsageCard,html body .workspace>#panelHealthCard{
   grid-column:1/-1!important;width:100%!important;
 }
}
@media(max-width:850px){
 html body .workspace>#panelHealthCard #status{grid-template-columns:repeat(2,minmax(0,1fr))!important}
 html body .workspace>#panelHealthCard #recentActivityList{max-height:220px!important}
}

/* Visual pass 3: compact reference-like dashboard and avoid oversized toolbar on narrow screens. */
@media(min-width:1151px){
 html body .workspace>#dashboardUsageCard[data-section-page="dashboard"]{
   grid-column:6 / span 7!important;
   grid-row:2!important;
 }
 html body .workspace>#panelHealthCard[data-section-page="dashboard"]{
   grid-column:1 / span 5!important;
   grid-row:2!important;
 }
 html body .workspace>#overviewStats[data-section-page="dashboard"]{
   grid-column:1/-1!important;
 }
}
html body .workspace>#dashboardUsageCard .chart-wrap,
html body .workspace>#dashboardUsageCard canvas,
html body .workspace>#dashboardUsageCard svg{max-width:100%!important}
html body .workspace>#panelHealthCard #recentActivityList{
 max-height:190px!important;overflow:auto!important;
}
@media(min-width:851px){
 html body .workspace{align-content:start!important;align-items:start!important}
 html body .workspace>[data-section-page]:not(#overviewStats):not(#dashboardUsageCard):not(#panelHealthCard):not(#dashboardQuickCard):not(.nav-hidden){
   min-height:0!important;
 }
}
@media(max-width:850px){
 html body .topbar,html body .header-actions,html body .toolbar-actions{
   max-width:100%!important;flex-wrap:wrap!important;gap:6px!important;
 }
 html body .workspace>#panelHealthCard #status{grid-template-columns:repeat(2,minmax(0,1fr))!important}
 html body .workspace>#dashboardUsageCard,
 html body .workspace>#panelHealthCard{min-width:0!important;max-width:100%!important}
 html body .workspace>#dashboardUsageCard .chart-wrap{overflow:hidden!important}
}

/* Reference fidelity pass: establish an intentional dashboard grid rather than relying on
   auto-placement; keep the overview metrics above the chart and service health panels. */
@media(min-width:851px){
 html body .app-shell{grid-template-columns:196px minmax(0,1fr)!important;max-width:none!important}
 html body .sidebar{width:196px!important;box-sizing:border-box!important;padding:18px 10px!important}
 html body .workspace{
   display:grid!important;
   grid-template-columns:repeat(12,minmax(0,1fr))!important;
   grid-auto-flow:row!important;
   align-content:start!important;
   align-items:start!important;
   gap:12px!important;
   width:100%!important;max-width:none!important;
   min-width:0!important;
   padding:14px 18px 26px!important;
 }
 html body .workspace>.top{grid-column:1/-1!important;grid-row:1!important;min-width:0!important;display:flex!important;align-items:center!important;gap:12px!important;padding:2px 0 12px!important}
 html body .workspace>#overviewStats{grid-column:1/-1!important;grid-row:2!important;margin:0!important;display:grid!important;grid-template-columns:repeat(4,minmax(0,1fr))!important;gap:10px!important;min-width:0!important}
 html body .workspace>#dashboardUsageCard{grid-column:6/span 7!important;grid-row:3!important;align-self:start!important;margin:0!important;min-width:0!important}
 html body .workspace>#panelHealthCard{grid-column:1/span 5!important;grid-row:3!important;align-self:start!important;margin:0!important;min-width:0!important}
 html body .workspace>.top .abyss-brand-row{flex:0 0 auto!important}
 html body .workspace>.top .mint{margin-inline-start:auto!important;white-space:nowrap!important}
 html body .workspace>.top .section-heading{margin:0!important;font-size:18px!important;white-space:nowrap!important}
 html body .workspace>.top .tools{flex:1 1 auto!important;min-width:0!important;display:flex!important;justify-content:flex-end!important;flex-wrap:wrap!important;gap:6px!important}
 html body .workspace>.top .tools input{width:190px!important;min-width:100px!important}
 html body .workspace>#overviewStats>.card{min-width:0!important;margin:0!important;padding:15px 16px!important}
 html body .workspace>#dashboardUsageCard,html body .workspace>#panelHealthCard{padding:16px!important}
 html body .workspace>#dashboardUsageCard>.stats{display:grid!important;grid-template-columns:repeat(3,minmax(0,1fr))!important;gap:8px!important;margin:12px 0!important}
 html body .workspace>#dashboardUsageCard>.stats>.card{min-width:0!important;margin:0!important;padding:10px!important}
 html body .workspace>#dashboardUsageCard canvas{display:block!important;width:100%!important;height:150px!important}
 html body .workspace>#panelHealthCard #status{display:none!important}
 html body .workspace>#panelHealthCard #dashboardComponentStatus{display:grid!important;grid-template-columns:1fr!important;gap:7px!important}
 html body .workspace>#panelHealthCard .report-events{display:grid!important;gap:7px!important}
 html body .workspace>[data-section-page]:not(#overviewStats):not(#dashboardUsageCard):not(#panelHealthCard):not(#dashboardQuickCard):not(.nav-hidden){
   grid-column:1/-1!important;grid-row:auto!important;align-self:start!important;margin:0!important;min-width:0!important;
 }
}
html body .sidebar{background:linear-gradient(180deg,rgba(9,9,10,.98),rgba(3,3,4,.99))!important;border-right:1px solid rgba(180,182,188,.16)!important;border-left:1px solid rgba(180,182,188,.12)!important}
html body .side-brand{padding:7px 8px 18px!important}
html body .side-nav{gap:4px!important}
html body .nav-item{min-height:37px!important;padding:9px 10px!important;border-radius:10px!important;font-size:12px!important}
html body .nav-item:hover,html body .nav-item.active{background:linear-gradient(120deg,rgba(220,222,228,.13),rgba(220,222,228,.035))!important;border-color:rgba(205,207,213,.18)!important;color:#f0f0f2!important;box-shadow:inset 0 1px 0 rgba(255,255,255,.04)!important}
html body .workspace .card{background:linear-gradient(145deg,rgba(16,16,18,.97),rgba(6,6,7,.98))!important;border-color:rgba(176,179,187,.17)!important;box-shadow:0 10px 28px rgba(0,0,0,.2),inset 0 1px 0 rgba(255,255,255,.035)!important;border-radius:13px!important}
html body .workspace #overviewStats>.card .num{font-size:clamp(20px,2vw,29px)!important}
html body .workspace .section-title{font-size:14px!important;letter-spacing:0!important}
html body .workspace .small{line-height:1.5!important}
@media(min-width:851px) and (max-width:1150px){
 html body .workspace{grid-template-columns:repeat(6,minmax(0,1fr))!important;padding:12px!important}
 html body .workspace>.top,html body .workspace>#overviewStats{grid-column:1/-1!important}
 html body .workspace>#dashboardUsageCard{grid-column:1/-1!important;grid-row:3!important}
 html body .workspace>#panelHealthCard{grid-column:1/-1!important;grid-row:4!important}
 html body .workspace>#overviewStats{grid-template-columns:repeat(2,minmax(0,1fr))!important}
}
@media(max-width:850px){
 html body .app-shell{display:block!important}
 html body .sidebar{width:min(290px,84vw)!important;max-width:84vw!important;padding:18px 12px!important}
 html body .workspace{display:grid!important;grid-template-columns:minmax(0,1fr)!important;gap:10px!important;padding:8px 12px 24px!important}
 html body .workspace>.top{grid-column:1!important;grid-row:auto!important;display:flex!important;flex-wrap:wrap!important;gap:8px!important;padding:8px 0 12px!important}
 html body .workspace>#overviewStats{grid-column:1!important;grid-row:auto!important;display:grid!important;grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:8px!important;margin:0!important}
 html body .workspace>#dashboardUsageCard,html body .workspace>#panelHealthCard{grid-column:1!important;grid-row:auto!important;margin:0!important;min-width:0!important;width:100%!important}
 html body .workspace>#dashboardUsageCard>.stats{display:grid!important;grid-template-columns:repeat(3,minmax(0,1fr))!important;gap:6px!important}
 html body .workspace>#dashboardUsageCard canvas{max-width:100%!important;height:120px!important}
 html body .workspace>#panelHealthCard #status{display:none!important}
 html body .workspace>#panelHealthCard #dashboardComponentStatus{display:grid!important;grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:7px!important}
 html body .workspace>[data-section-page]:not(#overviewStats):not(#dashboardUsageCard):not(#panelHealthCard):not(#dashboardQuickCard):not(.nav-hidden){grid-column:1!important;grid-row:auto!important;margin:0!important;min-width:0!important;width:100%!important}
}

/* Reference-layout correction: let the grid size rows from actual content.
   Fixed row numbers caused the stats and monitoring panels to overlap on rendered screenshots. */
@media(min-width:851px){
 html body .workspace{
   display:grid!important;
   grid-template-columns:repeat(12,minmax(0,1fr))!important;
   grid-auto-flow:row dense!important;
   grid-auto-rows:min-content!important;
   align-content:start!important;
   align-items:start!important;
   gap:12px!important;
 }
 html body .workspace>.top{
   grid-column:1/-1!important;grid-row:auto!important;
   display:flex!important;flex-wrap:wrap!important;
   min-height:0!important;height:auto!important;
   align-items:center!important;gap:10px!important;
   margin:0!important;padding:8px 0 12px!important;
 }
 html body .workspace>#overviewStats{
   grid-column:1/-1!important;grid-row:auto!important;
   display:grid!important;grid-template-columns:repeat(4,minmax(0,1fr))!important;
   align-self:start!important;position:relative!important;
   height:auto!important;min-height:0!important;margin:0!important;
 }
 html body .workspace>#dashboardUsageCard{
   grid-column:span 7!important;grid-row:auto!important;
   position:relative!important;inset:auto!important;
   height:auto!important;min-height:0!important;margin:0!important;
 }
 html body .workspace>#panelHealthCard{
   grid-column:span 5!important;grid-row:auto!important;
   position:relative!important;inset:auto!important;
   height:auto!important;min-height:0!important;margin:0!important;
 }
 html body .workspace>#overviewStats>.card{
   position:relative!important;inset:auto!important;
   height:auto!important;min-height:94px!important;
   margin:0!important;min-width:0!important;
 }
 html body .workspace>#dashboardUsageCard .stats{
   display:grid!important;grid-template-columns:repeat(3,minmax(0,1fr))!important;
   gap:8px!important;margin:12px 0!important;
 }
 html body .workspace>#dashboardUsageCard .stats>.card{margin:0!important;min-width:0!important}
 html body .workspace>#dashboardUsageCard #usageSparkline{
   display:block!important;width:100%!important;max-width:100%!important;height:150px!important;
 }
 html body .workspace>[data-section-page]:not(#overviewStats):not(#dashboardUsageCard):not(#panelHealthCard):not(#dashboardQuickCard):not(.nav-hidden){
   grid-column:1/-1!important;grid-row:auto!important;position:relative!important;
   inset:auto!important;height:auto!important;min-height:0!important;margin:0 0 12px!important;
 }
}
@media(min-width:851px) and (max-width:1150px){
 html body .workspace>#overviewStats{grid-template-columns:repeat(2,minmax(0,1fr))!important}
 html body .workspace>#dashboardUsageCard,html body .workspace>#panelHealthCard{grid-column:1/-1!important}
}
@media(max-width:850px){
 html body .workspace{
   display:grid!important;grid-template-columns:minmax(0,1fr)!important;
   grid-auto-flow:row!important;grid-auto-rows:min-content!important;
   align-content:start!important;gap:10px!important;
 }
 html body .workspace>.top,html body .workspace>#overviewStats,
 html body .workspace>#dashboardUsageCard,html body .workspace>#panelHealthCard,
 html body .workspace>[data-section-page]:not(.nav-hidden){
   grid-column:1!important;grid-row:auto!important;
   position:relative!important;inset:auto!important;
   width:100%!important;max-width:100%!important;
   height:auto!important;min-height:0!important;margin:0 0 10px!important;
   box-sizing:border-box!important;
 }
 html body .workspace>.top{display:flex!important;flex-wrap:wrap!important;gap:8px!important}
 html body .workspace>#overviewStats{display:grid!important;grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:8px!important}
 html body .workspace>#overviewStats>.card{min-width:0!important;margin:0!important}
 html body .workspace>#dashboardUsageCard .stats{display:grid!important;grid-template-columns:repeat(3,minmax(0,1fr))!important;gap:6px!important}
 html body .workspace>#dashboardUsageCard #usageSparkline{width:100%!important;max-width:100%!important;height:120px!important}
 html body .workspace>#panelHealthCard #dashboardComponentStatus{display:grid!important;grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:7px!important}
 html body .workspace>#panelHealthCard #recentActivityList{max-height:220px!important;overflow:auto!important}
}

/* Screenshot-driven correction: keep the overview metrics in DOM order and keep the
   RTL sidebar on the right; dense auto-placement had pulled cards out of reference order. */
html body .app-shell{direction:rtl!important}
@media(min-width:851px){
 html body .app-shell{
   display:grid!important;
   grid-template-columns:minmax(0,1fr) 224px!important;
   max-width:1800px!important;
   margin-inline:auto!important;
   align-items:start!important;
 }
 html body .sidebar{
   grid-column:2!important;grid-row:1!important;
   position:sticky!important;right:0!important;left:auto!important;
   width:172px!important;height:100dvh!important;max-height:100dvh!important;
   overflow-y:auto!important;overflow-x:hidden!important;
 }
 html body .workspace{
   grid-column:1!important;grid-row:1!important;
   display:grid!important;
   grid-template-columns:repeat(12,minmax(0,1fr))!important;
   grid-auto-flow:row!important;grid-auto-rows:min-content!important;
   align-content:start!important;align-items:start!important;
   min-width:0!important;width:100%!important;max-width:none!important;
   padding:18px 22px 30px!important;gap:12px!important;
 }
 html body .workspace>.top{grid-column:1/-1!important;grid-row:1!important;min-width:0!important}
 html body .workspace>#overviewStats{grid-column:1/-1!important;grid-row:2!important;order:0!important}
 html body .workspace>#dashboardUsageCard{grid-column:1/span 7!important;grid-row:3!important}
 html body .workspace>#panelHealthCard{grid-column:8/span 5!important;grid-row:3!important}
 html body .workspace>#overviewStats,
 html body .workspace>#dashboardUsageCard,
 html body .workspace>#panelHealthCard{align-self:start!important;position:relative!important;inset:auto!important;height:auto!important}
 html body .workspace>#overviewStats{margin:0!important;grid-template-columns:repeat(4,minmax(0,1fr))!important;gap:10px!important}
 html body .workspace>#dashboardUsageCard .stats{grid-template-columns:repeat(3,minmax(0,1fr))!important}
 html body .workspace>#dashboardUsageCard #usageSparkline{height:155px!important}
 html body .workspace>#panelHealthCard #status{display:none!important}
 html body .workspace>#panelHealthCard #dashboardComponentStatus{display:grid!important;grid-template-columns:1fr!important;gap:8px!important}
 html body .workspace>#panelHealthCard #recentActivityList{max-height:190px!important;overflow:auto!important}
}
@media(min-width:851px) and (max-width:1150px){
 html body .app-shell{grid-template-columns:minmax(0,1fr) 190px!important}
 html body .sidebar{width:190px!important}
 html body .workspace{padding:14px!important}
 html body .workspace>#overviewStats{grid-template-columns:repeat(2,minmax(0,1fr))!important}
 html body .workspace>#dashboardUsageCard{grid-column:1/-1!important;grid-row:3!important}
 html body .workspace>#panelHealthCard{grid-column:1/-1!important;grid-row:4!important}
}
@media(max-width:850px){
 html body .app-shell{display:block!important;direction:rtl!important}
 html body .sidebar{position:fixed!important;right:0!important;left:auto!important;top:0!important;width:min(290px,84vw)!important;max-width:84vw!important;height:100dvh!important;transform:translateX(105%)!important;z-index:60!important}
 html body .sidebar.open{transform:translateX(0)!important}
 html body .workspace{display:grid!important;grid-template-columns:minmax(0,1fr)!important;grid-auto-flow:row!important;grid-auto-rows:min-content!important;gap:10px!important;padding:8px 12px 24px!important;width:100%!important;max-width:100%!important;box-sizing:border-box!important}
 html body .workspace>.top{grid-column:1!important;grid-row:1!important}
 html body .workspace>#overviewStats{grid-column:1!important;grid-row:2!important;display:grid!important;grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:8px!important}
 html body .workspace>#dashboardUsageCard{grid-column:1!important;grid-row:3!important}
 html body .workspace>#panelHealthCard{grid-column:1!important;grid-row:4!important}
 html body .workspace>#overviewStats>.card,html body .workspace>#dashboardUsageCard,html body .workspace>#panelHealthCard{min-width:0!important;max-width:100%!important;margin:0!important;box-sizing:border-box!important}
 html body .workspace>#dashboardUsageCard #usageSparkline{width:100%!important;max-width:100%!important;height:125px!important}
 html body .workspace>#panelHealthCard #dashboardComponentStatus{grid-template-columns:repeat(2,minmax(0,1fr))!important}
 html body .workspace>.top .tools{display:flex!important;flex-wrap:wrap!important;max-width:100%!important;gap:6px!important}
 html body .workspace>.top .tools input{width:min(100%,220px)!important;flex:1 1 140px!important}
}

/* Screenshot audit v2: use explicit named grid rows so the overview can never be painted
   underneath the resource/status cards. The approved references place navigation on the left. */
@media(min-width:851px){
 html body .app-shell{
   display:grid!important;
   grid-template-columns:172px minmax(0,1fr)!important;
   grid-template-rows:minmax(100vh,auto)!important;
   direction:ltr!important;
   align-items:stretch!important;
 }
 html body .app-shell>.sidebar{
   grid-column:1!important;grid-row:1!important;
   position:sticky!important;top:0!important;left:0!important;right:auto!important;
   width:172px!important;height:100vh!important;max-height:100vh!important;
   align-self:start!important;overflow-y:auto!important;
 }
 html body .app-shell>.workspace{
   grid-column:2!important;grid-row:1!important;direction:rtl!important;
   display:grid!important;
   grid-template-columns:repeat(12,minmax(0,1fr))!important;
   grid-template-rows:auto auto auto auto!important;
   grid-auto-flow:row!important;grid-auto-rows:min-content!important;
   align-content:start!important;align-items:start!important;
   min-width:0!important;width:100%!important;max-width:none!important;
   padding:16px 20px 28px!important;gap:12px!important;
 }
 html body .workspace>.top{
   grid-column:1/-1!important;grid-row:1!important;
   position:relative!important;inset:auto!important;transform:none!important;
   height:auto!important;min-height:0!important;margin:0!important;
 }
 html body .workspace>#overviewStats{
   grid-column:1/-1!important;grid-row:2!important;
   position:relative!important;inset:auto!important;transform:none!important;float:none!important;
   height:auto!important;min-height:0!important;margin:0!important;
   display:grid!important;grid-template-columns:repeat(4,minmax(0,1fr))!important;
   gap:10px!important;align-self:start!important;
 }
 html body .workspace>#dashboardUsageCard{
   grid-column:6/-1!important;grid-row:3!important;
   position:relative!important;inset:auto!important;transform:none!important;float:none!important;
   height:auto!important;min-height:0!important;margin:0!important;align-self:start!important;
 }
 html body .workspace>#panelHealthCard{
   grid-column:1/span 5!important;grid-row:3!important;
   position:relative!important;inset:auto!important;transform:none!important;float:none!important;
   height:auto!important;min-height:0!important;margin:0!important;align-self:start!important;
 }
 html body .workspace>#overviewStats>.card{min-width:0!important;min-height:100px!important;margin:0!important}
 html body .workspace>#dashboardUsageCard .stats{display:grid!important;grid-template-columns:repeat(3,minmax(0,1fr))!important;gap:8px!important;margin:12px 0!important}
 html body .workspace>#dashboardUsageCard .stats>.card{margin:0!important;min-width:0!important}
 html body .workspace>#dashboardUsageCard #usageSparkline{display:block!important;width:100%!important;height:150px!important}
 html body .workspace>#panelHealthCard #status{display:none!important}
 html body .workspace>#panelHealthCard #dashboardComponentStatus{display:grid!important;grid-template-columns:1fr!important;gap:8px!important}
 html body .workspace>#panelHealthCard #recentActivityList{max-height:190px!important;overflow:auto!important}
 html body .workspace>section[data-section-page]:not(#overviewStats):not(#dashboardUsageCard):not(#panelHealthCard):not(#dashboardQuickCard):not(.nav-hidden){
   grid-column:1/-1!important;grid-row:auto!important;position:relative!important;inset:auto!important;
   transform:none!important;float:none!important;height:auto!important;min-height:0!important;margin:0 0 12px!important;
 }
}
@media(min-width:851px) and (max-width:1150px){
 html body .app-shell{grid-template-columns:190px minmax(0,1fr)!important}
 html body .app-shell>.sidebar{width:190px!important}
 html body .workspace{padding:12px!important}
 html body .workspace>#overviewStats{grid-template-columns:repeat(2,minmax(0,1fr))!important}
 html body .workspace>#dashboardUsageCard{grid-column:1/-1!important;grid-row:3!important}
 html body .workspace>#panelHealthCard{grid-column:1/-1!important;grid-row:4!important}
}
@media(max-width:850px){
 html body .app-shell{display:block!important;direction:ltr!important}
 html body .app-shell>.sidebar{position:fixed!important;top:0!important;right:0!important;left:auto!important;width:min(290px,84vw)!important;max-width:84vw!important;height:100dvh!important;transform:translateX(105%)!important;z-index:60!important}
 html body .app-shell>.sidebar.open{transform:translateX(0)!important}
 html body .app-shell>.workspace{display:grid!important;grid-template-columns:minmax(0,1fr)!important;grid-template-rows:auto auto auto auto!important;grid-auto-flow:row!important;grid-auto-rows:min-content!important;gap:10px!important;padding:8px 12px 24px!important;width:100%!important;max-width:100%!important;box-sizing:border-box!important;direction:rtl!important}
 html body .workspace>.top{grid-column:1!important;grid-row:1!important}
 html body .workspace>#overviewStats{grid-column:1!important;grid-row:2!important;display:grid!important;grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:8px!important}
 html body .workspace>#dashboardUsageCard{grid-column:1!important;grid-row:3!important}
 html body .workspace>#panelHealthCard{grid-column:1!important;grid-row:4!important}
 html body .workspace>#overviewStats,html body .workspace>#dashboardUsageCard,html body .workspace>#panelHealthCard{position:relative!important;inset:auto!important;transform:none!important;width:100%!important;max-width:100%!important;height:auto!important;min-height:0!important;margin:0 0 10px!important;box-sizing:border-box!important}
 html body .workspace>#dashboardUsageCard #usageSparkline{width:100%!important;max-width:100%!important;height:125px!important}
 html body .workspace>#panelHealthCard #dashboardComponentStatus{grid-template-columns:repeat(2,minmax(0,1fr))!important}
 html body .workspace>section[data-section-page]:not(#overviewStats):not(#dashboardUsageCard):not(#panelHealthCard):not(#dashboardQuickCard):not(.nav-hidden){grid-column:1!important;grid-row:auto!important;position:relative!important;inset:auto!important;transform:none!important;width:100%!important;max-width:100%!important;height:auto!important;min-height:0!important;margin:0 0 10px!important}
}

/* Reference fidelity pass: compact left rail and tighter glass dashboard surfaces. */
@media(min-width:1151px){
 html body main.app-shell{grid-template-columns:172px minmax(0,1fr)!important}
 html body main.app-shell>aside.sidebar{width:172px!important;padding:14px 8px!important}
 html body main.app-shell>.workspace{padding:14px 18px 28px!important;gap:10px!important}
 html body main.app-shell>.workspace>#overviewStats{gap:8px!important}
 html body main.app-shell>.workspace>#overviewStats>.card{padding:12px 10px!important}
}
html body main.app-shell>aside.sidebar .side-brand{gap:7px!important;justify-content:center!important}
html body main.app-shell>aside.sidebar .brand-name{font-size:11px!important;letter-spacing:.08em!important}
html body main.app-shell>aside.sidebar .side-caption{font-size:10px!important;margin:8px 0 6px!important}
html body main.app-shell>aside.sidebar .side-nav{gap:4px!important}
html body main.app-shell>aside.sidebar .nav-item{min-height:34px!important;padding:8px 7px!important;gap:7px!important;font-size:11px!important;line-height:1.35!important;border-radius:9px!important}
html body main.app-shell>aside.sidebar .nav-icon{width:18px!important;min-width:18px!important;font-size:14px!important}
html body main.app-shell>aside.sidebar .side-footer{font-size:10px!important}
html body main.app-shell>.workspace>.top{padding-bottom:10px!important}
html body main.app-shell>.workspace>.top .tools{gap:6px!important}
html body main.app-shell>.workspace>.top .tools button,
html body main.app-shell>.workspace>.top .tools input{min-height:34px!important;padding:7px 10px!important;font-size:11px!important}
html body main.app-shell>.workspace .card{border-color:rgba(190,198,211,.18)!important;background:linear-gradient(145deg,rgba(24,26,31,.88),rgba(8,9,12,.94))!important;box-shadow:inset 0 1px 0 rgba(255,255,255,.035),0 12px 30px rgba(0,0,0,.2)!important}
html body main.app-shell>.workspace #overviewStats .num{font-size:clamp(20px,1.8vw,30px)!important}
/* Last-cascade layout fix: the older repair layer set .workspace to display:block!important,
   which silently disabled all grid-row assignments and stacked dashboard cards at y=173. */
@media(min-width:851px){
 html body main.app-shell{display:grid!important;grid-template-columns:172px minmax(0,1fr)!important;grid-template-rows:minmax(100vh,auto)!important;direction:ltr!important;align-items:stretch!important}
 html body main.app-shell>aside.sidebar{grid-column:1!important;grid-row:1!important;position:sticky!important;top:0!important;left:0!important;right:auto!important;width:172px!important;height:100vh!important;max-height:100vh!important;transform:none!important;align-self:start!important}
 html body main.app-shell>.workspace{grid-column:2!important;grid-row:1!important;direction:rtl!important;display:grid!important;grid-template-columns:repeat(12,minmax(0,1fr))!important;grid-template-rows:auto auto auto!important;grid-auto-flow:row!important;grid-auto-rows:min-content!important;align-content:start!important;align-items:start!important;min-width:0!important;width:100%!important;max-width:none!important;margin:0!important;padding:18px 22px 30px!important;gap:12px!important}
 html body main.app-shell>.workspace>.top{grid-column:1/-1!important;grid-row:1!important;position:relative!important;inset:auto!important;height:auto!important;margin:0!important;min-width:0!important}
 html body main.app-shell>.workspace>#overviewStats{grid-column:1/-1!important;grid-row:2!important;position:relative!important;inset:auto!important;transform:none!important;float:none!important;width:100%!important;height:auto!important;min-height:0!important;margin:0!important;display:grid!important;grid-template-columns:repeat(4,minmax(0,1fr))!important;gap:10px!important;align-self:start!important}
 html body main.app-shell>.workspace>#dashboardUsageCard{grid-column:6/-1!important;grid-row:3!important;position:relative!important;inset:auto!important;transform:none!important;float:none!important;width:100%!important;max-width:100%!important;height:auto!important;min-height:0!important;margin:0!important;align-self:start!important}
 html body main.app-shell>.workspace>#panelHealthCard{grid-column:1/span 5!important;grid-row:3!important;position:relative!important;inset:auto!important;transform:none!important;float:none!important;width:100%!important;max-width:100%!important;height:auto!important;min-height:0!important;margin:0!important;align-self:start!important}
 html body main.app-shell>.workspace>#overviewStats>.card{min-width:0!important;margin:0!important}
 html body main.app-shell>.workspace>#dashboardUsageCard>.stats{display:grid!important;grid-template-columns:repeat(3,minmax(0,1fr))!important;gap:8px!important}
 html body main.app-shell>.workspace>#dashboardUsageCard #usageSparkline{display:block!important;width:100%!important;height:150px!important}
 html body main.app-shell>.workspace>#panelHealthCard #status{display:none!important}
 html body main.app-shell>.workspace>#panelHealthCard #dashboardComponentStatus{display:grid!important;grid-template-columns:1fr!important;gap:8px!important}
 html body main.app-shell>.workspace>section[data-section-page]:not(#overviewStats):not(#dashboardUsageCard):not(#panelHealthCard):not(#dashboardQuickCard):not(.nav-hidden){grid-column:1/-1!important;grid-row:auto!important;position:relative!important;inset:auto!important;transform:none!important;float:none!important;height:auto!important;min-height:0!important;margin:0 0 12px!important}
}
@media(min-width:851px) and (max-width:1150px){
 html body main.app-shell{grid-template-columns:190px minmax(0,1fr)!important}
 html body main.app-shell>aside.sidebar{width:190px!important}
 html body main.app-shell>.workspace{padding:12px!important}
 html body main.app-shell>.workspace>#overviewStats{grid-template-columns:repeat(2,minmax(0,1fr))!important}
 html body main.app-shell>.workspace>#dashboardUsageCard{grid-column:1/-1!important;grid-row:3!important}
 html body main.app-shell>.workspace>#panelHealthCard{grid-column:1/-1!important;grid-row:4!important}
}
@media(max-width:850px){
 html body main.app-shell{display:block!important;direction:ltr!important}
 html body main.app-shell>aside.sidebar{position:fixed!important;top:0!important;right:0!important;left:auto!important;width:min(290px,84vw)!important;max-width:84vw!important;height:100dvh!important;transform:translateX(105%)!important;z-index:10011!important}
 html body main.app-shell>aside.sidebar.open{transform:translateX(0)!important}
 html body main.app-shell>.workspace{display:grid!important;grid-template-columns:minmax(0,1fr)!important;grid-template-rows:auto auto auto auto!important;grid-auto-flow:row!important;grid-auto-rows:min-content!important;gap:10px!important;padding:8px 12px 24px!important;width:100%!important;max-width:100%!important;box-sizing:border-box!important;direction:rtl!important}
 html body main.app-shell>.workspace>.top{grid-column:1!important;grid-row:1!important}
 html body main.app-shell>.workspace>#overviewStats{grid-column:1!important;grid-row:2!important;display:grid!important;grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:8px!important}
 html body main.app-shell>.workspace>#dashboardUsageCard{grid-column:1!important;grid-row:3!important}
 html body main.app-shell>.workspace>#panelHealthCard{grid-column:1!important;grid-row:4!important}
 html body main.app-shell>.workspace>#overviewStats,html body main.app-shell>.workspace>#dashboardUsageCard,html body main.app-shell>.workspace>#panelHealthCard{position:relative!important;inset:auto!important;transform:none!important;width:100%!important;max-width:100%!important;height:auto!important;min-height:0!important;margin:0 0 10px!important;box-sizing:border-box!important}
 html body main.app-shell>.workspace>#dashboardUsageCard #usageSparkline{width:100%!important;max-width:100%!important;height:125px!important}
 html body main.app-shell>.workspace>#panelHealthCard #dashboardComponentStatus{grid-template-columns:repeat(2,minmax(0,1fr))!important}
 html body main.app-shell>.workspace>section[data-section-page]:not(#overviewStats):not(#dashboardUsageCard):not(#panelHealthCard):not(#dashboardQuickCard):not(.nav-hidden){grid-column:1!important;grid-row:auto!important;position:relative!important;inset:auto!important;transform:none!important;width:100%!important;max-width:100%!important;height:auto!important;min-height:0!important;margin:0 0 10px!important}
}

/* Final reference polish: black starfield, restrained orbit, readable Persian navigation. */
html body:has(.login-layout){background:#050506!important;background-image:radial-gradient(1px 1px at 8% 17%,rgba(230,232,237,.62) 98%,transparent),radial-gradient(1px 1px at 21% 72%,rgba(230,232,237,.4) 98%,transparent),radial-gradient(1px 1px at 36% 33%,rgba(230,232,237,.48) 98%,transparent),radial-gradient(1px 1px at 57% 16%,rgba(230,232,237,.38) 98%,transparent),radial-gradient(1px 1px at 73% 62%,rgba(230,232,237,.42) 98%,transparent),radial-gradient(1px 1px at 89% 29%,rgba(230,232,237,.52) 98%,transparent),radial-gradient(1px 1px at 94% 83%,rgba(230,232,237,.35) 98%,transparent),linear-gradient(128deg,transparent 0 24%,rgba(190,193,200,.035) 24.08%,transparent 24.22% 68%,rgba(190,193,200,.025) 68.08%,transparent 68.24%),#050506!important;background-size:100% 100%!important}
html body:has(.login-layout) .login-visual .visual-orbit{top:15%!important;left:7%!important;width:min(39vw,440px)!important;opacity:.17!important;border-color:rgba(190,193,200,.16)!important;box-shadow:0 0 80px rgba(190,193,200,.025),inset 0 0 55px rgba(190,193,200,.02)!important}
html body:has(.login-layout) .login-visual .visual-orbit:before{border-color:rgba(205,207,213,.17)!important}
html body:has(.login-layout) .login-visual .visual-orbit:after{border-color:rgba(218,220,225,.24)!important}
html body main.app-shell>aside.sidebar .nav-item{font-size:12px!important;line-height:1.45!important;padding:8px 9px!important;gap:7px!important}
html body main.app-shell>aside.sidebar .nav-icon{width:21px!important;flex:0 0 21px!important;font-size:14px!important}
html body main.app-shell>.workspace>.top .tools button,
html body main.app-shell>.workspace>.top .tools input{font-size:12px!important}
@media(max-width:700px){html body:has(.login-layout) .login-visual .visual-orbit{top:4%!important;left:-10%!important;width:72vw!important;opacity:.13!important}}

/* Compact desktop dashboard: match the reference's dense, three-zone overview. */
@media(min-width:1151px){
 html body main.app-shell>.workspace{gap:12px!important}
 html body main.app-shell>.workspace>#overviewStats>.card{padding:15px!important;min-height:96px!important}
 html body main.app-shell>.workspace>#dashboardUsageCard{padding:15px!important}
 html body main.app-shell>.workspace>#dashboardUsageCard #usageSparkline{height:88px!important;max-height:88px!important;margin-top:3px!important}
 html body main.app-shell>.workspace>#dashboardUsageCard>.stats{gap:8px!important}
 html body main.app-shell>.workspace>#dashboardUsageCard>.stats>.card{padding:10px!important}
 html body main.app-shell>.workspace>#panelHealthCard{padding:15px!important}
 html body main.app-shell>.workspace>#panelHealthCard #dashboardComponentStatus{gap:7px!important}
 html body main.app-shell>.workspace>#panelHealthCard #dashboardComponentStatus>*{min-height:36px!important;padding:7px 10px!important}
 html body main.app-shell>.workspace>#panelHealthCard .event-item,
 html body main.app-shell>.workspace>#panelHealthCard .activity-item{padding:9px 11px!important;margin-top:7px!important}
}

/* Compact protocol choices and event rows without reducing tap targets on mobile. */
@media(min-width:1151px){
 html body main.app-shell>.workspace>#createServiceCard #clientProfileChoices.profile-grid{grid-template-columns:repeat(3,minmax(0,1fr))!important;gap:9px!important}
 html body main.app-shell>.workspace>#createServiceCard #clientProfileChoices .profile-setting{min-height:46px!important;padding:10px 12px!important;border-radius:13px!important}
 html body main.app-shell>.workspace>#panelHealthCard #recentActivityList>div{padding:9px 11px!important;margin:6px 0 0!important;min-height:0!important;border-radius:12px!important}
 html body main.app-shell>.workspace>#panelHealthCard .section-title[style*="margin-top"]{margin-top:12px!important}
}
@media(min-width:851px) and (max-width:1150px){
 html body main.app-shell>.workspace>#createServiceCard #clientProfileChoices.profile-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}
}
@media(max-width:700px){
 html body main.app-shell>.workspace>#createServiceCard #clientProfileChoices.profile-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:8px!important}
 html body main.app-shell>.workspace>#createServiceCard #clientProfileChoices .profile-setting{min-height:44px!important;padding:9px!important}
}

/* Three-card dashboard row mirrors the approved overview composition. */
@media(min-width:1151px){
 html body main.app-shell>.workspace>#dashboardUsageCard:not(.nav-hidden){grid-column:span 5!important;min-width:0!important}
 html body main.app-shell>.workspace>#panelHealthCard:not(.nav-hidden){grid-column:span 3!important;min-width:0!important}
 html body main.app-shell>.workspace>#dashboardQuickCard:not(.nav-hidden){grid-column:span 4!important;min-width:0!important}
 html body main.app-shell>.workspace>#dashboardQuickCard{padding:15px!important;min-height:320px!important}
 html body main.app-shell>.workspace>#dashboardQuickCard .quick-detail-list{display:grid!important;gap:8px!important;margin-top:10px!important}
 html body main.app-shell>.workspace>#dashboardQuickCard .quick-detail-row{display:flex!important;align-items:center!important;justify-content:space-between!important;gap:12px!important;padding:10px 11px!important;min-width:0!important;border:1px solid var(--ab-line)!important;border-radius:12px!important;background:rgba(255,255,255,.018)!important}
 html body main.app-shell>.workspace>#dashboardQuickCard .quick-detail-row strong{font-size:12px!important;font-weight:600!important;text-align:left!important}
 html body main.app-shell>.workspace>#dashboardQuickCard #recentActivityList{max-height:245px!important;overflow:auto!important;padding-inline-end:2px!important}
 html body:has(.login-layout) .login-visual .visual-orbit{top:18%!important;left:9%!important;transform:none!important;width:min(31vw,400px)!important;opacity:.22!important}
}
@media(min-width:851px) and (max-width:1150px){
 html body main.app-shell>.workspace>#dashboardUsageCard:not(.nav-hidden){grid-column:span 7!important}
 html body main.app-shell>.workspace>#panelHealthCard:not(.nav-hidden){grid-column:span 5!important}
 html body main.app-shell>.workspace>#dashboardQuickCard:not(.nav-hidden){grid-column:1/-1!important}
}
@media(max-width:850px){
 html body main.app-shell>.workspace>#dashboardQuickCard:not(.nav-hidden){grid-column:1/-1!important}
 html body:has(.login-layout) .login-visual .visual-orbit{transform:translateX(-50%)!important}
}

/* Reference layout: explicit RTL grid lines prevent legacy auto-placement rules
   from pushing the quick-details card onto a second row. */
@media(min-width:1151px){
 html body main.app-shell>.workspace>#dashboardQuickCard:not(.nav-hidden){
   order:0!important;grid-column:1 / span 4!important;grid-row:3!important;
   min-width:0!important;min-height:0!important;width:auto!important;
 }
 html body main.app-shell>.workspace>#panelHealthCard:not(.nav-hidden){
   order:0!important;grid-column:5 / span 3!important;grid-row:3!important;
   min-width:0!important;width:auto!important;
 }
 html body main.app-shell>.workspace>#dashboardUsageCard:not(.nav-hidden){
   order:0!important;grid-column:8 / span 5!important;grid-row:3!important;
   min-width:0!important;width:auto!important;
 }
 html body main.app-shell>.workspace>#dashboardQuickCard #recentActivityList{max-height:205px!important}
 html body main.app-shell>.workspace>#dashboardQuickCard .quick-detail-row strong{max-width:68%!important;overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important}
}
/* Keep sidebar navigation and creator links in normal flow; never let the footer overlap the last menu item. */
html body main.app-shell>aside.sidebar{
 display:flex!important;flex-direction:column!important;align-items:stretch!important;
 overflow-y:auto!important;overflow-x:hidden!important;overscroll-behavior:contain!important;
 scrollbar-gutter:stable!important;box-sizing:border-box!important;
}
html body main.app-shell>aside.sidebar>.side-nav{
 display:grid!important;grid-template-columns:minmax(0,1fr)!important;
 gap:4px!important;flex:0 0 auto!important;position:relative!important;
}
html body main.app-shell>aside.sidebar>.side-nav>.nav-item{
 position:relative!important;flex:0 0 auto!important;box-sizing:border-box!important;
 margin:0!important;transform:none!important;min-width:0!important;
}
html body main.app-shell>aside.sidebar>.side-caption:nth-last-child(2){
 flex:0 0 auto!important;margin:14px 0 4px!important;padding-top:10px!important;
 border-top:1px solid var(--ab-line)!important;
}
html body main.app-shell>aside.sidebar>.abyss-utility-links{
 position:relative!important;inset:auto!important;flex:0 0 auto!important;
 margin:10px 0 12px!important;padding-bottom:6px!important;
}
@media(max-width:850px){
 html body main.app-shell>aside.sidebar{
   height:100dvh!important;max-height:100dvh!important;min-height:0!important;
   padding-top:max(12px,env(safe-area-inset-top))!important;
   padding-bottom:max(12px,env(safe-area-inset-bottom))!important;
   overflow:hidden!important;
 }
 html body main.app-shell>aside.sidebar>.side-nav{
   flex:1 1 auto!important;min-height:0!important;overflow-y:auto!important;
   overscroll-behavior:contain!important;scrollbar-width:thin!important;
   padding-bottom:8px!important;
 }
 html body main.app-shell>aside.sidebar>.side-caption:nth-last-child(2){flex:0 0 auto!important}
 html body main.app-shell>aside.sidebar>.abyss-utility-links{
   flex:0 0 auto!important;gap:6px!important;margin-top:8px!important;
   padding-bottom:0!important;
 }
 html body main.app-shell>aside.sidebar>.abyss-utility-links a{max-width:100%!important}
}
/* Keep mobile controls usable without turning each toolbar action into a full-width row. */
@media(max-width:850px){
 html body main.app-shell>.workspace>.top{display:grid!important;grid-template-columns:minmax(0,1fr)!important;gap:8px!important;min-width:0!important}
 html body main.app-shell>.workspace>.top>.mint{display:none!important}
 html body main.app-shell>.workspace>.top>.tools{display:grid!important;grid-template-columns:repeat(4,minmax(0,1fr))!important;align-items:center!important;gap:6px!important;width:100%!important;min-width:0!important}
 html body main.app-shell>.workspace>.top>.tools>*{min-width:0!important;max-width:100%!important;box-sizing:border-box!important;font-size:11px!important;padding:8px 4px!important;white-space:normal!important;overflow-wrap:anywhere!important;line-height:1.25!important;min-height:32px!important}
 html body main.app-shell>.workspace>.top>.tools>.top-tools-search{grid-column:1/-1!important;width:100%!important}
 html body main.app-shell>.workspace>.top>.tools>.account-badge{grid-column:span 2!important;justify-content:center!important}
 html body main.app-shell>.workspace>.top>.tools>button{flex:none!important}
 html body main.app-shell>.workspace>.top>.tools>button[data-i18n="changePassword"],
 html body main.app-shell>.workspace>.top>.tools>button[data-i18n="refresh"],
 html body main.app-shell>.workspace>.top>.tools>button[data-i18n="logout"]{padding-inline:2px!important}
}
@media(min-width:851px) and (max-width:1150px){
 /* Tablet: put chart and service health on one row; details occupy the next row. */
 html body main.app-shell>.workspace>#dashboardUsageCard:not(.nav-hidden){
   order:0!important;grid-column:6 / span 7!important;grid-row:3!important;
   width:auto!important;min-width:0!important;
 }
 html body main.app-shell>.workspace>#panelHealthCard:not(.nav-hidden){
   order:0!important;grid-column:1 / span 5!important;grid-row:3!important;
   width:auto!important;min-width:0!important;
 }
 html body main.app-shell>.workspace>#dashboardQuickCard:not(.nav-hidden){
   order:0!important;grid-column:1 / -1!important;grid-row:4!important;
   width:auto!important;min-width:0!important;
 }
}

/* Keep the toolbar's visual order aligned with the reference: search at left, status/actions at right. */
@media(min-width:851px){
 html body main.app-shell>.workspace>.top>.tools{direction:ltr!important}
 html body main.app-shell>.workspace>.top>.tools>*{direction:rtl!important}
 html body main.app-shell>.workspace>.top>.section-heading{justify-self:end!important;text-align:left!important}
 html body main.app-shell>.workspace>#overviewStats>.card:has(#dashboardTraffic){grid-column:3!important;grid-row:1!important}
 html body main.app-shell>.workspace>#overviewStats>.card:has(#xray){grid-column:4!important;grid-row:1!important}
}
/* Reference-matching pass: simplify the rail and compact the header/cards without removing controls. */
@media(min-width:851px){
 html body main.app-shell>.workspace>.top{display:grid!important;grid-template-columns:minmax(0,1fr)!important;grid-template-rows:auto auto!important;align-items:center!important;gap:7px!important;padding:4px 0 8px!important}
 html body main.app-shell>.workspace>.top>.abyss-brand-row,html body main.app-shell>.workspace>.top>.mint{display:none!important}
 html body main.app-shell>.workspace>.top>.tools{grid-row:1!important;grid-column:1!important;display:flex!important;flex-wrap:nowrap!important;justify-content:flex-start!important;align-items:center!important;gap:7px!important;width:100%!important;min-width:0!important;overflow-x:auto!important;padding:2px 0 5px!important;scrollbar-width:thin!important}
 html body main.app-shell>.workspace>.top>.tools>*{flex:0 0 auto!important;white-space:nowrap!important}
 html body main.app-shell>.workspace>.top>.tools>.top-tools-search{width:190px!important;flex:0 1 190px!important}
 html body main.app-shell>.workspace>.top>.section-heading{grid-row:2!important;grid-column:1!important;justify-self:start!important;align-self:center!important;font-size:18px!important;font-weight:700!important;margin:0!important;padding:4px 0!important}
 html body main.app-shell>aside.sidebar .side-nav>.nav-item{background:transparent!important;border-color:transparent!important;box-shadow:none!important;border-radius:9px!important;min-height:35px!important;padding:7px 9px!important;transition:background .16s ease,border-color .16s ease!important}
 html body main.app-shell>aside.sidebar .side-nav>.nav-item:hover{background:rgba(255,255,255,.045)!important;border-color:rgba(255,255,255,.06)!important}
 html body main.app-shell>aside.sidebar .side-nav>.nav-item.active{background:linear-gradient(90deg,rgba(230,232,237,.105),rgba(230,232,237,.035))!important;border-color:rgba(230,232,237,.13)!important;box-shadow:inset -2px 0 0 rgba(225,227,232,.78)!important}
 html body main.app-shell>.workspace>#overviewStats{direction:ltr!important;grid-template-columns:repeat(4,minmax(0,1fr))!important}
 html body main.app-shell>.workspace>#overviewStats>.card{direction:rtl!important;text-align:right!important}
 html body main.app-shell>.workspace>#dashboardUsageCard{min-height:0!important}
 html body main.app-shell>.workspace>#dashboardUsageCard>.stats{margin:8px 0!important}
 html body main.app-shell>.workspace>#dashboardUsageCard>.stats>.card{padding:8px!important;min-height:66px!important}
 html body main.app-shell>.workspace>#dashboardUsageCard>.stats>.card .num{font-size:21px!important}
 html body main.app-shell>.workspace>#dashboardUsageCard #usageSparkline{height:112px!important;max-height:112px!important;margin-top:3px!important}
 html body main.app-shell>.workspace>#dashboardUsageCard #chartLegend{margin-top:4px!important}
 html body main.app-shell>.workspace>#dashboardUsageCard #chartNote{display:none!important}
 html body main.app-shell>.workspace>#panelHealthCard #dashboardComponentStatus>*{min-height:31px!important;padding:5px 9px!important}
 html body main.app-shell>.workspace>#dashboardQuickCard{min-height:0!important}
 html body main.app-shell>.workspace>#dashboardQuickCard .quick-detail-row{padding:7px 9px!important}
 html body main.app-shell>.workspace>#dashboardQuickCard #recentActivityList{max-height:165px!important}
}
html body main.app-shell{background-image:radial-gradient(1px 1px at 7% 13%,rgba(235,237,242,.32) 98%,transparent),radial-gradient(1px 1px at 19% 64%,rgba(235,237,242,.22) 98%,transparent),radial-gradient(1px 1px at 32% 27%,rgba(235,237,242,.25) 98%,transparent),radial-gradient(1px 1px at 48% 79%,rgba(235,237,242,.18) 98%,transparent),radial-gradient(1px 1px at 67% 18%,rgba(235,237,242,.24) 98%,transparent),radial-gradient(1px 1px at 81% 53%,rgba(235,237,242,.22) 98%,transparent),radial-gradient(1px 1px at 93% 33%,rgba(235,237,242,.27) 98%,transparent)!important;background-size:100% 100%!important;background-repeat:no-repeat!important}
@media(max-width:850px){
 html body main.app-shell>.workspace>.top{display:grid!important;grid-template-columns:minmax(0,1fr)!important;grid-template-rows:auto auto!important;gap:7px!important;padding:0 0 8px!important}
 html body main.app-shell>.workspace>.top>.abyss-brand-row,html body main.app-shell>.workspace>.top>.mint{display:none!important}
 html body main.app-shell>.workspace>.top>.section-heading{grid-row:1!important;grid-column:1!important;justify-self:start!important;font-size:18px!important;margin:0!important;padding:3px 0!important}
 html body main.app-shell>.workspace>.top>.tools{grid-row:2!important;grid-column:1!important;display:flex!important;flex-wrap:nowrap!important;overflow-x:auto!important;overflow-y:hidden!important;gap:6px!important;width:100%!important;padding:2px 0 7px!important;scrollbar-width:none!important}
 html body main.app-shell>.workspace>.top>.tools::-webkit-scrollbar{display:none!important}
 html body main.app-shell>.workspace>.top>.tools>*{flex:0 0 auto!important;min-width:36px!important;max-width:none!important;width:auto!important;white-space:nowrap!important;overflow-wrap:normal!important;padding:8px 10px!important;min-height:38px!important;font-size:11px!important}
 html body main.app-shell>.workspace>.top>.tools>.top-tools-search{flex:0 0 145px!important;width:145px!important}
 html body main.app-shell>.workspace>.top>.tools>button[data-i18n="refresh"]{display:none!important}
 html body main.app-shell>.workspace>.top>.tools>.account-badge{flex:0 0 auto!important;grid-column:auto!important}
 html body main.app-shell>.workspace>#overviewStats{direction:ltr!important}
 html body main.app-shell>.workspace>#overviewStats>.card{direction:rtl!important;text-align:right!important}
 html body main.app-shell>aside.sidebar .side-nav>.nav-item{background:transparent!important;border-color:transparent!important;box-shadow:none!important}
 html body main.app-shell>aside.sidebar .side-nav>.nav-item.active{background:rgba(235,237,242,.09)!important;border-color:rgba(235,237,242,.12)!important}
}


@media(min-width:851px){html body main.app-shell>.workspace>.top>.section-heading{justify-self:end!important;text-align:left!important}}

@media(max-width:850px){
 html body main.app-shell>.workspace>.top{grid-template-rows:auto auto auto!important}
 html body main.app-shell>.workspace>.top>.abyss-brand-row{
   display:flex!important;grid-row:1!important;grid-column:1!important;justify-self:center!important;
   align-items:center!important;gap:6px!important;margin:0 auto 2px!important;
   font-size:10px!important;letter-spacing:.12em!important;max-width:100%!important;
 }
 html body main.app-shell>.workspace>.top>.abyss-brand-row .abyss-logo-mark{width:23px!important;height:23px!important;flex:0 0 23px!important}
 html body main.app-shell>.workspace>.top>.abyss-brand-row .brand-name{font-size:10px!important;line-height:1.2!important}
 html body main.app-shell>.workspace>.top>.abyss-brand-row .brand-name small{font-size:8px!important}
 html body main.app-shell>.workspace>.top>.section-heading{grid-row:2!important}
 html body main.app-shell>.workspace>.top>.tools{grid-row:3!important}
}

/* Restore the wordmark beneath the eclipse, as shown in the supplied login reference. */
html body:has(.login-layout) .login-visual .visual-eyebrow{
 display:block!important;position:absolute!important;z-index:2!important;
 top:calc(18% + min(31vw,400px) + 12px)!important;left:9%!important;
 width:min(31vw,400px)!important;text-align:center!important;
 color:rgba(238,239,242,.92)!important;font-size:23px!important;
 font-weight:500!important;letter-spacing:.22em!important;line-height:1.5!important;
}
html body:has(.login-layout) .login-visual h2{
 display:block!important;position:absolute!important;z-index:2!important;
 top:calc(18% + min(31vw,400px) + 47px)!important;left:9%!important;
 width:min(31vw,400px)!important;text-align:center!important;
 color:rgba(211,213,219,.76)!important;font-size:10px!important;
 font-weight:500!important;letter-spacing:.32em!important;line-height:1.5!important;margin:0!important;
}
html body:has(.login-layout) .login-visual p{display:none!important}
html body:has(.login-layout){
 background-color:#030304!important;
 background-image:
 radial-gradient(1px 1px at 4% 12%,rgba(237,239,244,.62) 98%,transparent),
 radial-gradient(1px 1px at 9% 69%,rgba(237,239,244,.38) 98%,transparent),
 radial-gradient(1px 1px at 16% 28%,rgba(237,239,244,.48) 98%,transparent),
 radial-gradient(1px 1px at 22% 84%,rgba(237,239,244,.3) 98%,transparent),
 radial-gradient(1px 1px at 29% 11%,rgba(237,239,244,.42) 98%,transparent),
 radial-gradient(1px 1px at 37% 57%,rgba(237,239,244,.34) 98%,transparent),
 radial-gradient(1px 1px at 44% 23%,rgba(237,239,244,.32) 98%,transparent),
 radial-gradient(1px 1px at 51% 91%,rgba(237,239,244,.3) 98%,transparent),
 radial-gradient(1px 1px at 63% 13%,rgba(237,239,244,.48) 98%,transparent),
 radial-gradient(1px 1px at 72% 73%,rgba(237,239,244,.36) 98%,transparent),
 radial-gradient(1px 1px at 82% 36%,rgba(237,239,244,.4) 98%,transparent),
 radial-gradient(1px 1px at 94% 18%,rgba(237,239,244,.5) 98%,transparent),
 radial-gradient(1px 1px at 96% 86%,rgba(237,239,244,.3) 98%,transparent),
 linear-gradient(128deg,transparent 0 24%,rgba(190,193,200,.035) 24.08%,transparent 24.22% 68%,rgba(190,193,200,.025) 68.08%,transparent 68.24%),#030304!important;
 background-size:100% 100%!important;background-repeat:no-repeat!important;
}
@media(max-width:850px){
 html body:has(.login-layout) .login-visual .visual-eyebrow,
 html body:has(.login-layout) .login-visual h2{display:none!important}
}

html body main.app-shell>aside.sidebar .nav-icon{display:inline-flex!important;align-items:center!important;justify-content:center!important;line-height:1!important;color:rgba(222,224,230,.78)!important}
html body main.app-shell>aside.sidebar .nav-icon svg{display:block!important;width:17px!important;height:17px!important;stroke:currentColor!important;fill:none!important;stroke-width:1.55!important;stroke-linecap:round!important;stroke-linejoin:round!important;flex:0 0 17px!important}

/* Tighten the login eclipse scale and keep the form itself free of a duplicate wordmark. */
html body:has(.login-layout) .login-visual .visual-orbit{
 top:12%!important;left:9%!important;width:min(20vw,280px)!important;
 opacity:.3!important;filter:drop-shadow(0 0 22px rgba(220,222,230,.10))!important;
}
html body:has(.login-layout) .login-visual .visual-eyebrow{
 top:calc(12% + min(20vw,280px) + 8px)!important;
 left:9%!important;width:min(20vw,280px)!important;
 font-size:21px!important;letter-spacing:.15em!important;
}
html body:has(.login-layout) .login-visual h2{
 top:calc(12% + min(20vw,280px) + 39px)!important;
 left:9%!important;width:min(20vw,280px)!important;
}
html body .login-layout>.card .login-brand{display:none!important}
@media(max-width:850px){
 html body:has(.login-layout) .login-visual .visual-orbit{width:72vw!important;top:4%!important;left:14%!important}
}

/* Reference user-management split view: compact table plus persistent detail inspector. */
.clients-layout{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(250px,.8fr);gap:12px;align-items:start;direction:ltr}
.clients-table-wrap,.client-details-panel{direction:rtl;min-width:0}
.clients-table-scroll{width:100%;overflow:auto;border:1px solid var(--ab-line);border-radius:15px;background:rgba(4,4,5,.28)}
.clients-table{width:100%;border-collapse:separate;border-spacing:0;min-width:620px;font-size:12px}
.clients-table th{padding:11px 10px;color:var(--ab-muted);font-size:10px;font-weight:600;white-space:nowrap;text-align:right;border-bottom:1px solid var(--ab-line);background:rgba(255,255,255,.025)}
.clients-table td{padding:10px;border-bottom:1px solid rgba(180,183,191,.1);vertical-align:middle}
.clients-table tbody tr{cursor:pointer;transition:background .15s ease}
.clients-table tbody tr:hover{background:rgba(255,255,255,.035)}
.clients-table tbody tr.selected{background:rgba(220,222,228,.07);box-shadow:inset -2px 0 0 rgba(226,228,233,.65)}
.clients-table tbody tr:last-child td{border-bottom:0}
.clients-table td small{display:block;margin-top:4px;color:var(--ab-muted);font-size:10px;direction:ltr;text-align:right}
.client-table-name{font-weight:700;overflow-wrap:anywhere}
.client-status{display:inline-flex;align-items:center;gap:5px;border:1px solid var(--ab-line);border-radius:999px;padding:4px 8px;font-size:10px;white-space:nowrap}
.client-status:before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.client-status.good{color:#70d6a0;border-color:rgba(112,214,160,.22)}
.client-status.paused{color:#c7a2a2;border-color:rgba(199,162,162,.22)}
.clients-table .actions{display:flex;gap:4px;flex-wrap:nowrap;min-width:max-content}
.clients-table .actions button{min-width:30px;width:30px;height:30px;padding:0!important;display:grid;place-items:center;font-size:11px}
.client-details-panel{border:1px solid var(--ab-line);border-radius:16px;padding:14px;background:linear-gradient(145deg,rgba(20,20,22,.72),rgba(7,7,8,.78));box-shadow:inset 0 1px rgba(255,255,255,.025)}
.client-detail-head{display:flex;align-items:center;gap:9px;min-width:0;padding-bottom:13px;border-bottom:1px solid var(--ab-line)}
.client-detail-head>div:nth-child(2){min-width:0;flex:1;overflow-wrap:anywhere}
.client-detail-avatar{width:40px;height:40px;flex:0 0 40px;border:1px solid var(--ab-line);border-radius:50%;display:grid;place-items:center;background:rgba(255,255,255,.04);font-size:16px;font-weight:700}
.client-detail-list{display:grid;gap:0;margin-top:5px}
.client-detail-list>div{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;padding:10px 0;border-bottom:1px solid rgba(180,183,191,.1);font-size:11px}
.client-detail-list>div span{color:var(--ab-muted);flex:0 0 auto}
.client-detail-list>div b{max-width:65%;text-align:left;overflow-wrap:anywhere}
.client-detail-actions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;margin-top:13px}
.client-detail-actions button{min-width:0;padding:9px 7px!important;font-size:11px!important}
@media(max-width:1150px){.clients-layout{grid-template-columns:minmax(0,1fr)!important}.client-details-panel{grid-row:2!important}.clients-table{min-width:620px}}
@media(max-width:850px){.clients-layout{gap:10px!important}.client-details-panel{padding:12px!important}.clients-table th,.clients-table td{padding:9px 8px!important}.client-detail-actions button{min-height:40px!important}}

.client-pagination{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:10px 2px;color:var(--ab-muted);font-size:10px}
.client-pagination>div{display:flex;align-items:center;gap:7px}
.client-pagination button{min-width:28px;width:28px;height:28px;padding:0!important;display:grid;place-items:center}
.client-pagination button:disabled{opacity:.35;cursor:not-allowed}
@media(max-width:850px){.client-pagination{flex-wrap:wrap}.client-pagination button{min-width:36px;width:36px;height:36px}}

/* Protocol catalog uses the reference's compact management table, not a wall of cards. */
#protocolCatalog.protocol-catalog{display:block!important;grid-template-columns:none!important}
.protocol-table-scroll{width:100%;overflow:auto;border:1px solid var(--ab-line);border-radius:15px;background:rgba(4,4,5,.25)}
.protocol-table{width:100%;min-width:680px;border-collapse:separate;border-spacing:0;font-size:12px}
.protocol-table th{padding:12px 11px;text-align:right;color:var(--ab-muted);font-size:10px;font-weight:600;background:rgba(255,255,255,.025);border-bottom:1px solid var(--ab-line);white-space:nowrap}
.protocol-table td{padding:12px 11px;border-bottom:1px solid rgba(180,183,191,.1);vertical-align:middle}
.protocol-table tbody tr:last-child td{border-bottom:0}
.protocol-table tbody tr:hover{background:rgba(255,255,255,.025)}
.protocol-table td small{display:block;color:var(--ab-muted);font-size:10px;margin-top:4px;overflow-wrap:anywhere}
.protocol-table .experimental-label{color:#c8ac73}
.protocol-table-toggle{display:inline-flex;align-items:center;gap:8px;white-space:nowrap;color:var(--ab-muted);font-size:10px}
.protocol-table-toggle input{accent-color:#aeb8b2;width:15px;height:15px}
@media(max-width:850px){.protocol-table th,.protocol-table td{padding:10px 8px!important}}

/* Native table formatting must override the legacy global table{display:block} rule. */
html body main.app-shell .clients-table,
html body main.app-shell .protocol-table{
 display:table!important;width:100%!important;max-width:none!important;
 overflow:visible!important;border-collapse:separate!important;
}
html body main.app-shell .clients-table-scroll,
html body main.app-shell .protocol-table-scroll{
 display:block!important;width:100%!important;max-width:none!important;
}

/* Reference fidelity: repeat a sparse, irregular starfield across the page instead of a few isolated dots. */
html body main.app-shell>.workspace{
 background-color:transparent!important;
 background-image:
  radial-gradient(1px 1px at 12px 19px,rgba(238,240,245,.24) 98%,transparent),
  radial-gradient(1px 1px at 82px 104px,rgba(238,240,245,.17) 98%,transparent),
  radial-gradient(1.4px 1.4px at 156px 53px,rgba(238,240,245,.2) 98%,transparent),
  radial-gradient(1px 1px at 221px 168px,rgba(238,240,245,.16) 98%,transparent),
  radial-gradient(1px 1px at 279px 77px,rgba(238,240,245,.18) 98%,transparent),
  radial-gradient(1px 1px at 47px 202px,rgba(238,240,245,.13) 98%,transparent),
  radial-gradient(1.5px 1.5px at 197px 232px,rgba(238,240,245,.2) 98%,transparent),
  radial-gradient(ellipse at 16% 28%,rgba(190,194,203,.025),transparent 38%)!important;
 background-size:310px 260px,310px 260px,310px 260px,310px 260px,310px 260px,310px 260px,310px 260px,100% 100%!important;
 background-repeat:repeat,repeat,repeat,repeat,repeat,repeat,repeat,no-repeat!important;
}
@media(min-width:851px) and (max-width:1150px){
 html body main.app-shell>.workspace>.top>.tools{
  flex-wrap:wrap!important;overflow:visible!important;overflow-x:visible!important;
  white-space:normal!important;align-content:center!important;row-gap:7px!important;
 }
 html body main.app-shell>.workspace>.top>.tools>*{flex:0 1 auto!important;max-width:100%!important}
 html body main.app-shell>.workspace>.top>.tools>.top-tools-search{flex:1 1 150px!important;min-width:140px!important}
 html body main.app-shell>.workspace>.top>.tools>#abyssThemeDock{max-width:100%!important}
}
@media(max-width:850px){
 html body main.app-shell>.workspace{
  background-size:240px 220px,240px 220px,240px 220px,240px 220px,240px 220px,240px 220px,240px 220px,100% 100%!important;
 }
}
/* Match the login reference's denser star field while keeping the central eclipse understated. */
html body:has(.login-layout) .login-layout:after{
 content:"";position:fixed;inset:0;z-index:1;pointer-events:none;opacity:.58;
 background-image:
  radial-gradient(1px 1px at 18px 27px,rgba(245,246,249,.55) 98%,transparent),
  radial-gradient(1px 1px at 93px 119px,rgba(245,246,249,.3) 98%,transparent),
  radial-gradient(1.5px 1.5px at 177px 68px,rgba(245,246,249,.38) 98%,transparent),
  radial-gradient(1px 1px at 244px 189px,rgba(245,246,249,.32) 98%,transparent),
  radial-gradient(1px 1px at 286px 34px,rgba(245,246,249,.35) 98%,transparent),
  radial-gradient(1px 1px at 56px 214px,rgba(245,246,249,.24) 98%,transparent);
 background-size:320px 250px!important;background-repeat:repeat!important;
}
html body:has(.login-layout) .login-layout>.card{z-index:2!important}

/* Tablet header fit: compact controls so the theme selector does not fall onto an isolated row. */
@media(min-width:851px) and (max-width:1150px){
 html body main.app-shell>.workspace>.top>.tools{gap:5px!important;row-gap:5px!important}
 html body main.app-shell>.workspace>.top>.tools>*{font-size:10px!important;padding:5px 6px!important;min-height:30px!important;line-height:1.2!important}
 html body main.app-shell>.workspace>.top>.tools>.top-tools-search{flex:1 1 120px!important;width:120px!important;min-width:110px!important}
 html body main.app-shell>.workspace>.top>.tools>#abyssThemeDock{flex:0 0 auto!important;width:165px!important;max-width:165px!important;min-width:0!important;gap:3px!important;padding:4px 5px!important}
 html body main.app-shell>.workspace>.top>.tools>#abyssThemeDock select{width:116px!important;max-width:116px!important;min-width:0!important;font-size:10px!important;padding:4px!important}
}
@media(min-width:851px){
 html body:has(.login-layout) .login-visual .visual-orbit{width:min(20vw,260px)!important}
}

/* Keep live dashboard status available to assistive technology and the health checks without changing the reference card composition. */
html body main.app-shell>.workspace>#dashboardQuickCard .dashboard-status-sr-only{
 position:absolute!important;width:1px!important;height:1px!important;padding:0!important;margin:-1px!important;
 overflow:hidden!important;clip:rect(0,0,0,0)!important;clip-path:inset(50%)!important;
 white-space:nowrap!important;border:0!important;opacity:0!important;pointer-events:none!important;
}

/* Desktop rail proportion from the supplied reference panels. */
@media(min-width:1151px){
 html body main.app-shell{grid-template-columns:220px minmax(0,1fr)!important}
 html body main.app-shell>aside.sidebar{width:220px!important;padding:16px 10px!important}
 html body main.app-shell>.workspace{min-width:0!important}
}

/* Keep all four reference-style activity rows visible without an inner scrollbar on desktop. */
@media(min-width:1151px){
 html body main.app-shell>.workspace>#dashboardQuickCard #recentActivityList{max-height:220px!important;overflow-y:visible!important}
 html body main.app-shell>.workspace>#dashboardQuickCard #recentActivityList .report-event{
  gap:2px!important;padding:6px 9px!important;margin:4px 0 0!important;border-radius:10px!important;
 }
 html body main.app-shell>.workspace>#dashboardQuickCard #recentActivityList .event-message{font-size:11px!important;line-height:1.3!important}
 html body main.app-shell>.workspace>#dashboardQuickCard #recentActivityList .event-meta{font-size:9px!important;line-height:1.2!important}
}
/* Compact resource chips preserve the reference dashboard's low-profile chart card. */
html body main.app-shell>.workspace>#dashboardUsageCard>.stats{
 display:grid!important;grid-template-columns:repeat(3,minmax(0,1fr))!important;
 gap:6px!important;margin:9px 0 7px!important;
}
html body main.app-shell>.workspace>#dashboardUsageCard>.stats>.card{
 display:flex!important;align-items:center!important;justify-content:space-between!important;
 gap:6px!important;min-width:0!important;min-height:0!important;height:auto!important;
 padding:7px 9px!important;border-radius:10px!important;
}
html body main.app-shell>.workspace>#dashboardUsageCard>.stats>.card>span{
 font-size:10px!important;line-height:1.2!important;
}
html body main.app-shell>.workspace>#dashboardUsageCard>.stats>.card>.num{
 font-size:14px!important;line-height:1.2!important;margin:0!important;
}
html body main.app-shell>.workspace>#dashboardUsageCard>#usageSparkline{
 display:block!important;width:100%!important;height:112px!important;max-height:112px!important;
}
html body main.app-shell>.workspace>#dashboardUsageCard>#chartNote{
 font-size:9px!important;line-height:1.3!important;margin-top:3px!important;
}

/* Account identity remains visible at the foot of the navigation rail, as in the mobile reference. */
html body main.app-shell>aside.sidebar>.sidebar-account-badge{
 display:flex!important;align-items:center!important;gap:10px!important;
 flex:0 0 auto!important;min-width:0!important;margin:12px 0 0!important;
 padding:10px 11px!important;border-top:1px solid var(--ab-line)!important;
 border-bottom:1px solid var(--ab-line)!important;background:rgba(255,255,255,.018)!important;
 border-radius:10px!important;
}
html body main.app-shell>aside.sidebar>.sidebar-account-badge .sidebar-account-avatar{
 display:grid!important;place-items:center!important;flex:0 0 30px!important;
 width:30px!important;height:30px!important;border:1px solid var(--ab-line)!important;
 border-radius:50%!important;background:rgba(255,255,255,.035)!important;font-size:14px!important;
}
html body main.app-shell>aside.sidebar>.sidebar-account-badge b,
html body main.app-shell>aside.sidebar>.sidebar-account-badge small{
 display:block!important;overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important;
}
html body main.app-shell>aside.sidebar>.sidebar-account-badge b{font-size:11px!important;font-weight:600!important}
html body main.app-shell>aside.sidebar>.sidebar-account-badge small{margin-top:3px!important;color:var(--ab-muted)!important;font-size:10px!important}

/* Reference-style segmented creation flow; all existing form IDs and API payloads remain intact. */
html body #createServiceCard .creation-tabs{display:flex!important;align-items:center!important;gap:7px!important;flex-wrap:wrap!important;margin:18px 0 14px!important;padding:5px!important;border:1px solid var(--ab-line)!important;border-radius:12px!important;background:rgba(255,255,255,.018)!important}
html body #createServiceCard .creation-tab{flex:1 1 110px!important;min-height:38px!important;padding:8px 14px!important;border:1px solid transparent!important;border-radius:8px!important;background:transparent!important;color:var(--ab-muted)!important;font-size:12px!important;transition:background .18s ease,border-color .18s ease,color .18s ease!important}
html body #createServiceCard .creation-tab:hover{border-color:var(--ab-line)!important;color:var(--ab-text)!important}
html body #createServiceCard .creation-tab.is-active{border-color:rgba(220,228,232,.22)!important;background:linear-gradient(180deg,rgba(255,255,255,.09),rgba(255,255,255,.035))!important;color:var(--ab-text)!important;box-shadow:inset 0 1px rgba(255,255,255,.07),0 5px 18px rgba(0,0,0,.16)!important}
html body #createServiceCard .creation-tab-panel{min-height:170px!important;padding:8px 2px 14px!important}
html body #createServiceCard .creation-tab-panel[hidden]{display:none!important}
html body #createServiceCard .creation-fields-general,html body #createServiceCard .creation-fields-limits{grid-template-columns:repeat(2,minmax(0,1fr))!important}
html body #createServiceCard .creation-hint{margin:12px 2px 0!important;line-height:1.9!important}
html body #createServiceCard .creation-panel-title{margin:4px 0 12px!important}
html body #createServiceCard .creation-submit-row{align-items:center!important;margin-top:10px!important;padding-top:14px!important;border-top:1px solid var(--ab-line)!important;gap:12px!important}
html body #createServiceCard .creation-submit-row .small{max-width:68ch!important}
html body #createServiceCard .profile-grid{grid-template-columns:repeat(3,minmax(0,1fr))!important;gap:9px!important}
html body #createServiceCard .profile-setting{min-height:58px!important;padding:12px!important;border-color:var(--ab-line)!important;border-radius:12px!important;background:linear-gradient(145deg,rgba(255,255,255,.035),rgba(255,255,255,.012))!important}
html body #createServiceCard .profile-setting:has(input:checked){border-color:rgba(220,228,232,.32)!important;background:linear-gradient(145deg,rgba(255,255,255,.075),rgba(255,255,255,.02))!important}
@media(max-width:850px){html body #createServiceCard .profile-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}}
@media(max-width:560px){html body #createServiceCard .creation-tabs{gap:4px!important}html body #createServiceCard .creation-tab{flex-basis:calc(50% - 4px)!important}html body #createServiceCard .creation-fields-general,html body #createServiceCard .creation-fields-limits{grid-template-columns:minmax(0,1fr)!important}html body #createServiceCard .profile-grid{grid-template-columns:minmax(0,1fr)!important}html body #createServiceCard .creation-submit-row{align-items:stretch!important;flex-direction:column!important}html body #createServiceCard .creation-submit-row button{width:100%!important}}
/* Restore the reference eclipse/radial-ray mark; keep the starfield quiet and monochrome. */
html body:has(.login-layout) .login-visual .visual-orbit{
 opacity:.31!important;border-color:rgba(205,208,215,.22)!important;
 background-image:radial-gradient(circle at 50% 50%,#020202 0 11.5%,rgba(3,3,4,.96) 12% 13.5%,transparent 14.2%),repeating-conic-gradient(from 0deg,rgba(205,208,215,.28) 0deg .38deg,transparent .42deg 2.4deg)!important;
 background-size:100% 100%!important;
 box-shadow:0 0 76px rgba(190,193,200,.045),inset 0 0 35px rgba(190,193,200,.035)!important;
}
html body:has(.login-layout) .login-visual .visual-orbit:before{border-color:rgba(215,217,223,.24)!important}
html body:has(.login-layout) .login-visual .visual-orbit:after{border-color:rgba(226,228,232,.32)!important}
@media(max-width:700px){html body:has(.login-layout) .login-visual .visual-orbit{opacity:.22!important}}
/* Compact the sign-in panel to the proportions of the approved reference. */
html body .login-layout>.card{padding:28px 30px!important;border-radius:22px!important}
html body .login-layout>.card h1{font-size:clamp(24px,2.1vw,27px)!important;line-height:1.42!important;margin:0 0 7px!important}
html body .login-layout>.card p{font-size:12px!important;line-height:1.8!important;margin:0!important}
html body .login-layout>.card form{margin-top:15px!important}
html body .login-layout>.card input{min-height:39px!important;padding-block:8px!important}
html body .login-layout>.card form>button:not(.login-password-toggle){min-height:40px!important;padding-block:8px!important}
html body .login-layout>.card .login-password-toggle{width:30px!important;min-width:30px!important;height:30px!important;min-height:30px!important;padding:0!important;border:0!important;border-radius:50%!important;box-shadow:none!important}
/* Align the eclipse and wordmark above the form, matching the supplied login composition. */
html body:has(.login-layout) .login-visual .visual-orbit{top:4%!important;left:7%!important;width:min(20vw,180px)!important;opacity:.38!important}
html body:has(.login-layout) .login-visual .visual-eyebrow{top:calc(4% + min(20vw,180px) + 8px)!important;left:7%!important;width:min(20vw,280px)!important;font-size:21px!important}
html body:has(.login-layout) .login-visual h2{top:calc(4% + min(20vw,180px) + 39px)!important;left:7%!important;width:min(20vw,280px)!important}
/* Four-column profile choices mirror the compact protocol matrix in the reference. */
@media(min-width:1151px){html body main.app-shell>.workspace>#createServiceCard #clientProfileChoices.profile-grid{grid-template-columns:repeat(4,minmax(0,1fr))!important;gap:9px!important}}
/* Reference bandwidth-history controls and chart axis. */
html body main.app-shell>.workspace>#dashboardUsageCard .usage-chart-head{display:flex!important;align-items:flex-start!important;justify-content:space-between!important;gap:10px!important;flex-wrap:wrap!important;margin-bottom:9px!important}
html body main.app-shell>.workspace>#dashboardUsageCard .usage-range-tabs{display:flex!important;align-items:center!important;gap:5px!important;flex:0 0 auto!important}
html body main.app-shell>.workspace>#dashboardUsageCard .usage-range-tabs button{min-height:30px!important;height:30px!important;min-width:42px!important;padding:4px 10px!important;border:1px solid var(--ab-line)!important;border-radius:9px!important;background:rgba(255,255,255,.018)!important;color:var(--ab-muted)!important;font-size:10px!important;line-height:1!important;box-shadow:inset 0 1px 0 rgba(255,255,255,.025)!important}
html body main.app-shell>.workspace>#dashboardUsageCard .usage-range-tabs button.is-active{border-color:rgba(220,225,232,.34)!important;background:linear-gradient(145deg,rgba(255,255,255,.13),rgba(255,255,255,.045))!important;color:var(--ab-text)!important;box-shadow:inset 0 1px 0 rgba(255,255,255,.07),0 3px 10px rgba(0,0,0,.12)!important}
html body main.app-shell>.workspace>#dashboardUsageCard #usageSparkline{height:108px!important;max-height:108px!important;margin-top:6px!important}
@media(max-width:560px){html body main.app-shell>.workspace>#dashboardUsageCard .usage-chart-head{align-items:stretch!important}html body main.app-shell>.workspace>#dashboardUsageCard .usage-range-tabs{justify-content:flex-start!important}html body main.app-shell>.workspace>#dashboardUsageCard .usage-range-tabs button{flex:1!important}}




@media(max-width:700px){
 html body .login-layout>.card{padding:22px 18px!important;border-radius:20px!important}
 html body .login-layout>.card h1{font-size:23px!important}
 html body .login-layout>.card input{min-height:42px!important}
}


/* Metric cards borrow the reference's compact, embossed icon medallions without inventing metrics. */
html body main.app-shell>.workspace>#overviewStats>.card{
 position:relative!important;isolation:isolate!important;padding-left:64px!important;
 overflow:hidden!important;min-width:0!important;
 background:linear-gradient(145deg,rgba(255,255,255,.055),rgba(255,255,255,.012))!important;
 box-shadow:inset 0 1px 0 rgba(255,255,255,.035),0 8px 22px rgba(0,0,0,.16)!important;
}
html body main.app-shell>.workspace>#overviewStats>.card:before{
 content:"";position:absolute!important;left:17px!important;top:50%!important;transform:translateY(-50%)!important;
 width:36px!important;height:36px!important;box-sizing:border-box!important;border-radius:50%!important;
 border:1px solid rgba(214,222,232,.19)!important;
 background-color:rgba(255,255,255,.025)!important;
 background-repeat:no-repeat!important;background-position:center!important;background-size:19px 19px!important;
 box-shadow:inset 0 1px 3px rgba(255,255,255,.045),0 3px 9px rgba(0,0,0,.18)!important;
 pointer-events:none!important;
}
html body main.app-shell>.workspace>#overviewStats>.card:nth-child(1):before{
 background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23d5d9df' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='12' cy='8' r='3.5'/%3E%3Cpath d='M5 20c.8-3.3 3.1-5 7-5s6.2 1.7 7 5'/%3E%3C/svg%3E")!important;
}
html body main.app-shell>.workspace>#overviewStats>.card:nth-child(2):before{
 background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23d5d9df' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='9' cy='8' r='3'/%3E%3Cpath d='M3 20c.5-3.2 2.5-5 6-5 2.1 0 3.7.7 4.7 2'/%3E%3Cpath d='m15 18 2 2 4-5'/%3E%3C/svg%3E")!important;
}
html body main.app-shell>.workspace>#overviewStats>.card:nth-child(3):before{
 background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23d5d9df' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='4' y='4' width='16' height='6' rx='2'/%3E%3Crect x='4' y='14' width='16' height='6' rx='2'/%3E%3Cpath d='M8 7h.01M8 17h.01M12 7h4M12 17h4'/%3E%3C/svg%3E")!important;
}
html body main.app-shell>.workspace>#overviewStats>.card:nth-child(4):before{
 background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23d5d9df' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 3C9 7 5 11 5 15a7 7 0 0 0 14 0c0-4-4-8-7-12Z'/%3E%3Cpath d='M9 16a3 3 0 0 0 3 3'/%3E%3C/svg%3E")!important;
}
@media(max-width:1150px){
 html body main.app-shell>.workspace>#overviewStats>.card{padding-left:58px!important}
 html body main.app-shell>.workspace>#overviewStats>.card:before{left:12px!important;width:32px!important;height:32px!important;background-size:17px 17px!important}
}
@media(max-width:560px){
 html body main.app-shell>.workspace>#overviewStats>.card{padding:14px 10px 14px 48px!important}
 html body main.app-shell>.workspace>#overviewStats>.card:before{left:9px!important;width:28px!important;height:28px!important;background-size:15px 15px!important}
}

/* Desktop login visual scale and spacing: align the eclipse/wordmark as one left-column brand block. */
@media(min-width:851px){
 html body:has(.login-layout) .login-visual .visual-orbit{
  top:10%!important;left:50%!important;transform:translateX(-50%)!important;
  width:min(43vw,320px)!important;max-width:320px!important;opacity:.84!important;
 }
 html body:has(.login-layout) .login-visual .visual-eyebrow{
  display:block!important;position:absolute!important;z-index:2!important;
  top:calc(10% + min(43vw,320px) + 10px)!important;left:50%!important;
  transform:translateX(-50%)!important;width:min(43vw,520px)!important;
  text-align:center!important;font-size:23px!important;letter-spacing:.24em!important;
 }
 html body:has(.login-layout) .login-visual h2{
  display:block!important;position:absolute!important;z-index:2!important;
  top:calc(10% + min(43vw,320px) + 43px)!important;left:50%!important;
  transform:translateX(-50%)!important;width:min(43vw,520px)!important;
  text-align:center!important;font-size:11px!important;letter-spacing:.32em!important;
 }
 html body:has(.login-layout) .login-layout>.card{
  width:min(100%,520px)!important;max-width:520px!important;
  padding:40px 38px!important;
 }
 html body:has(.login-layout) .login-layout>.card h1{font-size:31px!important;line-height:1.42!important}
 html body:has(.login-layout) .login-layout>.card form{margin-top:19px!important}
 html body:has(.login-layout) .login-layout>.card input{min-height:45px!important}
 html body:has(.login-layout) .login-layout>.card form>button:not(.login-password-toggle){min-height:44px!important}
}




/* Prevent the desktop activity feed from cutting off its last visible event. */
@media(min-width:1151px){
 html body main.app-shell>.workspace>#dashboardQuickCard #recentActivityList{
  max-height:none!important;height:auto!important;overflow:visible!important
 }
 html body main.app-shell>.workspace>#dashboardQuickCard #recentActivityList .report-event{
  padding:8px 10px!important;margin-top:6px!important
 }
}



/* Restore the reference's stacked metric label/value while keeping compact card height. */
@media(min-width:851px){
 html body main.app-shell>.workspace>#overviewStats>.card{
  display:flex!important;flex-direction:column!important;align-items:flex-start!important;
  justify-content:center!important;gap:2px!important;padding:8px 12px 8px 48px!important;
  text-align:right!important
 }
 html body main.app-shell>.workspace>#overviewStats>.card>span{
  display:block!important;font-size:11px!important;line-height:1.15!important;white-space:nowrap!important
 }
 html body main.app-shell>.workspace>#overviewStats>.card>.num{
  display:block!important;font-size:21px!important;line-height:1.1!important
 }
 html body main.app-shell>.workspace>#overviewStats>.card .small{display:none!important}
}
/* Reference-proportion correction: compact metrics and keep the chart/status row dense. */
@media(min-width:851px){
 html body main.app-shell>.workspace>#overviewStats>.card{
  height:64px!important;min-height:64px!important;max-height:64px!important;
  padding:8px 12px!important;display:flex!important;align-items:center!important
 }
 html body main.app-shell>.workspace>#dashboardUsageCard{
  padding:13px!important;min-height:0!important
 }
 html body main.app-shell>.workspace>#dashboardUsageCard #usageSparkline{
  height:105px!important;max-height:105px!important
 }
 html body main.app-shell>.workspace>#panelHealthCard,
 html body main.app-shell>.workspace>#dashboardQuickCard{
  padding:13px!important;min-height:0!important
 }
 html body main.app-shell>.workspace>#dashboardQuickCard #recentActivityList .report-event{
  min-height:0!important;padding:7px 9px!important;margin-top:5px!important
 }
 html body main.app-shell>.workspace>#dashboardQuickCard #recentActivityList .report-event *{
  line-height:1.3!important
 }
}
@media(min-width:851px) and (max-height:800px){
 html body main.app-shell>.workspace>#dashboardUsageCard #usageSparkline{height:92px!important;max-height:92px!important}
}
/* Final desktop reference pass: compact dashboard rhythm and tighter top offset. */
@media(min-width:851px){
 html body main.app-shell>.workspace{padding-top:56px!important}
 html body main.app-shell>.workspace>#overviewStats{gap:9px!important;margin-bottom:10px!important}
 html body main.app-shell>.workspace>#overviewStats>.card{
  min-height:64px!important;padding-top:10px!important;padding-bottom:10px!important;
  border-radius:13px!important
 }
 html body main.app-shell>.workspace>#overviewStats>.card .num{font-size:23px!important;line-height:1.15!important}
 html body main.app-shell>.workspace>#overviewStats>.card>span{font-size:11px!important}
 html body main.app-shell>.workspace>#dashboardUsageCard{padding:16px!important}
 html body main.app-shell>.workspace>#dashboardUsageCard #usageSparkline{height:142px!important;max-height:142px!important}
 html body main.app-shell>.workspace>#panelHealthCard,
 html body main.app-shell>.workspace>#dashboardQuickCard{padding:16px!important}
 html body main.app-shell>.workspace>#panelHealthCard .dashboard-component-list{gap:7px!important}
 html body main.app-shell>.workspace>#dashboardQuickCard #recentActivityList .report-event{padding:9px 11px!important;margin-top:7px!important}
}
@media(min-width:851px) and (max-height:800px){
 html body main.app-shell>.workspace{padding-top:48px!important}
 html body main.app-shell>.workspace>#dashboardUsageCard #usageSparkline{height:118px!important;max-height:118px!important}
}


/* Match the reference dashboard chart and preserve all four status/activity rows without clipping. */
@media(min-width:851px){
 html body main.app-shell>.workspace>#dashboardUsageCard>.stats{display:none!important}
 html body main.app-shell>.workspace>#dashboardUsageCard{height:220px!important;min-height:220px!important;max-height:220px!important;padding:12px 13px!important;overflow:hidden!important}
 html body main.app-shell>.workspace>#dashboardUsageCard #usageSparkline{height:108px!important;max-height:108px!important;margin-top:6px!important}
 html body main.app-shell>.workspace>#dashboardUsageCard #chartLegend{margin-top:3px!important}
 html body main.app-shell>.workspace>#panelHealthCard{height:auto!important;min-height:220px!important;max-height:none!important;overflow:visible!important;padding:12px!important}
 html body main.app-shell>.workspace>#dashboardQuickCard{height:auto!important;min-height:220px!important;max-height:none!important;overflow:visible!important;padding:12px!important}
 html body main.app-shell>.workspace>#panelHealthCard .dashboard-component-list{gap:4px!important}
 html body main.app-shell>.workspace>#panelHealthCard .dashboard-component-list>*{padding-top:5px!important;padding-bottom:5px!important}
 html body main.app-shell>.workspace>#dashboardQuickCard #recentActivityList .report-event{padding:5px 8px!important;margin-top:4px!important;min-height:0!important}
 html body main.app-shell>.workspace>#dashboardQuickCard #recentActivityList .report-event *{line-height:1.2!important}
}
@media(min-width:851px) and (max-height:800px){
 html body main.app-shell>.workspace>#dashboardUsageCard{height:205px!important;min-height:205px!important;max-height:205px!important}
 html body main.app-shell>.workspace>#dashboardUsageCard #usageSparkline{height:123px!important;max-height:123px!important}
}

/* Final desktop dashboard alignment: keep the recent-activity card level with its neighbors without hiding any of its four entries. */
@media(min-width:851px){
 html body main.app-shell>.workspace>#dashboardQuickCard{height:220px!important;min-height:220px!important;max-height:220px!important;overflow:hidden!important;padding:12px!important}
 html body main.app-shell>.workspace>#dashboardQuickCard #recentActivityList{gap:2px!important}
 html body main.app-shell>.workspace>#dashboardQuickCard #recentActivityList .report-event{padding:3px 7px!important;margin-top:2px!important;min-height:0!important;height:auto!important}
 html body main.app-shell>.workspace>#dashboardQuickCard #recentActivityList .report-event *{font-size:9px!important;line-height:1.08!important}
 html body main.app-shell>.workspace>#dashboardQuickCard #recentActivityList .report-event strong,
 html body main.app-shell>.workspace>#dashboardQuickCard #recentActivityList .report-event b{font-size:10px!important;line-height:1.1!important}
}

/* Hide the resource summary chips inside the usage chart on every viewport; the chart itself remains visible. */
html body main.app-shell>.workspace>#dashboardUsageCard .stats{display:none!important}
html body main.app-shell>.workspace>#dashboardUsageCard #usageSparkline{margin-top:12px!important}
html body main.app-shell>.workspace>#dashboardUsageCard #chartNote{margin-top:6px!important}
 @media(min-width:561px){html body main.app-shell>.workspace>#dashboardUsageCard #usageSparkline{height:72px!important;max-height:72px!important;margin-top:0!important}html body main.app-shell>.workspace>#dashboardUsageCard #chartLegend{margin-top:0!important}html body main.app-shell>.workspace>#dashboardUsageCard #chartNote{display:none!important}}
/* Reference match pass: tighten the header-to-metrics gap and deepen the raised black-glass finish. */
@media(min-width:851px){
 html body main.app-shell>.workspace{padding-top:34px!important}
 html body main.app-shell>.workspace>#overviewStats{margin-top:0!important;margin-bottom:10px!important}
 html body main.app-shell>.workspace>#overviewStats>.card{
  background:linear-gradient(145deg,rgba(255,255,255,.052),rgba(255,255,255,.012) 54%,rgba(0,0,0,.18))!important;
  border-color:rgba(210,214,222,.14)!important;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.055),inset 0 -1px 0 rgba(0,0,0,.55),0 9px 24px rgba(0,0,0,.24)!important;
 }
 html body main.app-shell>.workspace>#dashboardUsageCard,
 html body main.app-shell>.workspace>#panelHealthCard,
 html body main.app-shell>.workspace>#dashboardQuickCard{
  background:linear-gradient(145deg,rgba(20,20,22,.96),rgba(9,9,10,.985) 72%)!important;
  border-color:rgba(205,209,218,.15)!important;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.045),inset 0 -1px 0 rgba(0,0,0,.65),0 12px 28px rgba(0,0,0,.2)!important;
 }
}
@media(min-width:851px) and (max-height:800px){html body main.app-shell>.workspace{padding-top:30px!important}}
@media(max-width:850px){
 html body main.app-shell>.workspace>#overviewStats>.card,
 html body main.app-shell>.workspace>#dashboardUsageCard,
 html body main.app-shell>.workspace>#panelHealthCard,
 html body main.app-shell>.workspace>#dashboardQuickCard{
  border-color:rgba(205,209,218,.15)!important;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.04),0 8px 20px rgba(0,0,0,.18)!important;
 }
}
/* Reference user table: keep the detail inspector beside the table on wide desktops; stack on tablet and mobile. */
@media(min-width:1151px){
 html body main.app-shell>.workspace .clients-layout{
  display:grid!important;
  grid-template-columns:minmax(0,1.35fr) minmax(250px,.8fr)!important;
  align-items:start!important;
  gap:12px!important;
 }
 html body main.app-shell>.workspace .clients-layout>.clients-table-wrap,
 html body main.app-shell>.workspace .clients-layout>#clients,
 html body main.app-shell>.workspace .clients-layout>.client-details-panel,
 html body main.app-shell>.workspace .clients-layout>#clientDetailsPanel{
  grid-column:auto!important;
  width:100%!important;
  min-width:0!important;
  max-width:none!important;
 }
 html body main.app-shell>.workspace .clients-layout>#clientDetailsPanel{margin-top:12px!important}
 html body main.app-shell>.workspace .clients-layout .clients-table-scroll{
  width:100%!important;
  max-width:none!important;
 }
 html body main.app-shell>.workspace .clients-layout .clients-table{
  width:100%!important;
  min-width:620px!important;
 }
}html body main.app-shell>.workspace>#dashboardQuickCard .quick-detail-copy{display:grid!important;grid-template-columns:minmax(0,1fr)!important;gap:2px!important;min-width:0!important;flex:1 1 auto!important;text-align:right!important}
html body main.app-shell>.workspace>#dashboardQuickCard #recentActivityList[hidden]{display:none!important}
html body main.app-shell>.workspace>#dashboardQuickCard .quick-detail-meta{display:block!important;min-width:0!important;color:var(--ab-muted)!important;font-size:9px!important;line-height:1.35!important;overflow-wrap:anywhere!important}

/* Desktop proportions from the reference dashboard: wide chart with balanced side panels. */
@media(min-width:1151px){
 html body main.app-shell>.workspace>#dashboardQuickCard:not(.nav-hidden){grid-column:1 / span 3!important;grid-row:3!important}
 html body main.app-shell>.workspace>#panelHealthCard:not(.nav-hidden){grid-column:4 / span 3!important;grid-row:3!important}
 html body main.app-shell>.workspace>#dashboardUsageCard:not(.nav-hidden){grid-column:7 / span 6!important;grid-row:3!important}
}

/* Screenshot-driven finish: neutral reference tones, compact navigation, and report-first information hierarchy. */
.sidebar{width:206px!important;padding:16px 10px 20px!important;background:linear-gradient(180deg,rgba(8,8,9,.98),rgba(3,3,4,.99))!important}
.workspace{max-width:calc(100% - 206px)!important}
.side-brand{padding:8px 9px 17px!important;color:var(--ab-text)!important;letter-spacing:.11em!important}
.side-caption{padding:9px 8px 5px!important;color:rgba(220,220,225,.48)!important}
.side-nav{gap:3px!important}
.nav-item{min-height:36px!important;padding:8px 9px!important;gap:9px!important;border-radius:10px!important;font-size:12px!important;line-height:1.45!important;color:#b6b6bc!important}
.nav-icon{width:22px!important;flex:0 0 22px!important}
.nav-item:hover,.nav-item.active{background:linear-gradient(145deg,rgba(185,187,194,.12),rgba(27,27,29,.88))!important;border-color:rgba(190,192,198,.2)!important;color:#ececef!important;box-shadow:inset 0 1px rgba(255,255,255,.045),0 5px 16px rgba(0,0,0,.22)!important}
.workspace .reference-page-head{align-items:center!important}
.workspace .reference-page-head .section-title{margin-bottom:4px!important}

/* Reports put the event log first, as in the visual reference, and use a dense table instead of tall cards. */
#reportsPage .report-summary{padding:11px 14px!important;margin-bottom:12px!important}
#reportsPage .report-events{display:block!important;width:100%!important;min-width:0!important;margin-top:8px!important}
#reportsPage .report-event-table-wrap{width:100%;max-width:100%;overflow-x:auto;border:1px solid var(--ab-line);border-radius:13px;background:var(--ab-panel);box-shadow:inset 0 1px rgba(255,255,255,.025)}
#reportsPage .report-event-table{width:100%;min-width:0;border-collapse:collapse;table-layout:fixed;direction:rtl}
#reportsPage .report-event-table th,#reportsPage .report-event-table td{padding:10px 13px;border-bottom:1px solid rgba(185,187,194,.09);text-align:right;vertical-align:top;line-height:1.65;overflow-wrap:anywhere;word-break:normal}
#reportsPage .report-event-table th{font-size:10px;font-weight:750;color:var(--ab-muted);background:rgba(255,255,255,.025)}
#reportsPage .report-event-table tr:last-child td{border-bottom:0}
#reportsPage .report-event-table tbody tr:hover{background:rgba(205,207,212,.025)}
#reportsPage .report-event-table th:first-child{width:52%}
#reportsPage .report-event-table th:nth-child(2){width:14%}
#reportsPage .report-event-table th:nth-child(3){width:34%}
#reportsPage .report-event-table td.event-meta{direction:ltr;text-align:left;font-size:10px;color:var(--ab-muted);font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
#reportsPage .event-level{display:inline-flex;align-items:center;justify-content:center;max-width:100%;padding:3px 7px;border:1px solid var(--ab-line);border-radius:7px;background:rgba(255,255,255,.025);font-size:10px;line-height:1.4;overflow-wrap:anywhere}
#reportsPage .report-profiles{grid-template-columns:minmax(0,1fr)!important;gap:6px!important;margin-top:8px!important}
#reportsPage .report-profiles .report-state{display:grid!important;grid-template-columns:minmax(130px,1.15fr) minmax(90px,.8fr) minmax(145px,1fr) minmax(180px,2fr)!important;align-items:center!important;gap:6px 12px!important;padding:9px 12px!important;border-radius:10px!important;box-shadow:none!important;background:rgba(15,15,16,.68)!important}
#reportsPage .report-profiles .state-title{min-width:0!important;gap:8px!important;font-size:12px!important}
#reportsPage .report-profiles .report-state strong{margin:0!important;font-size:12px!important;line-height:1.5!important}
#reportsPage .report-profiles .report-state .small{min-width:0!important;font-size:10px!important;line-height:1.55!important;overflow-wrap:anywhere!important}
#reportsPage .report-profiles .report-state .small:last-child{margin-top:0!important}
#reportsPage .report-issues{gap:6px!important;margin:8px 0 16px!important}
#reportsPage .report-issue{padding:8px 11px!important;border-radius:9px!important;font-size:11px!important;line-height:1.65!important}

/* The Settings screen exposes existing companion sections as compact tabs, without duplicating their logic. */
#settingsCard .settings-tabs{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin:14px 0 16px;padding:5px;border:1px solid var(--ab-line);border-radius:13px;background:rgba(5,5,6,.72)}
#settingsCard .settings-tab{flex:0 0 auto;width:auto!important;min-width:82px;min-height:34px;padding:7px 12px!important;border:1px solid transparent;border-radius:9px;background:transparent;color:var(--ab-muted);font-size:11px;line-height:1.4;box-shadow:none!important}
#settingsCard .settings-tab:hover,#settingsCard .settings-tab.active{border-color:rgba(190,192,198,.17);background:linear-gradient(145deg,rgba(185,187,194,.12),rgba(35,35,37,.72));color:var(--ab-text);box-shadow:inset 0 1px rgba(255,255,255,.035)!important}
#settingsCard .profile-grid{grid-template-columns:repeat(3,minmax(0,1fr))!important;gap:8px!important}
#settingsCard .profile-setting{min-width:0!important;min-height:40px!important;padding:9px 11px!important;border-radius:11px!important;background:var(--ab-panel)!important;box-shadow:inset 0 1px rgba(255,255,255,.025)!important}
#settingsCard .profile-setting span{min-width:0!important;font-size:11px!important;line-height:1.5!important;overflow-wrap:anywhere!important}

/* Preserve real server diagnostics while keeping the information grid aligned and compact. */
#serversPage .server-identity{margin:11px 0!important;padding:13px 16px!important;border-radius:14px!important}
#serversPage .server-table-wrap{max-width:100%!important;overflow-x:auto!important}
#serversPage .server-state{min-height:112px!important;padding:13px 14px!important}
#serversPage .server-state strong{font-size:16px!important;line-height:1.5!important}
#serversPage .server-state .small{font-size:11px!important;line-height:1.6!important}

@media(max-width:980px){
  #reportsPage .report-profiles .report-state{grid-template-columns:minmax(120px,1fr) minmax(90px,.8fr)!important}
  #reportsPage .report-profiles .report-state .small{grid-column:1/-1!important}
  #settingsCard .profile-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}
}
@media(max-width:850px){
  .sidebar{width:min(290px,84vw)!important;padding:16px 10px 20px!important}
  .workspace{max-width:100%!important;width:100%!important}
  #settingsCard .settings-tabs{gap:5px!important}
  #settingsCard .settings-tab{min-width:0!important;flex:1 1 calc(33.333% - 5px)!important;padding:7px 6px!important}
  #reportsPage .report-event-table th,#reportsPage .report-event-table td{padding:8px 7px!important;font-size:10px!important}
  #reportsPage .report-profiles .report-state{grid-template-columns:minmax(0,1fr) auto!important;gap:5px 8px!important}
  #reportsPage .report-profiles .state-title{grid-column:1/-1!important}
  #reportsPage .report-profiles .report-state strong,#reportsPage .report-profiles .report-state .small{grid-column:1/-1!important}
  #settingsCard .profile-grid{grid-template-columns:minmax(0,1fr)!important}
}
@media(prefers-reduced-motion:reduce){
  #reportsPage .report-event-table tbody tr{transition:none!important}
}

/* Final rendered-output fixes verified from the fresh screenshots. */
html body main.app-shell .workspace #reportsPage .report-event-table{display:table!important;width:100%!important;max-width:none!important;min-width:100%!important;overflow:visible!important;border-collapse:collapse!important}
#reportsPage .report-event-table-wrap{display:block!important;width:100%!important;max-width:100%!important}
.workspace .stats .num{direction:ltr!important;unicode-bidi:isolate!important}
@media(max-width:700px){
 html body main.app-shell .workspace #createServiceCard #clientProfileChoices .profile-setting{gap:5px!important;padding:7px 6px!important}
 html body main.app-shell .workspace #createServiceCard #clientProfileChoices .profile-setting input{width:15px!important;height:15px!important;flex:0 0 15px!important}
 html body main.app-shell .workspace #createServiceCard #clientProfileChoices .profile-setting span:not(.help-dot){flex:1 1 auto!important;min-width:0!important;font-size:10px!important;line-height:1.35!important;overflow-wrap:normal!important;word-break:normal!important}
 html body main.app-shell .workspace #createServiceCard #clientProfileChoices .profile-setting .help-dot{flex:0 0 15px!important;width:15px!important;height:15px!important;min-width:15px!important;padding:0!important;font-size:9px!important}
}

/* Login artwork is the supplied image, not a CSS approximation. */
html body .abyss-logo-mark{background-image:url('/brand/abyss-tunnel-logo.jpg')!important;background-size:150% 150%!important;background-position:center top!important;background-repeat:no-repeat!important;background-color:#050505!important;overflow:hidden!important}
html body .abyss-logo-mark:before{content:none!important;display:none!important}
html body .login-visual .visual-orbit{display:block!important;position:relative!important;top:auto!important;left:auto!important;inset:auto!important;width:min(39vw,440px)!important;max-width:440px!important;height:auto!important;aspect-ratio:auto!important;align-self:center!important;margin:0 auto!important;border:0!important;border-radius:0!important;background:none!important;box-shadow:none!important;filter:none!important;mask-image:none!important;opacity:1!important;object-fit:contain!important;mix-blend-mode:screen!important;z-index:1!important}
html body .login-visual .visual-orbit:before,html body .login-visual .visual-orbit:after{display:none!important;content:none!important}
html body .login-visual .visual-eyebrow,html body .login-visual h2,html body .login-visual p{display:none!important}
@media(max-width:900px){html body .login-visual .visual-orbit{width:min(34vw,330px)!important;max-width:330px!important}}

/* Desktop/tablet reference layout: the navigation rail stays visible beside the workspace. */
@media(min-width:851px){
 html body main.app-shell .sidebar{
  transform:translateX(0)!important;
  width:clamp(178px,15vw,220px)!important;
  left:0!important;right:auto!important;
  overflow-y:auto!important;
 }
 html body main.app-shell #menuToggle{display:none!important}
 html body main.app-shell .workspace{
  margin:0!important;
  width:100%!important;
  max-width:none!important;
  box-sizing:border-box!important;
  padding:24px 24px 42px!important;
 }
 html body main.app-shell .workspace .top{padding-top:0!important}
}
/* Preserve the supplied logo while reducing the compressed JPEG's near-black square edge. */
html body .login-visual .visual-orbit{filter:contrast(1.7) brightness(1.4)!important}

/* Final visual QA: let the supplied logo image blend with the page starfield instead of an isolated JPEG tile. */
html body .login-layout{isolation:auto!important}
html body .login-visual{z-index:auto!important;isolation:auto!important}

/* Tablet width: allow all reference quick-detail rows to determine the card height instead of clipping them. */
@media (min-width:851px) and (max-width:1150px){
 html body main.app-shell>.workspace>#dashboardQuickCard{
  height:auto!important;min-height:220px!important;max-height:none!important;overflow:visible!important
 }
}

/* Soften the supplied JPEG's rectangular edge while preserving the eclipse, rays, and wordmark. */
html body .login-visual .visual-orbit{
 -webkit-mask-image:radial-gradient(ellipse 72% 112% at 50% 46%,#000 48%,rgba(0,0,0,.94) 63%,rgba(0,0,0,.38) 82%,transparent 101%)!important;
 mask-image:radial-gradient(ellipse 72% 112% at 50% 46%,#000 48%,rgba(0,0,0,.94) 63%,rgba(0,0,0,.38) 82%,transparent 101%)!important;
}

/* Restore the small login footer shown in the supplied reference while keeping it outside the form card. */
.login-reference-footer{position:fixed!important;left:clamp(20px,4.5vw,70px)!important;bottom:20px!important;z-index:3!important;width:min(560px,43vw)!important;display:flex!important;align-items:center!important;justify-content:space-between!important;gap:22px!important;color:rgba(210,212,218,.62)!important;font-size:10px!important;line-height:1.7!important;direction:ltr!important}
.login-reference-footer .login-footer-links{display:flex!important;align-items:center!important;gap:14px!important;flex-wrap:wrap!important}
.login-reference-footer a{color:rgba(220,222,228,.68)!important;text-decoration:none!important;white-space:nowrap!important;font-size:10px!important}
.login-reference-footer a:hover{color:#eee!important}
.login-reference-footer .login-footer-brand{text-align:right!important;direction:ltr!important;white-space:nowrap!important;letter-spacing:.08em!important;color:rgba(218,220,225,.70)!important}
.login-reference-footer .login-footer-brand small{display:block!important;color:rgba(170,172,180,.48)!important;font-size:8px!important;letter-spacing:.14em!important}
@media(max-width:850px){.login-reference-footer{position:relative!important;left:auto!important;bottom:auto!important;width:min(432px,calc(100vw - 28px))!important;max-width:432px!important;margin:14px auto 0!important;gap:12px!important;font-size:9px!important}.login-reference-footer .login-footer-links{gap:9px!important}.login-reference-footer a{font-size:9px!important}.login-reference-footer .login-footer-brand{font-size:9px!important}}
@media(max-width:380px){.login-reference-footer{flex-direction:column!important;align-items:flex-start!important}.login-reference-footer .login-footer-brand{text-align:left!important}}

/* Final reference QA: fit quick details and tablet toolbar without changing page structure. */
@media(min-width:1151px){
 html body main.app-shell>.workspace>#dashboardQuickCard{
  height:220px!important;min-height:220px!important;max-height:220px!important;overflow:hidden!important;padding:10px!important
 }
 html body main.app-shell>.workspace>#dashboardQuickDetails{
  gap:4px!important;margin-top:6px!important
 }
 html body main.app-shell>.workspace>#dashboardQuickDetails .quick-detail-row{
  padding:4px 7px!important;gap:6px!important;border-radius:9px!important;min-height:0!important
 }
 html body main.app-shell>.workspace>#dashboardQuickDetails .quick-detail-copy{gap:1px!important}
 html body main.app-shell>.workspace>#dashboardQuickDetails .quick-detail-copy>.small{
  font-size:9px!important;line-height:1.2!important
 }
 html body main.app-shell>.workspace>#dashboardQuickDetails .quick-detail-meta{
  font-size:8px!important;line-height:1.15!important
 }
 html body main.app-shell>.workspace>#dashboardQuickDetails .quick-detail-row>strong{
  max-width:50%!important;overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important;
  font-size:10px!important;line-height:1.15!important
 }
}
@media(min-width:851px) and (max-width:1150px){
 html body main.app-shell>.workspace>.top>.tools{gap:4px!important;min-width:0!important}
 html body main.app-shell>.workspace>.top>.tools>.top-tools-search{
  width:145px!important;max-width:145px!important;min-width:115px!important;flex:0 1 145px!important;
  padding:6px 8px!important;font-size:10px!important
 }
 html body main.app-shell>.workspace>.top>.tools>button{
  min-height:32px!important;height:32px!important;padding:5px 7px!important;font-size:10px!important;white-space:nowrap!important;flex:0 1 auto!important
 }
 html body main.app-shell>.workspace>.top>.tools>#abyssThemeDock{
  width:132px!important;max-width:132px!important;min-width:0!important;flex:0 0 132px!important;
  gap:4px!important;padding:4px!important;font-size:9px!important
 }
 html body main.app-shell>.workspace>.top>.tools>#abyssThemeDock>span:not(.theme-mark){display:none!important}
 html body main.app-shell>.workspace>.top>.tools>#abyssThemeDock>#abyssThemeSelect{
  width:96px!important;max-width:96px!important;min-width:0!important;padding:3px!important;font-size:9px!important
 }
}
</style>"""
ABYSS_VOIDLING_CSS = r"""<style id="voidling-interactive-space">
#void-space-canvas{position:fixed;inset:0;width:100%;height:100%;z-index:1;pointer-events:none;opacity:.9}
body:has(#voidling-widget)>.app-shell,body:has(#voidling-widget)>.wrap{position:relative;z-index:2}
#voidling-widget{position:fixed;right:max(18px,env(safe-area-inset-right));bottom:max(18px,env(safe-area-inset-bottom));z-index:60;width:82px;height:94px;border:0!important;background:transparent!important;box-shadow:none!important;min-height:0!important;padding:0!important;cursor:grab;touch-action:none;user-select:none;-webkit-user-select:none;filter:drop-shadow(0 8px 18px rgba(0,0,0,.75));transition:transform .25s ease,filter .25s ease;overflow:visible!important}
#voidling-widget:hover{transform:translateY(-4px) scale(1.035);filter:drop-shadow(0 0 15px rgba(220,228,255,.24))}
#voidling-widget:focus-visible{outline:2px solid #dce4ff!important;outline-offset:5px;border-radius:18px}
#voidling-widget[data-rotation-mode="on"]{cursor:crosshair}
.voidling-renderer{position:absolute;left:-4%;top:-4%;width:108%;height:108%;z-index:1;display:block;pointer-events:none;background:transparent;opacity:1}
.voidling-art{position:absolute;inset:-2%;z-index:1;display:block;background-position:0% 50%;background-repeat:no-repeat;background-size:500% 100%;mix-blend-mode:screen;pointer-events:none;transform-origin:50% 52%;-webkit-mask-image:radial-gradient(ellipse 50% 62% at 50% 49%,#000 48%,rgba(0,0,0,.94) 66%,rgba(0,0,0,.38) 82%,transparent 100%);mask-image:radial-gradient(ellipse 50% 62% at 50% 49%,#000 48%,rgba(0,0,0,.94) 66%,rgba(0,0,0,.38) 82%,transparent 100%);filter:contrast(1.12) drop-shadow(0 5px 10px rgba(0,0,0,.58));animation:voidling-float 3.6s ease-in-out infinite}
#voidling-widget[data-renderer="webgl"] .voidling-art{opacity:0;visibility:hidden}
.voidling-orbit{position:absolute;pointer-events:none;z-index:2;left:-8%;top:28%;width:116%;height:40%;border:1px solid rgba(205,215,255,.19);border-radius:50%;transform:rotate(-25deg);opacity:.72;animation:voidling-orbit 9s linear infinite}
.voidling-orbit:after{content:"";position:absolute;inset:16% -7%;border:1px solid rgba(218,224,244,.12);border-radius:50%;transform:rotate(42deg);box-shadow:0 0 8px rgba(210,220,245,.035)}
#voidling-widget[data-state="online"] .voidling-art{background-position:0% 50%}
#voidling-widget[data-state="checking"] .voidling-art{background-position:25% 50%;animation:voidling-float 1.2s ease-in-out infinite;filter:drop-shadow(0 0 9px rgba(215,225,255,.35))}
#voidling-widget[data-state="error"] .voidling-art{background-position:50% 50%;filter:drop-shadow(0 0 6px rgba(255,75,88,.55))}
#voidling-widget[data-state="sleep"] .voidling-art{background-position:75% 50%}
#voidling-widget[data-state="sleep"]{opacity:.84}
#voidling-widget.is-reacting .voidling-art{background-position:100% 50%!important;animation:voidling-react .55s ease-out 1}
#voidling-widget.is-reacting .voidling-orbit{border-color:rgba(238,243,255,.78)}
#voidling-widget.is-navigating .voidling-orbit{animation:voidling-nav-orbit .85s cubic-bezier(.2,.8,.2,1) 1;border-color:rgba(245,248,255,.9)}
#voidling-widget.is-navigating .voidling-art{background-position:100% 50%!important;animation:voidling-nav-hop .72s cubic-bezier(.2,.8,.2,1) 1;filter:drop-shadow(0 0 10px rgba(226,234,255,.36))}
#voidling-label{position:absolute;z-index:3;right:0;bottom:0;white-space:nowrap;font:10px/1.5 Vazirmatn,Tahoma,sans-serif;color:#dce4f6;background:rgba(7,8,12,.88);border:1px solid rgba(205,215,240,.2);border-radius:99px;padding:3px 8px;opacity:0;transform:translateY(3px);transition:opacity .2s,transform .2s;pointer-events:none}
#voidling-widget:hover #voidling-label,#voidling-widget:focus-visible #voidling-label,#voidling-widget.show-label #voidling-label{opacity:1;transform:translateY(0)}
.voidling-sleep-mark{display:none;position:absolute;z-index:3;right:4px;top:-4px;font:700 11px/1 Vazirmatn,Tahoma,sans-serif;letter-spacing:2px;color:#dce4f7;text-shadow:0 0 9px #dce4f780;pointer-events:none}
#voidling-widget[data-state="sleep"] .voidling-sleep-mark{display:block}
@keyframes voidling-float{0%,100%{transform:translateY(0) rotate(-2deg)}50%{transform:translateY(-6px) rotate(2deg)}}
@keyframes voidling-orbit{to{transform:rotate(335deg)}}
@keyframes voidling-react{0%{transform:scale(1)}35%{transform:scale(1.12) rotate(5deg)}100%{transform:scale(1)}}
@keyframes voidling-nav-orbit{0%{transform:rotate(-25deg) scale(1)}45%{transform:rotate(155deg) scale(1.16)}100%{transform:rotate(335deg) scale(1)}}
@keyframes voidling-nav-hop{0%,100%{transform:translateY(0) scale(1)}35%{transform:translateY(-10px) scale(1.06)}65%{transform:translateY(1px) scale(.98)}}
@media(max-width:600px){#voidling-widget{right:12px;left:auto;top:max(137px,calc(env(safe-area-inset-top) + 125px));bottom:auto;width:40px;height:44px;transform:none;transform-origin:top right}#voidling-widget:hover{transform:translateY(-2px)}#voidling-status-popover{top:max(64px,calc(env(safe-area-inset-top) + 52px))!important;bottom:auto!important;left:12px!important;right:12px!important;width:auto;max-width:none!important}}
@media(min-width:601px) and (max-width:1100px){#voidling-widget{width:38px;height:44px;bottom:10px}}
@media(prefers-reduced-motion:reduce){.voidling-art,.voidling-orbit{animation:none!important}#voidling-widget{transition:none}}
</style>"""
ABYSS_VOIDLING_JS = r"""<script id="voidling-interactive-space-script">
(()=>{if(document.getElementById('void-space-canvas'))return;
const canvas=document.createElement('canvas');canvas.id='void-space-canvas';canvas.setAttribute('aria-hidden','true');document.body.appendChild(canvas);
const ctx=canvas.getContext('2d',{alpha:true});if(!ctx)return;
let w=0,h=0,dpr=1,raf=0;const ripples=[],prefersReduced=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
function resize(){dpr=Math.min(window.devicePixelRatio||1,1.5);w=innerWidth;h=innerHeight;canvas.width=Math.round(w*dpr);canvas.height=Math.round(h*dpr);canvas.style.width=w+'px';canvas.style.height=h+'px';ctx.setTransform(dpr,0,0,dpr,0,0)}
function addRipple(x,y){ripples.push({x,y,start:performance.now(),life:prefersReduced?420:1050});if(ripples.length>12)ripples.shift();if(!raf)raf=requestAnimationFrame(draw)}
function draw(now){ctx.clearRect(0,0,w,h);for(let i=ripples.length-1;i>=0;i--){const p=ripples[i],t=(now-p.start)/p.life;if(t>=1){ripples.splice(i,1);continue}const radius=8+t*Math.min(145,Math.max(w,h)*.19),alpha=(1-t)*.42;ctx.lineWidth=1.15*(1-t)+.25;ctx.strokeStyle='rgba(220,228,245,'+alpha+')';ctx.beginPath();ctx.arc(p.x,p.y,radius,0,Math.PI*2);ctx.stroke();if(t<.78){ctx.strokeStyle='rgba(180,192,220,'+(alpha*.45)+')';ctx.beginPath();ctx.arc(p.x,p.y,radius*.68,0,Math.PI*2);ctx.stroke()}for(let j=0;j<7;j++){const a=j*2.399+t*1.2,rr=radius*(.3+(j%3)*.22);ctx.fillStyle='rgba(225,231,248,'+(alpha*(.7-j*.07))+')';ctx.beginPath();ctx.arc(p.x+Math.cos(a)*rr,p.y+Math.sin(a)*rr,1.2*(1-t),0,Math.PI*2);ctx.fill()}}
if(ripples.length)raf=requestAnimationFrame(draw);else{raf=0;ctx.clearRect(0,0,w,h)}}
resize();addEventListener('resize',resize,{passive:true});
document.addEventListener('click',e=>{wakeFromIdle();if(e.target.closest('#voidling-widget,button,a,input,select,textarea,[role="button"]')){if(e.target.closest('#voidling-widget'))return}addRipple(e.clientX,e.clientY)},{passive:true});
function reactToNavigation(e){const target=e.target.closest('a,button,[role="button"],[data-section],[data-page],[data-view],.nav-link,.menu-item,.sidebar-item');if(!target||target.closest('#voidling-widget')||target.closest('#voidling-status-popover'))return;const looksLikeNavigation=target.matches('a[href], [data-section], [data-page], [data-view], .nav-link, .menu-item, .sidebar-item')||target.closest('nav,aside,[role="navigation"],.sidebar,.drawer,.mobile-menu');if(!looksLikeNavigation)return;wakeFromIdle();triggerReaction();widget.classList.remove('is-navigating','is-reacting');void widget.offsetWidth;widget.classList.add('is-navigating','is-reacting');const r=widget.getBoundingClientRect();addRipple(r.left+r.width/2,r.top+r.height/2);playTone('hello');clearTimeout(widget._navReactTimer);widget._navReactTimer=setTimeout(()=>widget.classList.remove('is-navigating','is-reacting'),950)}document.addEventListener('click',reactToNavigation,true);
const widget=document.createElement('button');widget.type='button';widget.id='voidling-widget';widget.setAttribute('aria-label','Voidling؛ نمایش وضعیت پنل');widget.setAttribute('aria-haspopup','dialog');widget.dataset.state='online';widget.innerHTML='<span class="voidling-art" aria-hidden="true"></span><span class="voidling-orbit" aria-hidden="true"></span><span id="voidling-label">پنل آنلاین</span>';widget.querySelector('.voidling-art').style.backgroundImage='url("data:image/webp;base64,UklGRlwmAABXRUJQVlA4IFAmAAAQzACdASoCA7EAPsFapk2npSOyKFL7OkAYCWdu0/tTAhdaOzuI/6LENdZEcNHwXn78I/2H/G7oOVXnC3I/zH9LxdMAt73aHe6kb7kB8F5QJ8mr/j8jH5/6hnNRmqcFk5V+LvUG5PblyBiuQmQ76LnJD8izRsrEzetwyOZm/gubMRf5vpNzfSbl6jJ+4Sep695FD08EIFslE2X19RBRi4X/hKPS0Nl/j//mWFx52oCSYjfafcqUVtnRav2BhqHPo+2PG/sQrGUT+HGpz9CO9+EsvZM6O0T9dxVMVDC0JZH/JCtpTZ0Vm4U0go/CGo9e/LFU9l5eb+w6UCGTIc90AtQBUjkMjUWjdMRD+mgO+maQYI8qK015guqUgSWGqeA4OTafRzPd21rtwidRv5SfsNs0X3DR/uWJn4EcsEH6K5ZHrCGUFKR3BwDmdORjVj6woqla/c6/h1fxfPFmORQjlneiFUDKfPBoPpuXRnxKveqTnoADcIGetA/BAGtFebmh876NRHcsxnu5d5Svo4TRnsEeU6fc/4KSPHaHfry7TGr/YmdGcR++dgSGl5T6gS8sU8CHL0ILEZgaDzFuX6y/M9jP6mInOeB4i/0hF1sAhu8fqXR7MMkkloLGbPKnZ2h1lO6m1PXZ/EAhSxBvo66eZ3leFFoNjPt0glhrEwgo8vVe3t4fd0+0Srr63dG2nMLeX1MprT7AZ0juaTbplG0EfIO+q8ksoGpLN3GYyvgA5EcjGmfQxW2F421EGG5lODB9TR32wX3nUFyHd44Vi+yDKey3wd9aMODnyuLX3tR/fB3Vt73HHyNNOsrA70bXl+jxHldN/Q5JnYPLWGnMrYM1qdXgpKbgw6Q8z3sZuBiiyONUT2Xac/i6nYE10jMLLMib1Pq6K//glqaMixg96ena6/LqNvPS7Jk9Yp/CwTuU7rbMKul8GrpphaBB2v2vKO0UQ9bufsNFjmYumI03dq4KQnL/u3nTtvITvujTUm0Jwf4w8KmbyOKv1GtGK8lk0VPQDVauxU2KnUfnWmzMytSTWdaxKoM6+DPDVCsSPHBvizbamDSFvcwnbvfXe4ZFUNRLaMbQn/MeAkzPQXg9uWO+csKmuAB/kFhXI2xa+7Y861ir40DR4JmsKI2pFxjfTEoGnuJgPEEcjJ+t82NePaCqsumxARQdFQGvJk2Wf6qXi59Mh8MxIprhCWo6hC1azEm9jBYiNfiZ1JfZvlcXgNp9ym7bqvAqrkCPF1zZAPMv6RON7O+HhhQ9icB2VI6n+UM+Mm99tVd/5t+6NdT8JgAcTkAxSvb2w1I7iqP4k+KZV5MOTzWy3LvMErRty+PyS1BCEhF5IlcNzZoLQPN0aLplRz4SiFkVkd5/hHj32mHiaAM/FkCw/yCGb6Ch01mAN+6+thveOXQteN7CCFYkLkILhdGhb8YwuB55Mw4E+3X40gDFh0AOESnxP/NFdptlTdmx5rB/mKeTYw0P8JDkcs4YlARWMX/ym62qk/x+rpXN2fRV68fMfj43WKwryFTEftax6SZKC0kHxM16L4svKnp7T5ER/tYB51i4qLUIgLegb8KQ5Nt+fgTm+I2XCke8GBpaHGDqWUFak8OBGgJjpC/k57ncMDrQ89IZWK/q8yPB0EYg4noWvRXa+VerVj6u1Uf5BKMv7RVP4R2wOo7GynkqZ5lvglL5aqR5RFAbd/oFqVCzqYUyu82UJd3KX7+ySCEIxc4YlDhhS/p82qPXsYNFGyj9OZzZL/RcXwk2uT7eY+vbsJOlgJSCXvpPHFw/E+l7az/2SQgmc0RzGFIlT+BlG6iM2UlExiNTdM3C/Qr2U5DZx9VEar11esX/f/Bg8Q0QuOvdZaRZWdysujRWwCp5zzS1hRt4pH9DEWnQGljBBIADcmU+QaqsCSi4rCSUklDlaUaij0C8kVzEE1nyzZsxxjaK5/+lk/riHGBNO+qIvAzap1CFKR8rUr8tVqBujavkxMxNTlYLaFcWtb7MBv5h/hN5ikAEMbi7NlUibai3++umoLK7bcbSJbLbkV4ZrJaE6+SuFII4icye84UrGDIpKtxbXTxQfUX0cwVRYZJPuoYtEJQjwxCx25BtuUvBHk7SUTqMz1PSCw9pne8bwNm8LKXDVv9FfYg73Ag03bque4cFnRtwX8IScgNJk6AtVqOMEYvYbusPckHmR5AA/umUfNNm7PErMfeIJF2ZJTSApIiinB1SVh1JpKWaTi7NZAQ8KqsYyeHkCKhEqZiehgfrRtSuTPj5F/ohtPvAl3FgdVxnXIVBIIljDsidK8uY7pUQS9xXpwVLKJYZDhVynBmBDGrOrD/LNaoFqkcpy5+XhON11PtDqGHSdwrCIYIuB6jgn5e7zAIKnUwCJO/icoO7mdaTfWlRhhq9L+ijv0kbhU3NfqYXYfEcW/tG0WlR8ZYApNUpAPBOzI0FuXReBx+puzS/rzHhw5R59YKGdPxb7zu2JHz+HdzEfBH4rUz77P9FTG3/GcitFe+heqEZ974tdh6435Ugs8OQj5XIAhDnBvW7tKJp4y9Z4QW1bk2F3r1v02I7ErfOKs1sg5+fsBvQ9xOhw+244aGN6QoO+ZJf2N/KB9p6WPB19XUIdyF+rT3inVVwb2u4CPSuq4M0Hki8ZjUgJ6JjOWvoLlKvajt6WbS4IvZFlmaOrxxJkeIDZgHMJ1PpOxPN64vXrp/TfvDO0V6HzT7JjxOfKm+46BN4lhBUNicvqIJOdGdy/YKHSAWawrgtfnfzRuEVzQ3HYnnD2jDDg/iC6nDTENEWF+mmK5b0LSsTiCr6d5gIapcODB77/+Bg4brAsnru/elqYn25dqAUdMNjo9vHO4YK4856YfCeyCDp14WQD3W8g+RLJ6ccFTPU00MVDyFnJWcwlsFtCZVY4cepOIjxGFbGLhS8fN/qy0/pBMu1wLN7atB4KNarvCx4ADbCmbu376ap0UvXGFhlAujAsYNi5kBzh00tZO8L8vC3UvUP0vQfFJpIHWTwXBEoOMtXfDuByB0cDn84XC6Zr8tHUU+kNHP0EicmA8tKvpvGn+72VqM/NT87vUBeqttxkcs9tT15r/ZMD2MO6Vh5/h5niMebjQzGdBtNwKq5+TTCbh2bcNTRZsr7BQ8ZBKAbrkbrwwnzIfcshPcGDecVuMzfFtDnWqhcA9UMWWuzRrCOPwUcxK4SVt4wIEfhztFTQGN6543bUHpSN7UT9f3nqHo/JE9JEOdRs+LP/+ZfQAJAee1O8/ps9iU3FN7b7c8ewiVgRe25Gr5cePibLRRunEL2N6BidOihuyCmwmP0rFEOnxj9WMbmXJE6iaIZZ/clzkJdUK6rsowrrnRm2p8GGDDA1XzvfMy7t7stDe+eFMW91//sBjFZfrPpBwfWT+BW3uOKMee2vWPM2dvrmxzN2dA22mRPB6gyba/7KD2FTFjYTnMTRWC/4VKZYVt7s0wsIZ5FqSxsNOeQeGuOyGDpCHtkZNrJRUtdvvXQRH2b+TPahHayuV3q2WoupUKS+ydIIKfQ4HMzxlCGCJN78QLAW5hUsF83rsXY23lbbQ6KVIWFGtlyc0MD6ZcZ/KtAYZcabVYvHTwgipgr1OzfEUTaXyNiLml3o7szTmgRkWNLsFLg4wAsSnEFJYEDSmKwpoHewhNCb7za52Y8WjE8y/WRMQhPzq4vqyRaN/9EDhjwSzqDa9c1oDhBYjXw1rhO85uOiab+FdSNsdGGtWmitoGpsBvsidMV0ZbJ+GSo71+ohMkrwUk56dX5JpDRsuFcsslNmVlJDt3TCgbaiV0+GtRMni7ccPssPntXxRxtTTzvO9k5DR8Fik5eYCV//cJyNZ3YtakgUpBD8KWJL5MCF4a22Vfm6Dzf0uCinK6lY1E4Ma28HwyVBYfQQM5U/ZXSvTV9L26P3QdlDa+RhA8z017ICLGN5lmp9O+KB3JrW9R7K5ESk9Z0UggLjYL67z+BIaWhKNH+Z1J+Yzm8lLZjQSRnra/57avyVrF+y2M2LzzHLNgjv3/HSJEhFOIFEbWP32wJ9B5SBIaBukDVPzHQSx8M5Q5Fe0rVFyaMy9h6MH+dhIHxaIJNamXVM9NiLq+pANOZ8aoKsueCLbJ77RkUSJX591Dnz+dmP4gkcwaEdNg/0tBtOSip1DMAoLi6dIymiu9dgtQkMrgQMDAgob1fupJthPEMmph03zgGBSPub1YPSJtaUbQsQQTiW9fPvXtEIET01EG+S/jvYksnsy55/4plonKS/+O0noJXJdS6JMQ7Y6Ve8FUvgJuVhTwwMxSoh2fmMYQph1X0knBFCmmzWK6OGDhQnbEtbEZtKuffC7l3CZLHpvGha03nXFQQWgLvrPC8sAfO8kPGjw7sQodF62TFXG55skdhJEKF1TKwevXapyhLos26QarSfDppHbORgzSciEp3bbKPZYHUvLjxlmkt5JvTIVSV5XazorVMxYbZeeG4OGRcNn+Nrd12e+IielIEOGekAF/SjHIx6Nsd2+cxqjveeOnzZiT2yiz1xLHkqvmaMbfWk5324Mi+yHTMjQoY+4Z/Gs80d+jZHPpBJiqmZVUxM+/g9Z6gyKSEEZeBizbLOeTwANFE/3pmr1LVRXm1VXNTbt+9U25hFrA22/GlgiW3a7rszUSzfBecAQGrFasxn2IJ8xSNS+46afV9Qq5BEWVgeA1fZP+wafxYAuqCZmuF2d9AsgWMsOXElVWNF4Ua1eSnDzm5dFs8EuqF4/We6+7ySlBkRRFcT0ndnDo/RUTWQQFqXQpeC7Sp7jSDdc9XEfmWIR4rpos5b+Y90fx+uANj2PK4CaA46Ur2DCBl95yNMOw5I/Vl220MuPqlJ4qN13e5P1jP5Vmnms3buypE1K+08idh4iCc4zWHU3rReFOlprJ/MdJkChAXStQk8JdjrLviMxX7ED2CuGir8zqgsCWlk7TEudwV8UgE5SzBw4K2I7GrucmMD1VAcO2GpDP1AXHAkI5gouLuV+JUHP9i4u59wBfmhl6mpnRL23s7KMitP7q9oGVr2A22kN7skJWYe1V2PHzTLONrLFSDfkGDOHHDWcpJyQbu28lX1CemYPuQXHwT+E1MLlnKNVExvDG65XUe3OAaugGd8dZweN44LAmQtuTCiilr4YmTV/arDliepj+xxnPpH7xljHvm/oun+ejZT7d1bAMEdRijQzYdM41/akyTfefvIxw2clzIVCgBsyxZFS4xeDC9l/RvVby/GDK4+PqdcTNcOFzaEvVamnow3+01AIqfKrMZ1/9OJ/vWEkdUO7deoQpxALrws4NfZ+d6B0lyKDrS4MSCkP1c5rdtq0r2jX3bp/3fI+jUgU36uVbNBd2WEWh9ZcDbsee8jZYF6MPd00+FdK5Du6rq8Lh/GvTC4+G04PGJPAe/Jvz0vqzpP+85vusGq5DEqDthrnFPcvHcfc9XuxWYe9e4JJiyHlYgIUYdZ1KKCOFC1B4hqMxEMt53p0z54cwxmS2mDn6I+weqG2xJNOZeIFK/5jf3ry1QgDOoUnQ9QQ9bQqBGyeP848wiSQdJz+bzswk2K52Q4lJB5xj2kFBr+7rX/Cz1pI3Me/519wGdy/vQjBKyklnNsPxeb7oXimaKrndnfwcX60zNu7/nHtrghKPFsjwNe/Ue8KLwdOTLNi98FHqFH4g1nxoSQwdkcp4HVnNuo7LMif3MfgtXVsXbZfsvxspM/d5JBlr0P6mdkJXHez9HDWmjT5NJrORYRXuP2E6nbvu1HfeBaa349rkIBNssvo/ewLuSsv8m+eO+dqkoJhLsZuFfgPiJQ4cP/2T429cM8f1tx0eHVm72F2IP1xO+c+AnlcZs8WfiNVOYwuGKQokgqyQ2peTiiuMhuriBP9/JHJ4p5KbOoBRu8/zVVDxWqA0o0BziclGY+cYU3zubbmRmltkk+HMoUp5B2IFHIkj+y8YMh8iNXK/HBhgVK6rlGI2F8xEEq4qxFAL2a9rq3ee6mscs7JQIi8p01oFsw+VDTFWRB4/71HK5HH1a9rjB1n9k6NmEvNpXTo8EB/Vz0BCAN2HgNwT7Kjf+gk5FpZykRpFSu1ZymqpFRW3oaDpJokfax4MM/pztW5bSh8FRPKkooWZyDzJNUZVInJlXnm/UpKC5vEo/VgKaqIn9/U29ku9BmgFVikJsBOyWMnbw0FPiWXv0KrlKulMXZ66vkz8mPnOkndeE1Y3PTnlbijT5OM874WISHHpeVB5s/9STwY9600xBDmDsKvIi6EQqD8bWe+a0k3iw/3m8dea3qAWAmbd4QAG1hBX3uyW8wtCVQlMMx2uA0kl4SXUp3zOg7bZgW6uw0NfhWEIg5BfsuMlDKTR17mGlw6g4aqlP2Dxao/d6yHQk0Wq2z9WUEc71cWk+aDbTR8dEywUqmRHdt8rscRI95wKzs5wlwowuDC2z+D4LWlSTTvHduwAirKyMpPVBz3fWJQb9AjYwM+XXNQKxfkVY/bk16YkYB94v9ZS5E+KFUD4o4gEjeROd9bhTR95Kz0Eb3ZA3oKBLRGuq85WvRQx/PDIoTupbqD1EQHXd3jTiaJVZD7i/MM5nuD8zsWLq5EkRQhuAcTnfF73uKp1gmqd0Wkzvt0XyKrb5ITnb+K2KwUggUFDYq3giVg/ZyjQ8UiqYBWGkmHdqRw0ac6qEY+gcKSmV9FsyH0IYqmGYnallInHjK7jslHmtqfBcJdVhOEVBLEO1b/csuxCwtBvyr0Bp5IOKLicHzzRRI57cylx0Zm9LPxfV6RpF9ZF2sR8puAl2ANY7VnYKW7TPIxqiEUVIhxtYTUPt8ywuQ/LBOGZ1qsVQertndkl+6rOiuSLgkc5SEuj85Ec+wqQIZJJY/qUu0f0Vsey5cDBxKjPHM2G74k728TDVFsDpMqJlvPahRDBVCjtUAH5eRJk2UNIH7geYLGN8Rctfooj6aOqU+7iHA72oWUpYTEkc9burZKJx8330PUjUD7Od+dObgkey4uLE7Ameqg3fpc670YXdq6eyINNDgK2Z+hf/wliRJvPZg75Vpcd9YkVWgPTSrEStWMEcFkNqJ7R0b1j4nnvb8WbD95jJzELKQ39A8+59bQJYj+hb9+iK9HzRyzWMjUVW4DROImvwUvPERgxxjshwiB8sTR2QT7lKUjaeMT4dU2Th1KBAD5Fnk/TEMe8bCCgZIHax0Xo8PuIODbweOTAOJOVqOgyHQSCAPim7fC2tkt8poDF2bFIX9G3DVzBCOndhVDUUeeW29KKYwTJrgIKHs1QxkpgiaKPkFu27X3HPqSQ2Me/zp3/fEzKrxidL64AzzDIzXtCNWy0fuLy3pJ+HXHXggk3z5cIfh7ANt6HNfrDMVXrKrSNBTBow3vSerXs2nEMjNM3AmpEqGTOYLe9OT0438Rs0Pjk3eoU4bkahDTwyf3TrM95/e4d7y8Tini4bJSupHoUAOOu+w605QGMIT42+Z03Ucuk8lLFgW3R6pEQ0HLVo2c3XyVpITix8p4ypA4lGJ4haEzR2L+5aGHleZCPFip89LOfRRgTUbJ2UhIkXp05bq6CKO4R5m5r/dhij2gdLG7vD3vYgwy8yrbOjjz6QXZnkfutJApiaL4wMhIfzAfNklRn6R0pjsHN3XBNxQsVS4PY6o4JVSqTboWTVKido9ny30wNEbaLZHfvCm1tGZc67aoTcUCixQheaEsG/F5E2s9qAmGYNpwExEZ2xoKzNAqdvmPo8NAX3gqRPzuC1/z9wQtzwLFafCQg4sbbNqVPmvx0WMYJIBSe3XIKaUnzaFRPNSumr0kNvFhbJUMS8CWt/DZ1Zc3Vv0aUlyzseQuSI/S4JsU1xtzKsA2x2xnB8W2OnCwfcykOdfzKWkGIYhFsvtJGAffISDxQ+wQ9CQa9+T0EOGg42Bfc2Xf1wLUMcXZcIcOUwviy7cskbzKLu5yZjyoiyF8H/8ikCvmkoxdQt5xTnD7xFlP2BcrhKXjMQvWSUPOwXsgnH7JhZdvJFDAvQK1AaOjjshplg6J3eweY2PcMIuGoxvAKLRgxuvQF6IteHtlM/RFVVXjghHwCWrfxji82nKPQAIoFo7ncXg1JQBFU6nuPRkaAciNghTlK0J8SqAGLokXH0HUskerZuM8LvZeYJ5Kp9XROPjmZwZzTT44ERykSr5z5LzCKsma2TJpCYs0/1ZSDbWxDzqrLYe0Z7KTHeGtHxaR+IiXfEg4igbnx8GhqzWM5uuT4ImgGQHAR2W6ZbHaPrWMsyYOgFkqMP4FyJucHN5m/y7YHPzbrppSRM/0ZN5kc4Y/5FOdbqbWDfEXh3QMf65kMldAc/RM5eX3W0EL9B0fVuDGIzo7dTq2ZwFY9fjfek3PA4WEEYXE3AYNYpb6e9AKX87SOoeVrAV/FgrPYn7EVGEQjMcMq1FMUW1bP+Pkrl5pIjNCPF8u5a/EbMtib2VnTbrc+geOdZkfZNVpZKEqr9JGpprHbSkTQK0wfzampZrr7rdPXCYCH3PeyqXpTT+zb8CQNQZo8GeER7/L0CzuS2K37YapozMGZmQS1witcCaR88mlDDfNmaTWL3r94NGZcWyk6l02s5Oeahg9mbmMhmgFWDjRAEQHzxXeM4wMd2X1Wkt1dDGi+zQ0WynO+VE4nmBRbbnwqHA002WhChN+OhTF0piT30/ZANwDEfPnmp/YwlJk1YKH92EDPBxdkvYBVlEZQowhb4wW9YujRTku2fpVYaefp4sBhKVtlcWq2OO+kwtM2R81p+wBa52DmrH5hNbidERZ/j0uOruAs5ahe8NZqu5Jm3sn4ymKVQZ/CpxNar2Zb8fJ3F8w2dfTggyjoaiXwqYje/2yWigMlnNa5lrVQYJfu4wewJUGTNfIeyyNeLDPMvaEM4p9B51QQXGCawVfhxPYqbl6/lnEYqUB3d8o/X9q9vYkhx2I6JAZ8LwYx671z+A4JGfOC7P8mQg85qLvlcSxvWnGjRzS8jQUzqYiriRKvGZerNsL6/Kv/ZLzQuS4jISFsnnfe7yzLN3qNHrLOzoPF/JUUz1uevuTSGLv+EggIaJNe21b5kNLp/tdTWcN1M+FyJu1D3w/Jt2jHXh6kKHk9wwvZqO5X1TcH59t1QkjEvtObgd6CvE1vULE2duldP602jp+BA+JH+tqF09NG1IVFRbZ9Lcgkwl5rukUVtijEDVdhZVeKRwnq6nfy2VTuVB7d7Ra+LUVuagxuacyyf0e3yxyOfRfwiEVk8crSOpYOxAI4PUqa58ezRkVkm8+oDNK+beG1o03xT5dyFeZn9ZoFUgofDJkNFl23LgDiek5++NqKDQ4g8gsNQpxJPzDSOMjIe/+VlS3DO63ijXZuGC43OY+ft7JIfmGbFW+mwx2YDHEdhG37X4kZZ+2ESSVn2nmWIcDTa/3IwliHFlRaSCHYB7E588uP0vlBJkpN6CmIS3HRyi7BUw62tTJmqLpvZ/WzzEPicdfxXbmBWlxmjbZoQBWazJrCc5RDnfMlMf8/xo7j71f+Lr9HlbqPlintmj1sqyLs5Y4TRhxEWR1tFhMJ6HUhjXeZ1XF7N/q8zer2S2w5AFuQuX/A/Wuk9M2pbNHbsDYGf2nX75dl/SwvM8sr5spRBALVP0AX+LCDQ0d+fx8JZXzLdrLHW1kQPqfC3tSwbBUbb1LvNJGnpW2cRlu/U9mEXmch/Hcy7ECwTiIKe+kOuhdE9wxSma9am3VLM6WlPYM00x98x4/jJpISTDg/5N1tNtbLZk0LRVOMY73AcaDCvu+cv9Gv86HzAUuw4+C/ZUWYuQY8d2HOHLAhtaNd9ApY+Fs3Y72yZPvJukM3GoX7cmf02XxluzyKqrqRLrxCcnygpKz4MLOvFgdzjoiB1XTcRf6ISHQK/HKdx0MPfYvn+9UXWk2ryMsjMtsCHUiLXwR/T39sD/tvZM2j0E8NO6Vp5mO8YKG8V+NUW0Xa573a93aPZyOMrVZRcWT2BcUnKGq8VDKrzDgwaiS2ycECVJlA+R8ZN2X9I2CIUdl/miVUXqNVd/GWws12OwAna+siJu1dGVGvRCyECtEu1bWvu4+QqN9WvoxwdYhJmE2m8Z6iNxBhAvhlioMgm+feRDcF2b1dY2jU70SQfIVuiHqBacFjxXHQwByzTnLt6J+QPTvY4sO2XfZoPJEO7gCbN72eDnkGIo/3PjpCGO30h29SYdz/js6/AYds9QIX+6DX8W/r5sD9BUebz5bc65MbZ5OV+cXBH3QPyuYHziOIreGdMuCeVf5UWpdlbsgL5eCqXeikRrw60xJSIZPC/tnoTtxl+UniDAKipglWQtn18/BN8e+grwHjoLmb2xu+YjYR3nWr7vRrIZLunEpIG4DP+Bn82iDm184Ol3u/4kaANdNzTgDIBnGJKeipaEY3JqI95YWS41WLpVPvMjW+cWwF7d9NueUwglvQnLUwmEY/OvJTUwgwP7NFwNRlyU1GUKzfxBnnT4HU+eIVQt10L+JnFdzA4WDhqQ4BAWlKlsO8Z3HTPNPkqjcDnMPlUAoLlQSh6v2SwlX4It1hTMVbLJ2kYIUaf67SNz30Wy0LQ8yN3Pzw2gdMPnPRBnrqY1k4bJzBYh10mxY7+PVxlSNOailAX0D+nSUNqpdO3lHj5D2bml4dIW8xYFNWT+ebZdx2S6dAg5v+WTEU2sNaKWKXE6yPUJ+Y8PsssV5xfYVqKiHKLmyMghMfIR85xqiPWXrGgmIhpDijXYPwJ9SC1db54XDznzLYTXfUxNWBJg75zLbs265AsUJqHJRZjqvlWcjpEtdCvL0lEntwI3trcp7NxBV0aAq496YWaR416YyUHJ96Lm4rYJIhR/EzzYZ9Ss0XWB7PQhNjm+0Asu1br5ce4LKUWdL4pPaxiAXVtfnzwr2GOZdA9N5Y2VUjDIZer+BZX1eWS7eW2xpy5y7dBGJfUHQJDKvR76JambdDwC1W5k0Yy02nU05NUxZsnYuXVmfwaP2DEuTU5SSSt9DlXxZBwLwulWd78/Qta26AKhDFgRIOPdF2/dRi/3mV8NMO8blODV2keGQyTBlDrZMwwbuFrDidc72weuyj0rC96+aOmSuMQXD078Ull1LnPG3xas3o3N808E+aPjf2DFxOPnk5D9ch836Lu6oEnEb6YQ7Q8Aiy51CUWJweIo5dYmluZNmc2nB//OiQr8nHUo8MsnI7UMOJLS+JJu7AAfWIDFVdlXD2GDridcmTkj80CMwTh8NDy+B1GxCMA0/yD6kISoYxFwknlbo54FzARaMYjW3wWntDXwZ9MXHV05eUH6hDZeJsXpKZtcNm6tk5S97cHP7k0/CVSMBAZJ1/cSZ87Ul6bgMje1zCHvtaMTsU6Tbmpjib6ofp8djLoAPBcfPztoUZ6mAKl6nJWn3QY5c9zuCrypMTuZZM3Nd3Sd/lJwjBPIQG++O5fwch+xJIYCspi1a3AvI5sXOM9EYvV4FkWXsXd6T/Ku/ky7pEFCJ86wk0weykUODlGzwa40tuLfRdhJcJad2ssfD4zJQFwRqbLBRwjHbRYUmFNwy4C5Vx+gQdQv/3A06e+un16wcJRmDreQjRsv70drJIWdIDbvbvpjd9yPFFyUMSA0uRX4PQllKCzY+pfgFQMbEwzHh4O6wxHmbVvWR7EqmRDwMXIzimSt9FriwSMdDmfrEB0iPXY5TFLcWFbn0ki+7WsA1v9FTSJoam6YlID5szUANttQMZG5nbdoJJJ9WjHlICMF+nqCDlfkAdE9BJfT49uxzf18yMmm+vBfvb/+aUbsXq5WxvziOJsvuOg8zqlt6GwFK0mutYaaXCx6EaOVMD+Q4uQxDaMYRi67fy39Z1AOqWgNtZNZuy0XNCp7l3qcYu2T3z8YEHyS3ZzM2kL4TX1M81SyLPoRPF8ilA1cXWncJg+9ZbFMscCb5g1GKSohewU11XtUVvYJqVezW97sYgWiguydvLkKUoYV1OMUtHARtwIRx0aIZuXHnaerlP36feEOTGdsGKr3PHWBVlzQP5unHEmh9Bg5MiRe0oYlmwmgPzmADG/FrA37heOs4D6dMqsQ8aHEBnhdikYuyqEMyaL8fEFZXlO+kcgeXtd8nHNGoE7WHVG75+javHnFgTRyTI3wf+FRngo4y5LY05D8zVsz1LDEkXNcP/Ob8YBeK/KSXm3T9sYBX4U+nDHtbLyuRekOyANZFfsYlPProV6WxRQwii2795DSi7lga34M/QVtIrmVOdi+0SF5LECskEFXGk0oLwvnd7dPmyG2SlHntsrgNdjKVrgSGOK9NFaX0ujQiwCWIlRTU/Cf804q/iuToai+ha9w9pYR71gXeVrc3Bk0lveHHj41U4lcFogeKRGsbRGdeDQ6CrPO5meZ4A9e/6jcAaK5X1PwbOs2DTVH77cTQzYESK2/rE+f3wV3x1ZZ80Iz92nQDfCxXbZGTwhOs21gb6vLyfNkELwByllo+VNzyHQb+RuTlMj3VInNHdXlX8tcyeJlpKKHuHXY9G4SAX8rBfnyrSad/osz2fg/Ba269TTzzLmwgjTTaHzwKWvvPLKu+UNDYBCubb9Gjz8EN65SBUY7hLvRPxW/4zBrhOxbfpvbYCZHnzOTZfo7M5GQBTd6UQ5qcZDs8hNAZBYxmg9DbLOA4qMV0Yn8X3navbkLOKW/z0NunJLEhWKkFZM2FcbEkIdSnjfK5NLCmhEAJt5Rrmc1QABQ9OgHyvObIJEIrImbCLxvhR2l5HY7mYcimZgtCxjPHb5HTXKkLTIsulwAXyNhzOJrQ0+w5XNXBn7yxBR2TTX3Xqibi1uaz0AvufY4BZsXdUc1WCxcZw0cWArSuAHqPeH+unpkt+wOCp4O1uR2wA65We+vC9xs9yWI/7GyQaMjTsCj6+mZ1eQLEh+n9oi/775I71I7swA/27QgArwzYCos65q38OXTdC62b7FQdjfA4dNdjffpa607xssc52qrcTJSJpDTY7gAI9fn7A/UWXiASG5iHdOHS8xARusRAGMlPZatPN2qxGe+Qi1289tbVBXTT9gZDyvmSbLL6RelQ9YICCM/ypIDds0xSppl18+9B2EwsvMNTVXmYkqzBV50fgMtGg+rfwBwOa7TgBr836EncAA")';document.body.appendChild(widget);
widget.dataset.rotationMode='off';widget.insertAdjacentHTML('beforeend','<span class="voidling-sleep-mark" aria-hidden="true">z z</span>');
let modelYaw=0,modelPitch=0,rotationMode=false;
function createVoidlingRenderer(host,rotation){
 const canvas=document.createElement('canvas');canvas.className='voidling-renderer';canvas.setAttribute('aria-hidden','true');canvas.dataset.geometry='procedural-mesh';host.insertBefore(canvas,host.firstChild);
 let gl=null,program=null,rafId=0,lastFrame=0,dirty=true,disposed=false,particles=[];
 const reduceMotion=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
 try{
  gl=canvas.getContext('webgl',{alpha:true,antialias:true,depth:true,stencil:false,preserveDrawingBuffer:false,powerPreference:'low-power'});
  if(!gl)return null;
  const vertexSource=[
   'attribute vec3 aPosition;','attribute vec3 aNormal;','uniform mat4 uMVP;','uniform mat4 uModel;','varying vec3 vNormal;','varying vec3 vWorld;',
   'void main(){vec4 world=uModel*vec4(aPosition,1.0);vWorld=world.xyz;vNormal=normalize(mat3(uModel)*aNormal);gl_Position=uMVP*vec4(aPosition,1.0);}'
  ].join('\n');
  const fragmentSource=[
   'precision mediump float;','uniform vec3 uColor;','uniform vec3 uRim;','uniform vec3 uEmissive;','uniform float uAlpha;','uniform float uShine;','varying vec3 vNormal;','varying vec3 vWorld;',
   'void main(){vec3 n=normalize(vNormal);vec3 l=normalize(vec3(-0.42,0.62,1.0));vec3 v=normalize(vec3(0.0,0.0,5.25)-vWorld);float d=max(dot(n,l),0.0);float s=pow(max(dot(reflect(-l,n),v),0.0),34.0)*uShine;float rim=pow(1.0-max(dot(n,v),0.0),2.25);vec3 c=uColor*(0.16+0.34*d)+vec3(0.68,0.76,0.98)*s*0.72+uRim*rim*0.68+uEmissive;gl_FragColor=vec4(c,uAlpha);}'
  ].join('\n');
  function compile(type,source){const s=gl.createShader(type);gl.shaderSource(s,source);gl.compileShader(s);if(!gl.getShaderParameter(s,gl.COMPILE_STATUS)){const error=gl.getShaderInfoLog(s)||'shader compile failed';gl.deleteShader(s);throw new Error(error)}return s}
  const vs=compile(gl.VERTEX_SHADER,vertexSource),fs=compile(gl.FRAGMENT_SHADER,fragmentSource);program=gl.createProgram();gl.attachShader(program,vs);gl.attachShader(program,fs);gl.linkProgram(program);gl.deleteShader(vs);gl.deleteShader(fs);if(!gl.getProgramParameter(program,gl.LINK_STATUS))throw new Error(gl.getProgramInfoLog(program)||'program link failed');
  const loc={p:gl.getAttribLocation(program,'aPosition'),n:gl.getAttribLocation(program,'aNormal'),mvp:gl.getUniformLocation(program,'uMVP'),model:gl.getUniformLocation(program,'uModel'),color:gl.getUniformLocation(program,'uColor'),rim:gl.getUniformLocation(program,'uRim'),emissive:gl.getUniformLocation(program,'uEmissive'),alpha:gl.getUniformLocation(program,'uAlpha'),shine:gl.getUniformLocation(program,'uShine')};
  function meshData(pos,normals,idx){const p=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,p);gl.bufferData(gl.ARRAY_BUFFER,new Float32Array(pos),gl.STATIC_DRAW);const n=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,n);gl.bufferData(gl.ARRAY_BUFFER,new Float32Array(normals),gl.STATIC_DRAW);const i=gl.createBuffer();gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER,i);gl.bufferData(gl.ELEMENT_ARRAY_BUFFER,new Uint16Array(idx),gl.STATIC_DRAW);return{p,n,i,count:idx.length}}
  function sphereData(rows=18,cols=26){const p=[],n=[],idx=[];for(let y=0;y<=rows;y++){const t=y*Math.PI/rows;for(let x=0;x<=cols;x++){const a=x*Math.PI*2/cols,nx=Math.sin(t)*Math.cos(a),ny=Math.cos(t),nz=Math.sin(t)*Math.sin(a);p.push(nx,ny,nz);n.push(nx,ny,nz)}}for(let y=0;y<rows;y++)for(let x=0;x<cols;x++){const a=y*(cols+1)+x,b=a+cols+1;idx.push(a,a+1,b,b,a+1,b+1)}return meshData(p,n,idx)}
  function cross(a,b){return[a[1]*b[2]-a[2]*b[1],a[2]*b[0]-a[0]*b[2],a[0]*b[1]-a[1]*b[0]]}
  function norm(v){const d=Math.hypot(v[0],v[1],v[2])||1;return[v[0]/d,v[1]/d,v[2]/d]}
  function bezier(q,t){const u=1-t,a=u*u*u,b=3*u*u*t,c=3*u*t*t,d=t*t*t;return[0,1,2].map(k=>a*q[0][k]+b*q[1][k]+c*q[2][k]+d*q[3][k])}
  function tangent(q,t){const u=1-t;return norm([0,1,2].map(k=>3*u*u*(q[1][k]-q[0][k])+6*u*t*(q[2][k]-q[1][k])+3*t*t*(q[3][k]-q[2][k])))}
  function tubeData(q,radius,steps=24,sides=7){const p=[],n=[],idx=[];for(let s=0;s<=steps;s++){const t=s/steps,c=bezier(q,t),tan=tangent(q,t),ref=Math.abs(tan[1])>.86?[0,0,1]:[0,1,0],u=norm(cross(tan,ref)),v=norm(cross(tan,u)),r=radius*(.06+.94*Math.pow(1-t,.72));for(let k=0;k<=sides;k++){const a=k*Math.PI*2/sides,rx=Math.cos(a),ry=Math.sin(a),nn=norm([u[0]*rx+v[0]*ry,u[1]*rx+v[1]*ry,u[2]*rx+v[2]*ry]);p.push(c[0]+nn[0]*r,c[1]+nn[1]*r,c[2]+nn[2]*r);n.push(...nn)}}for(let s=0;s<steps;s++)for(let k=0;k<sides;k++){const a=s*(sides+1)+k,b=a+sides+1;idx.push(a,a+1,b,b,a+1,b+1)}return meshData(p,n,idx)}
  const sphere=sphereData(),tubes=[];
  function addTube(q,r){const m=tubeData(q,r);tubes.push(m);return m}
  addTube([[.43,.54,.03],[.72,.59,.06],[.68,.89,.08],[.83,1.00,.06]],.105);
  addTube([[-.43,.54,.03],[-.72,.60,.06],[-.69,.91,.08],[-.84,1.00,.06]],.105);
  addTube([[.58,.07,-.02],[.95,.25,-.04],[.82,-.14,.03],[.62,-.26,.10]],.065);
  addTube([[-.58,.07,-.02],[-.96,.27,-.04],[-.84,-.16,.03],[-.62,-.27,.10]],.065);
  const tails=[
   [[-.20,-.65,.05],[-.55,-.86,.28],[-.28,-1.22,.14],[-.62,-1.49,.05]],
   [[-.06,-.72,.13],[-.20,-1.06,.26],[.15,-1.23,.18],[.08,-1.50,.09]],
   [[.12,-.70,.02],[.48,-.92,-.08],[.23,-1.26,.02],[.55,-1.48,.05]],
   [[.26,-.63,-.07],[.62,-.88,-.21],[.60,-1.18,-.05],[.84,-1.38,-.02]],
   [[-.27,-.61,-.06],[-.64,-.83,-.18],[-.56,-1.13,-.02],[-.78,-1.36,.02]],
   [[.02,-.80,-.15],[.27,-1.03,-.31],[-.10,-1.28,-.17],[-.22,-1.46,-.07]]
  ];
  tails.forEach((q,i)=>addTube(q,i===1||i===5?.085:.074));
  const closedEyes=[addTube([[-.46,.23,.70],[-.42,.15,.72],[-.31,.15,.72],[-.26,.23,.70]],.022),addTube([[.26,.23,.70],[.31,.15,.72],[.42,.15,.72],[.46,.23,.70]],.022)];
  function ident(){return new Float32Array([1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1])}
  function mul(a,b){const o=new Float32Array(16);for(let c=0;c<4;c++)for(let r=0;r<4;r++)o[c*4+r]=a[r]*b[c*4]+a[4+r]*b[c*4+1]+a[8+r]*b[c*4+2]+a[12+r]*b[c*4+3];return o}
  function trans(x,y,z){const m=ident();m[12]=x;m[13]=y;m[14]=z;return m}
  function scaleM(x,y,z){const m=ident();m[0]=x;m[5]=y;m[10]=z;return m}
  function rx(a){const c=Math.cos(a),s=Math.sin(a);return new Float32Array([1,0,0,0,0,c,s,0,0,-s,c,0,0,0,0,1])}
  function ry(a){const c=Math.cos(a),s=Math.sin(a);return new Float32Array([c,0,-s,0,0,1,0,0,s,0,c,0,0,0,0,1])}
  function rz(a){const c=Math.cos(a),s=Math.sin(a);return new Float32Array([c,s,0,0,-s,c,0,0,0,0,1,0,0,0,0,1])}
  function projection(aspect){const f=1/Math.tan(40*Math.PI/360),near=.1,far=60,o=new Float32Array(16);o[0]=f/aspect;o[5]=f;o[10]=(far+near)/(near-far);o[11]=-1;o[14]=(2*far*near)/(near-far);return o}
  function transform(pos,rot,scl){let m=trans(...pos);m=mul(m,ry(rot[1]));m=mul(m,rx(rot[0]));m=mul(m,rz(rot[2]));return mul(m,scaleM(...scl))}
  function draw(g,root,vp,pos,scl,color,rim,emission,shine=.35,alpha=1,rot=[0,0,0]){const model=mul(root,transform(pos,rot,scl)),mvp=mul(vp,model);gl.uniformMatrix4fv(loc.model,false,model);gl.uniformMatrix4fv(loc.mvp,false,mvp);gl.uniform3fv(loc.color,color);gl.uniform3fv(loc.rim,rim);gl.uniform3fv(loc.emissive,emission);gl.uniform1f(loc.shine,shine);gl.uniform1f(loc.alpha,alpha);gl.bindBuffer(gl.ARRAY_BUFFER,g.p);gl.enableVertexAttribArray(loc.p);gl.vertexAttribPointer(loc.p,3,gl.FLOAT,false,0,0);gl.bindBuffer(gl.ARRAY_BUFFER,g.n);gl.enableVertexAttribArray(loc.n);gl.vertexAttribPointer(loc.n,3,gl.FLOAT,false,0,0);gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER,g.i);gl.drawElements(gl.TRIANGLES,g.count,gl.UNSIGNED_SHORT,0)}
  function resize(){const r=canvas.getBoundingClientRect(),dpr=Math.min(window.devicePixelRatio||1,1.25),w=Math.max(1,Math.round(r.width*dpr)),h=Math.max(1,Math.round(r.height*dpr));if(canvas.width!==w||canvas.height!==h){canvas.width=w;canvas.height=h;gl.viewport(0,0,w,h);dirty=true}schedule()}
  function schedule(){if(!disposed&&!rafId&&document.visibilityState!=='hidden')rafId=requestAnimationFrame(frame)}
  function burst(){const now=performance.now();particles=[];for(let i=0;i<16;i++)particles.push({a:i/16*Math.PI*2+(Math.random()-.5)*.28,b:(Math.random()-.5)*1.35,start:now,life:reduceMotion?120:760});dirty=true;schedule()}
  function frame(now){rafId=0;if(disposed||document.visibilityState==='hidden')return;if(reduceMotion&&!dirty&&!particles.length)return;if(!reduceMotion&&now-lastFrame<33){schedule();return}lastFrame=now;dirty=false;gl.clearColor(0,0,0,0);gl.clear(gl.COLOR_BUFFER_BIT|gl.DEPTH_BUFFER_BIT);gl.enable(gl.DEPTH_TEST);gl.enable(gl.BLEND);gl.blendFunc(gl.SRC_ALPHA,gl.ONE_MINUS_SRC_ALPHA);gl.useProgram(program);
   const w=canvas.width||1,h=canvas.height||1,proj=projection(w/h),view=trans(0,0,-5.25),vp=mul(proj,view),state=host.dataset.state||'online',t=reduceMotion?0:now*.001,pose=rotation(),bob=reduceMotion?0:Math.sin(t*1.9)*.035;
   const root=mul(trans(0,bob,0),mul(ry(pose.yaw+(reduceMotion?0:Math.sin(t*.68)*.045)),mul(rx(pose.pitch+(reduceMotion?0:Math.sin(t*.54)*.022)),scaleM(.78,.78,.78))));
   let rim=[.24,.31,.52],glow=[.025,.04,.085],eye=[.78,.84,1],eyeGlow=[.42,.52,.9];
   if(state==='checking'){rim=[.40,.28,.92];glow=[.11,.045,.30];eye=[.83,.80,1];eyeGlow=[.48,.37,1]}
   if(state==='error'){rim=[.95,.055,.09];glow=[.32,.006,.018];eye=[1,.20,.24];eyeGlow=[1,.035,.06]}
   if(state==='sleep'){rim=[.13,.16,.25];glow=[.012,.018,.04];eye=[.38,.44,.60];eyeGlow=[.16,.20,.34]}
   if(state==='reacting'){rim=[.48,.58,.98];glow=[.05,.09,.20];eye=[.9,.94,1];eyeGlow=[.70,.78,1]}
   const body=[.018,.021,.033],highlight=[.10,.13,.20];
   draw(sphere,root,vp,[0,-.50,.01],[.35,.43,.30],body,rim,glow,.82,1);
   draw(sphere,root,vp,[0,.24,0],[.77,.69,.64*(1+(reduceMotion?0:Math.sin(t*1.9)*.012))],body,rim,glow,.92,1);
   draw(sphere,root,vp,[0,-.30,.08],[.23,.20,.25],body,rim,glow,.70,.96);
   tubes.slice(0,4).forEach(g=>draw(g,root,vp,[0,0,0],[1,1,1],body,highlight,glow,.68,.92));
   tails.forEach((_,i)=>draw(tubes[4+i],root,vp,[0,0,0],[1,1,1],[.014,.017,.028],rim,glow,.78,.94,[Math.sin(t*1.3+i*.8)*.04,0,Math.sin(t*1.1+i)*.035]));
   if(state==='sleep'||state==='checking'){closedEyes.forEach(g=>draw(g,root,vp,[0,0,0],[1,1,1],eye,rim,eyeGlow,.58,.98))}
   else{[-1,1].forEach(side=>{const x=side*.29,rot=[0,0,side*.10];draw(sphere,root,vp,[x,.22,.64],[.205,.285,.075],eyeGlow,rim,eyeGlow,.25,.30,rot);draw(sphere,root,vp,[x,.22,.685],[.133,.205,.078],eye,rim,eyeGlow,.92,1,rot);draw(sphere,root,vp,[x-side*.035,.28,.746],[.026,.052,.018],[1,1,1],[1,1,1],[.82,.86,1],.2,.9,rot)})}
   const alive=[];particles.forEach(p=>{const age=(now-p.start)/p.life;if(age>=1)return;alive.push(p);const r=.52+age*.72,x=Math.cos(p.a)*r,y=Math.sin(p.a)*r*.75+p.b*.24,z=.2+Math.sin(p.a*1.7)*.26+age*.18,fade=1-age,size=.024*fade+.004;draw(sphere,root,vp,[x,y,z],[size,size,size],[.70,.78,1],[.72,.82,1],[.58,.68,1],.2,fade*.95)});particles=alive;
   if(!reduceMotion||particles.length)schedule()
  }
  canvas.addEventListener('webglcontextlost',e=>{e.preventDefault();disposed=true;if(rafId)cancelAnimationFrame(rafId);host.dataset.renderer='fallback';},{passive:false});
  addEventListener('resize',resize,{passive:true});document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='hidden'){if(rafId)cancelAnimationFrame(rafId);rafId=0}else{dirty=true;schedule()}});
  host.dataset.renderer='webgl';host.dataset.model='procedural-webgl';host.dataset.meshCount=String(1+tubes.length+closedEyes.length);resize();dirty=true;schedule();
  return{burst,refresh(){dirty=true;schedule()},destroy(){disposed=true;if(rafId)cancelAnimationFrame(rafId)}}
 }catch(error){host.dataset.renderer='fallback';canvas.dataset.error=String(error&&error.message||error).slice(0,120);return null}
}
const voidlingRenderer=createVoidlingRenderer(widget,()=>({yaw:modelYaw,pitch:modelPitch}));
let labelTimer=0;
const stateLabels={online:'پنل آنلاین',checking:'در حال بررسی',error:'نیازمند بررسی',sleep:'در حال استراحت',reacting:'واکنش به تعامل'};
function updateVisualState(){const state=panelState==='error'?'error':panelState==='checking'?'checking':reactionUntil>performance.now()?'reacting':sleeping?'sleep':'online';widget.dataset.state=state;const l=document.getElementById('voidling-label');if(l)l.textContent=stateLabels[state];if(voidlingRenderer)voidlingRenderer.refresh()}
function setState(state,label){if(state==='error'||state==='checking'||state==='online'){panelState=state;sleeping=false;if(state!=='online')reactionUntil=0}else if(state==='sleep'&&panelState==='online'){sleeping=true}else if(state==='reacting'&&panelState==='online'&&!sleeping){reactionUntil=performance.now()+680}updateVisualState()}
function readStatus(){
 const statusEl=document.getElementById('status'),area=document.getElementById('dashboardComponentStatus'),services=area?[...area.querySelectorAll('.dashboard-component')]:[];
 const textOf=el=>el?((el.innerText||el.textContent||'')+' '+(el.getAttribute('data-status')||'')+' '+(typeof el.className==='string'?el.className:'')):'';
 const all=[statusEl,...services].filter(Boolean),errorRe=/(?:خطا|ناموفق|متوقف|نصب‌نشده|\b(?:offline|failed|error)\b)/i,loadingRe=/(?:در حال بررسی|در حال دریافت|بارگذاری|\b(?:checking|loading|pending)\b)/i;
 if(all.some(el=>errorRe.test(textOf(el)))){setState('error','نیازمند بررسی');return}
 if(all.some(el=>el.getAttribute('aria-busy')==='true'||el.matches('[data-loading="true"],.loading,.is-loading,.spinner'))||all.some(el=>loadingRe.test(textOf(el)))){setState('checking','در حال بررسی');return}
 const healthyRe=/(?:\bonline\b|healthy|running|active|فعال|آنلاین|در حال اجرا)/i;
 const healthyServices=services.length>0&&services.every(el=>healthyRe.test(textOf(el))&&!errorRe.test(textOf(el)));
 if(healthyServices||statusEl&&healthyRe.test(textOf(statusEl))){panelState='online';if(!sleeping)updateVisualState();else updateVisualState();return}
}
const observer=new MutationObserver(readStatus);['status','dashboardComponentStatus'].forEach(id=>{const el=document.getElementById(id);if(el)observer.observe(el,{subtree:true,childList:true,characterData:true,attributes:true,attributeFilter:['class','data-status','data-loading','aria-busy']})});setTimeout(readStatus,900);setInterval(readStatus,15000);
let drag=null,moved=false,movedByRotation=false,soundEnabled=false,audioCtx=null,idleSleepTimer=0,panelState='online',sleeping=false,reactionUntil=0;
try{soundEnabled=localStorage.getItem('voidling-sound')==='on'}catch(e){}
function playTone(kind='tap'){if(!soundEnabled)return;try{audioCtx=audioCtx||new(window.AudioContext||window.webkitAudioContext)();if(audioCtx.state==='suspended')audioCtx.resume();const now=audioCtx.currentTime,osc=audioCtx.createOscillator(),gain=audioCtx.createGain();osc.type='sine';osc.frequency.setValueAtTime(kind==='drop'?740:kind==='hello'?560:420,now);osc.frequency.exponentialRampToValueAtTime(kind==='drop'?980:kind==='hello'?820:620,now+.11);gain.gain.setValueAtTime(.0001,now);gain.gain.exponentialRampToValueAtTime(.045,now+.018);gain.gain.exponentialRampToValueAtTime(.0001,now+.18);osc.connect(gain);gain.connect(audioCtx.destination);osc.start(now);osc.stop(now+.2)}catch(e){}}
function triggerReaction(){if(panelState==='error'||panelState==='checking'){if(voidlingRenderer)voidlingRenderer.burst();return}sleeping=false;reactionUntil=performance.now()+680;updateVisualState();if(voidlingRenderer)voidlingRenderer.burst();clearTimeout(widget._reactionStateTimer);widget._reactionStateTimer=setTimeout(updateVisualState,710)}
function setRotationMode(enabled){rotationMode=Boolean(enabled);widget.dataset.rotationMode=rotationMode?'on':'off';widget.style.cursor=rotationMode?'crosshair':'grab';if(voidlingRenderer)voidlingRenderer.refresh()}
function restoreRotation(){try{const p=JSON.parse(localStorage.getItem('voidling-rotation')||'null');if(p&&Number.isFinite(p.yaw)&&Number.isFinite(p.pitch)){modelYaw=p.yaw;modelPitch=clamp(p.pitch,-1.15,1.15);if(voidlingRenderer)voidlingRenderer.refresh()}}catch(e){}}
function saveRotation(){try{localStorage.setItem('voidling-rotation',JSON.stringify({yaw:modelYaw,pitch:modelPitch}))}catch(e){}}
function scheduleIdleSleep(){clearTimeout(idleSleepTimer);idleSleepTimer=setTimeout(()=>{if(panelState==='online'&&reactionUntil<=performance.now()){sleeping=true;updateVisualState()}},45000)}
function wakeFromIdle(){sleeping=false;updateVisualState();scheduleIdleSleep()}
function clamp(n,min,max){return Math.max(min,Math.min(max,n))}
function restorePosition(){try{const p=JSON.parse(localStorage.getItem('voidling-position')||'null');if(p&&Number.isFinite(p.x)&&Number.isFinite(p.y)){widget.style.left=clamp(p.x,0,innerWidth-widget.offsetWidth)+'px';widget.style.top=clamp(p.y,0,innerHeight-widget.offsetHeight)+'px';widget.style.right='auto';widget.style.bottom='auto'}}catch(e){}}
function savePosition(){try{localStorage.setItem('voidling-position',JSON.stringify({x:widget.offsetLeft,y:widget.offsetTop}))}catch(e){}}
widget.addEventListener('pointerdown',e=>{if(e.button!==0&&e.pointerType!=='touch')return;wakeFromIdle();drag={id:e.pointerId,startX:e.clientX,startY:e.clientY,left:widget.getBoundingClientRect().left,top:widget.getBoundingClientRect().top,rotate:rotationMode||e.altKey,yaw:modelYaw,pitch:modelPitch};moved=false;movedByRotation=false;widget.setPointerCapture?.(e.pointerId);widget.style.cursor=drag.rotate?'crosshair':'grabbing';e.preventDefault()});
widget.addEventListener('pointermove',e=>{if(!drag||drag.id!==e.pointerId)return;const dx=e.clientX-drag.startX,dy=e.clientY-drag.startY;if(Math.abs(dx)>5||Math.abs(dy)>5)moved=true;if(!moved)return;if(drag.rotate){movedByRotation=true;modelYaw=drag.yaw+dx*.014;modelPitch=clamp(drag.pitch+dy*.01,-1.15,1.15);if(voidlingRenderer)voidlingRenderer.refresh();return}const x=clamp(drag.left+dx,4,innerWidth-widget.offsetWidth-4),y=clamp(drag.top+dy,4,innerHeight-widget.offsetHeight-4);widget.style.left=x+'px';widget.style.top=y+'px';widget.style.right='auto';widget.style.bottom='auto'});
function finishDrag(e){if(!drag||drag.id!==e.pointerId)return;const wasMoved=moved,wasRotated=Boolean(drag.rotate&&movedByRotation);drag=null;widget.style.cursor=rotationMode?'crosshair':'grab';if(wasMoved){if(wasRotated)saveRotation();else savePosition();widget.dataset.justDragged='1';widget.classList.add('is-reacting');triggerReaction();playTone('drop');const r=widget.getBoundingClientRect();addRipple(r.left+r.width/2,r.top+r.height/2);setTimeout(()=>{widget.dataset.justDragged='0';widget.classList.remove('is-reacting')},500)}}
widget.addEventListener('pointerup',finishDrag);widget.addEventListener('pointercancel',finishDrag);
addEventListener('resize',()=>{if(widget.style.left){widget.style.left=clamp(widget.offsetLeft,4,innerWidth-widget.offsetWidth-4)+'px';widget.style.top=clamp(widget.offsetTop,4,innerHeight-widget.offsetHeight-4)+'px';savePosition()}},{passive:true});
restorePosition();restoreRotation();scheduleIdleSleep();
widget.addEventListener('click',()=>{if(widget.dataset.justDragged==='1')return;wakeFromIdle();triggerReaction();widget.classList.remove('is-reacting');void widget.offsetWidth;widget.classList.add('is-reacting','show-label');playTone('tap');clearTimeout(labelTimer);labelTimer=setTimeout(()=>widget.classList.remove('show-label','is-reacting'),3200);const rect=widget.getBoundingClientRect();addRipple(rect.left+rect.width/2,rect.top+rect.height/2);const existing=document.getElementById('voidling-status-popover');if(existing){existing.remove();return}const pop=document.createElement('div');pop.id='voidling-status-popover';pop.setAttribute('role','status');pop.style.cssText='position:fixed;right:18px;bottom:120px;z-index:61;max-width:min(280px,calc(100vw - 36px));padding:13px 15px;border:1px solid rgba(205,215,240,.24);border-radius:14px;background:rgba(7,9,14,.96);color:#e8edf9;box-shadow:0 12px 40px #0009;backdrop-filter:blur(14px);font:12px/1.9 Vazirmatn,Tahoma,sans-serif';const state=widget.dataset.state,services=[...document.querySelectorAll('#dashboardComponentStatus>*')],healthy=services.filter(el=>!/خطا|ناموفق|متوقف|نصب‌نشده|offline|failed|error/i.test(el.innerText||'' )).length,totalUsers=document.getElementById('total')?.innerText?.trim()||'—',activeUsers=document.getElementById('active')?.innerText?.trim()||'—';pop.innerHTML='<strong>Voidling · وضعیت پنل</strong><div style="color:#bfc9dc;margin-top:4px">'+(state==='error'?'برخی بررسی‌ها نیازمند توجه هستند.':state==='checking'?'وضعیت اجزای پنل در حال بررسی است.':'پنل در دسترس است.')+'</div><div style="margin-top:6px;color:#cbd4e5">سرویس‌ها: '+healthy+'/'+services.length+'</div><div style="color:#cbd4e5">کاربران: '+totalUsers+' · فعال: '+activeUsers+'</div><button type="button" style="margin-top:9px;padding:5px 10px;min-height:30px;border:1px solid #353c4a;border-radius:8px;background:#141820;color:#e8edf9" id="voidling-dismiss">بستن</button>';document.body.appendChild(pop);document.getElementById('voidling-dismiss').addEventListener('click',()=>pop.remove());
const soundBtn=document.createElement('button');soundBtn.type='button';soundBtn.id='voidling-sound-toggle';soundBtn.style.cssText='margin:9px 0 0 6px;padding:5px 10px;min-height:30px;border:1px solid #353c4a;border-radius:8px;background:#141820;color:#e8edf9;font:12px Vazirmatn,Tahoma,sans-serif';soundBtn.textContent=soundEnabled?'🔊 صدا روشن':'🔇 صدا خاموش';soundBtn.setAttribute('aria-pressed',String(soundEnabled));document.getElementById('voidling-dismiss').before(soundBtn);soundBtn.addEventListener('click',()=>{soundEnabled=!soundEnabled;try{localStorage.setItem('voidling-sound',soundEnabled?'on':'off')}catch(e){}soundBtn.textContent=soundEnabled?'🔊 صدا روشن':'🔇 صدا خاموش';soundBtn.setAttribute('aria-pressed',String(soundEnabled));if(soundEnabled)playTone('hello')});
const rotateBtn=document.createElement('button');rotateBtn.type='button';rotateBtn.id='voidling-rotation-toggle';rotateBtn.style.cssText='margin:9px 0 0 6px;padding:5px 10px;min-height:30px;border:1px solid #353c4a;border-radius:8px;background:#141820;color:#e8edf9;font:12px Vazirmatn,Tahoma,sans-serif';rotateBtn.textContent=rotationMode?'چرخش مدل روشن':'چرخش مدل';rotateBtn.setAttribute('aria-pressed',String(rotationMode));soundBtn.after(rotateBtn);rotateBtn.addEventListener('click',()=>{setRotationMode(!rotationMode);rotateBtn.textContent=rotationMode?'چرخش مدل روشن':'چرخش مدل';rotateBtn.setAttribute('aria-pressed',String(rotationMode))});
const hint=document.createElement('div');hint.textContent=rotationMode?'حالت چرخش روشن است؛ Voidling را بکش تا مدل بچرخد.':'برای جابه‌جایی بکش؛ برای چرخش مدل، «چرخش مدل» یا Alt را نگه دار.';hint.style.cssText='margin-top:7px;color:#8994aa;font-size:10px';pop.appendChild(hint);
setTimeout(()=>{if(pop.isConnected)pop.remove()},6500)});
})();
</script>"""

LOGIN = LOGIN.replace("<style>html,body,button,input,select,textarea{font-family:'Vazirmatn',Tahoma,system-ui,sans-serif}</style></head>", ABYSS_THEME_CSS + ABYSS_THEME_POLISH_CSS + ABYSS_LAYOUT_REPAIR_CSS + "<style>html,body,button,input,select,textarea{font-family:'Vazirmatn',Tahoma,system-ui,sans-serif}</style></head>").replace("</body>", ABYSS_THEME_JS + ABYSS_LAYOUT_REPAIR_JS + ABYSS_FINAL_LAYOUT_CSS + "</body>")
DASH = DASH.replace("<style>html,body,button,input,select,textarea{font-family:'Vazirmatn',Tahoma,system-ui,sans-serif}</style></head>", ABYSS_THEME_CSS + ABYSS_THEME_POLISH_CSS + ABYSS_VOIDLING_CSS + ABYSS_LAYOUT_REPAIR_CSS + "<style>html,body,button,input,select,textarea{font-family:'Vazirmatn',Tahoma,system-ui,sans-serif}</style></head>").replace("</body>", ABYSS_THEME_JS + ABYSS_VOIDLING_JS + ABYSS_LAYOUT_REPAIR_JS + ABYSS_FINAL_LAYOUT_CSS + "</body>")

@app.get("/dashboard.js",response_class=PlainTextResponse)
async def dashboard_js():
    return PlainTextResponse(DASH_JS,media_type="application/javascript",headers={"Cache-Control":"no-store"})

LOGO_PATH = Path(__file__).with_name("abyss-tunnel-logo.jpg")
@app.get("/brand/abyss-tunnel-logo.jpg",include_in_schema=False)
async def abyss_brand_logo():
    return FileResponse(LOGO_PATH,media_type="image/jpeg",headers={"Cache-Control":"public, max-age=86400"})

@app.get("/",response_class=HTMLResponse)
async def home(r:Request):
    if r.session.get("admin") is True or r.session.get("reseller_id"):
        return HTMLResponse(DASH,headers={"Cache-Control":"no-store, max-age=0","Pragma":"no-cache","Vary":"Cookie"})
    return RedirectResponse("/login",303)
@app.get("/login",response_class=HTMLResponse)
async def login_page(r:Request):
    t=secrets.token_urlsafe(24); r.session["login_csrf"]=t
    return HTMLResponse(LOGIN.replace("{{ERROR}}","").replace("{{CSRF}}",t))
@app.post("/login")
async def login(r:Request,username:str=Form(...),password:str=Form(...)):
    f=await r.form(); a=str(f.get("csrf_token","")); b=str(r.session.get("login_csrf",""))
    if not a or not b or not hmac.compare_digest(a,b):
        token=secrets.token_urlsafe(24); r.session["login_csrf"]=token
        return HTMLResponse(LOGIN.replace("{{ERROR}}","نشست منقضی شده؛ دوباره تلاش کن.").replace("{{CSRF}}",token),status_code=403)
    ip=r.client.host if r.client else "unknown"
    if not rate_check(r,"login:"+ip):
        token=secrets.token_urlsafe(24); r.session["login_csrf"]=token
        return HTMLResponse(LOGIN.replace("{{ERROR}}","تلاش‌های زیادی انجام شده؛ پنج دقیقه صبر کن.").replace("{{CSRF}}",token),status_code=429)
    if len(username)>64 or len(password)>256:
        row=None; account_type="admin"
    else:
        with db() as c:
            row=c.execute("SELECT id,username,password_hash,role,enabled,password_changed_at FROM panel_admins WHERE username=?",(username.strip(),)).fetchone()
            account_type="admin"
            if not row:
                row=c.execute("SELECT id,password_hash,enabled FROM resellers WHERE username=?",(username.strip(),)).fetchone()
                account_type="reseller"
    if not row or not row["enabled"] or not verify_password(password,row["password_hash"]):
        event("WARNING","Rejected administrator sign-in attempt.")
        token=secrets.token_urlsafe(24); r.session["login_csrf"]=token
        return HTMLResponse(LOGIN.replace("{{ERROR}}","نام کاربری یا رمز عبور اشتباه است.").replace("{{CSRF}}",token),status_code=401)
    r.session.clear(); r.session["csrf"]=secrets.token_urlsafe(32); r.session["remember_me"]=str(f.get("remember_me","")).strip().lower() in {"on","true","1","yes"}
    if account_type=="admin":
        r.session["admin"]=True; r.session["admin_id"]=row["id"]; r.session["admin_username"]=row["username"]; r.session["admin_role"]=row["role"]; r.session["admin_password_changed_at"]=row["password_changed_at"]
        event("INFO",f"Administrator signed in as {row['username']} ({row['role']}).")
    else:
        r.session["reseller_id"]=row["id"]; event("INFO",f"Reseller {username!r} signed in.")
    return RedirectResponse("/",303)
@app.get("/logout")
async def logout(r:Request): r.session.clear(); return RedirectResponse("/login",303)
@app.get("/api/overview")
async def overview(r:Request):
    require_admin(r); owner=owner_id_for(r)
    with db() as c:
        if owner is None:
            total=c.execute("SELECT COUNT(*) n FROM clients").fetchone()["n"]; active=c.execute("SELECT COUNT(*) n FROM clients WHERE enabled=1").fetchone()["n"]
            children=[dict(x) for x in c.execute("SELECT id,username,quota_bytes,enabled,created_at,parent_id FROM resellers ORDER BY created_at DESC")]
        else:
            total=c.execute("SELECT COUNT(*) n FROM clients WHERE owner_id=?",(owner,)).fetchone()["n"]; active=c.execute("SELECT COUNT(*) n FROM clients WHERE owner_id=? AND enabled=1",(owner,)).fetchone()["n"]
            children=[dict(x) for x in c.execute("SELECT id,username,quota_bytes,enabled,created_at,parent_id FROM resellers WHERE parent_id=? ORDER BY created_at DESC",(owner,))]
        events=[dict(x) for x in c.execute("SELECT at,level,message FROM events ORDER BY id DESC LIMIT 8")] if owner is None else []
    for child in children:
        child["allocated_bytes"]=reseller_allocated_for(child["id"])
        child["remaining_bytes"]=child["quota_bytes"]-child["allocated_bytes"]
    remaining=None if owner is None else reseller_remaining(owner)
    return {"csrf":r.session.get("csrf",""),"role":"root" if is_root(r) else ("reseller" if not r.session.get("admin") else r.session.get("admin_role","admin")),"user":{"username":r.session.get("admin_username", "reseller" if not r.session.get("admin") else "admin"),"role":r.session.get("admin_role","owner") if r.session.get("admin") else "reseller"},"remaining_bytes":remaining,"total":total,"active":active,"clients":get_clients(owner_id=owner,scoped=owner is not None),"resellers":children,"events":events,"xray":{"installed":Path(XRAY_BIN).exists(),"running":bool(xray_proc and xray_proc.poll() is None)}}
@app.get("/api/settings")
async def read_settings(r:Request):
    require_admin(r)
    flags=get_profile_flags()
    return {"profiles":[{"key":p["key"],"label":p["label"],"enabled":flags[p["key"]],"protocol":p.get("protocol","vless"),"network":p.get("network","—"),"path":p.get("path","—"),"mode":p.get("mode"),"port":p.get("port"),"experimental":bool(p.get("experimental",False))} for p in PROFILES]}

@app.patch("/api/settings/profiles")
async def update_profile_settings(r:Request):
    require_role(r,"owner","admin"); require_csrf(r); body=await r.json()
    profiles=body.get("profiles") if isinstance(body,dict) else None
    keys={p["key"] for p in PROFILES}
    if not isinstance(profiles,dict) or not profiles or set(profiles)-keys or any(not isinstance(v,bool) for v in profiles.values()):
        raise HTTPException(422,"profiles must contain supported profile keys and boolean values")
    current=get_profile_flags()
    updated={**current,**profiles}
    if not any(updated.values()): raise HTTPException(422,"At least one connection profile must remain enabled")
    with db() as c:
        previous={row["key"]:row["value"] for row in c.execute("SELECT key,value FROM settings WHERE key LIKE 'profile:%'")}
        for key,value in profiles.items():
            c.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",("profile:"+key,"1" if value else "0"))
    try:
        await start_xray()
    except Exception as e:
        with db() as c:
            for key in profiles:
                setting="profile:"+key
                if setting in previous: c.execute("UPDATE settings SET value=? WHERE key=?",(previous[setting],setting))
                else: c.execute("DELETE FROM settings WHERE key=?",(setting,))
        try: await start_xray()
        except Exception as restore_error: event("ERROR",f"Xray recovery after failed profile update also failed: {restore_error}")
        event("ERROR",f"Profile update rolled back because Xray update failed: {e}")
        raise HTTPException(503,"Profile settings were not saved because Xray could not apply the configuration")
    event("INFO","Updated enabled connection profiles.")
    return {"profiles":[{"key":p["key"],"label":p["label"],"enabled":updated[p["key"]],"protocol":p.get("protocol","vless"),"network":p.get("network","—"),"path":p.get("path","—"),"mode":p.get("mode"),"port":p.get("port"),"experimental":bool(p.get("experimental",False))} for p in PROFILES]}

@app.post("/api/clients")
async def create_client(r:Request):
    require_admin(r); require_csrf(r); b=await r.json(); name=valid_name(b.get("name")); note=b.get("note","")
    if not isinstance(note,str) or len(note)>300: raise HTTPException(422,"Note must be at most 300 characters")
    days=b.get("duration_days"); quota=b.get("quota_gb"); selected_profiles=b.get("profiles")
    known_profiles={p["key"] for p in PROFILES}
    if selected_profiles is not None and (not isinstance(selected_profiles,list) or not selected_profiles or any(not isinstance(k,str) or k not in known_profiles for k in selected_profiles) or len(set(selected_profiles))!=len(selected_profiles)):
        raise HTTPException(422,"profiles must be a non-empty list of supported profile keys")
    profile_keys=json.dumps(selected_profiles,separators=(",",":")) if selected_profiles is not None else None
    if days is not None and (not isinstance(days,(int,float)) or isinstance(days,bool) or not float(days).is_integer() or days<1 or days>3650): raise HTTPException(422,"duration_days must be a whole number from 1 to 3650")
    if quota is not None and (not isinstance(quota,(int,float)) or isinstance(quota,bool) or not 1<=quota<=100000): raise HTTPException(422,"quota_gb must be 1–100000")
    expires=(datetime.now(timezone.utc)+timedelta(days=int(days))).isoformat(timespec="seconds") if days is not None else None
    owner=owner_id_for(r); quota_bytes=int(float(quota)*1024**3) if quota is not None else None
    if owner is not None and quota_bytes is None:
        raise HTTPException(422,"Resellers must assign a finite quota to every client")
    cid,uid,token=str(uuid.uuid4()),str(uuid.uuid4()),secrets.token_urlsafe(32)
    with db() as c:
        # Serialize allocation checks and inserts to prevent concurrent requests
        # from spending the same remaining reseller quota twice.
        c.execute("BEGIN IMMEDIATE")
        if owner is not None:
            assert_reseller_chain_enabled(c,owner)
            parent=c.execute("SELECT quota_bytes FROM resellers WHERE id=?",(owner,)).fetchone()
            allocated=reseller_allocated(c,owner)
            if quota_bytes>int(parent["quota_bytes"])-allocated:
                raise HTTPException(422,"Client quota exceeds your remaining allocation")
        c.execute("INSERT INTO clients(id,name,client_uuid,sub_token,enabled,created_at,note,expires_at,quota_bytes,used_bytes,owner_id,profile_keys) VALUES(?,?,?,?,1,?,?,?,?,0,?,?)",(cid,name,uid,token,utc_now(),note.strip(),expires,quota_bytes,owner,profile_keys))
    try:
        await start_xray()
    except Exception as e:
        # Do not leave a client marked active when Xray rejected its config.
        with db() as c: c.execute("DELETE FROM clients WHERE id=?",(cid,))
        try: await start_xray()
        except Exception as restore_error: event("ERROR",f"Xray recovery after failed client creation also failed: {restore_error}")
        event("ERROR",f"Client creation rolled back because Xray update failed: {e}")
        raise HTTPException(503,"Client was not created because Xray could not apply the configuration")
    event("INFO",f"Created client {name!r} ({cid[:8]})."); return {"id":cid,"name":name,"enabled":True}
@app.patch("/api/clients/{cid}")
async def update_client(cid:str,r:Request):
    require_admin(r); require_csrf(r); require_client_access(r,cid); b=await r.json()
    allowed={"enabled","name","note","duration_days","quota_gb","profiles"}
    if not isinstance(b,dict) or not b or set(b)-allowed: raise HTTPException(422,"Provide supported client fields only")
    if "enabled" in b and not isinstance(b["enabled"],bool): raise HTTPException(422,"enabled must be true or false")
    if "name" in b: b["name"]=valid_name(b["name"])
    if "note" in b and (not isinstance(b["note"],str) or len(b["note"])>300): raise HTTPException(422,"Note must be at most 300 characters")
    if "duration_days" in b and b["duration_days"] is not None and (not isinstance(b["duration_days"],(int,float)) or isinstance(b["duration_days"],bool) or not float(b["duration_days"]).is_integer() or not 1<=b["duration_days"]<=3650): raise HTTPException(422,"duration_days must be a whole number from 1 to 3650, or null")
    if "quota_gb" in b and b["quota_gb"] is not None and (not isinstance(b["quota_gb"],(int,float)) or isinstance(b["quota_gb"],bool) or not 1<=b["quota_gb"]<=100000): raise HTTPException(422,"quota_gb must be 1–100000, or null")
    if "profiles" in b:
        known_profiles={p["key"] for p in PROFILES}; selected=b["profiles"]
        if not isinstance(selected,list) or not selected or any(not isinstance(k,str) or k not in known_profiles for k in selected) or len(set(selected))!=len(selected):
            raise HTTPException(422,"profiles must be a non-empty list of supported profile keys")
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        owner=owner_id_for(r)
        if owner is not None:
            assert_reseller_chain_enabled(c,owner)
        row=c.execute("SELECT * FROM clients WHERE id=?",(cid,)).fetchone()
        if not row: raise HTTPException(404,"Client not found")
        previous=dict(row)
        updates={}
        if "enabled" in b: updates["enabled"]=int(b["enabled"])
        if "name" in b: updates["name"]=b["name"]
        if "note" in b: updates["note"]=b["note"].strip()
        if "duration_days" in b:
            updates["expires_at"]=(datetime.now(timezone.utc)+timedelta(days=int(b["duration_days"]))).isoformat(timespec="seconds") if b["duration_days"] is not None else None
        if "quota_gb" in b: updates["quota_bytes"]=int(float(b["quota_gb"])*1024**3) if b["quota_gb"] is not None else None
        if "profiles" in b: updates["profile_keys"]=json.dumps(b["profiles"],separators=(",",":"))
        if not updates: raise HTTPException(422,"No fields to update")
        if owner is not None and "quota_bytes" in updates:
            new_quota=updates["quota_bytes"]
            if new_quota is None: raise HTTPException(422,"Reseller clients must have a finite quota")
            allocated=int(c.execute("SELECT COALESCE(SUM(quota_bytes),0) n FROM clients WHERE owner_id=? AND id<>?",(owner,cid)).fetchone()["n"] or 0)
            children=int(c.execute("SELECT COALESCE(SUM(quota_bytes),0) n FROM resellers WHERE parent_id=?",(owner,)).fetchone()["n"] or 0)
            parent=c.execute("SELECT quota_bytes FROM resellers WHERE id=?",(owner,)).fetchone()
            if allocated+children+new_quota>int(parent["quota_bytes"]): raise HTTPException(422,"Updated quota exceeds your remaining allocation")
        c.execute("UPDATE clients SET "+", ".join(f"{key}=?" for key in updates)+" WHERE id=?",(*updates.values(),cid))  # nosec B608: keys originate only from the explicit allowed-field mapping above
    if ("enabled" in updates and updates["enabled"] != previous["enabled"]) or "profile_keys" in updates:
        try:
            await start_xray()
        except Exception as e:
            rollback={key:previous[key] for key in ("enabled","profile_keys") if key in updates}
            if rollback:
                with db() as c: c.execute("UPDATE clients SET "+", ".join(f"{key}=?" for key in rollback)+" WHERE id=?",(*rollback.values(),cid))  # nosec B608: keys are restricted to fixed enabled/profile_keys fields
            try: await start_xray()
            except Exception as restore_error: event("ERROR",f"Xray recovery after failed client update also failed: {restore_error}")
            event("ERROR",f"Client update rolled back because Xray update failed: {e}")
            raise HTTPException(503,"Client settings were not changed because Xray could not apply the configuration")
    event("INFO",f"Updated client {cid[:8]}."); return {"ok":True}

@app.post("/api/clients/{cid}/reset-usage")
async def reset_client_usage(cid:str,r:Request):
    require_admin(r); require_csrf(r); require_client_access(r,cid)
    with db() as c:
        row=c.execute("SELECT name FROM clients WHERE id=?",(cid,)).fetchone()
        if not row: raise HTTPException(404,"Client not found")
    if Path(XRAY_BIN).exists() and xray_proc and xray_proc.poll() is None:
        try: apply_xray_stats(read_xray_stats())
        except Exception as e: raise HTTPException(503,"Could not synchronize live usage before resetting it") from e
    with db() as c: c.execute("UPDATE clients SET used_bytes=0 WHERE id=?",(cid,))
    event("INFO",f"Reset usage for client {row['name']!r} ({cid[:8]}).")
    return {"ok":True}
@app.delete("/api/clients/{cid}")
async def delete_client(cid:str,r:Request):
    require_admin(r); require_csrf(r); require_client_access(r,cid)
    with db() as c:
        row=c.execute("SELECT * FROM clients WHERE id=?",(cid,)).fetchone()
        if not row: raise HTTPException(404,"Client not found")
        previous=dict(row)
        c.execute("DELETE FROM clients WHERE id=?",(cid,))
    try:
        await start_xray()
    except Exception as e:
        with db() as c:
            c.execute("INSERT OR REPLACE INTO clients(id,name,client_uuid,sub_token,enabled,created_at,note,expires_at,quota_bytes,used_bytes,owner_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                      (previous["id"],previous["name"],previous["client_uuid"],previous["sub_token"],previous["enabled"],previous["created_at"],previous["note"],previous["expires_at"],previous["quota_bytes"],previous["used_bytes"],previous.get("owner_id")))
        try: await start_xray()
        except Exception as restore_error: event("ERROR",f"Xray recovery after failed client revocation also failed: {restore_error}")
        event("ERROR",f"Client revocation rolled back because Xray update failed: {e}")
        raise HTTPException(503,"Client was not revoked because Xray could not apply the configuration")
    event("INFO",f"Revoked client {cid[:8]}."); return {"ok":True}
def get_base_url(r=None):
    if BASE_URL: return BASE_URL
    if PUBLIC_DOMAIN: return "https://"+PUBLIC_DOMAIN
    if r: return f"{r.headers.get('x-forwarded-proto','https')}://{r.headers.get('x-forwarded-host') or r.headers.get('host','localhost')}"
    return "https://YOUR-RAILWAY-DOMAIN"

def active_subscription_client(token):
    if len(token)>100: raise HTTPException(404,"Not found")
    with db() as c: client=c.execute("SELECT * FROM clients WHERE sub_token=? AND enabled=1",(token,)).fetchone()
    if not client or not client_is_active(dict(client)):
        raise HTTPException(404,"Subscription not found, expired, or disabled")
    return dict(client)

def make_subscription_links(client, r):
    try: selected_profiles=json.loads(client.get("profile_keys") or "null")
    except (TypeError,ValueError): selected_profiles=None
    base=get_base_url(r)
    host=urlsplit(base).hostname or PUBLIC_DOMAIN or "YOUR-RAILWAY-DOMAIN"
    links=[]
    flags=get_profile_flags()
    for profile in PROFILES:
        if not flags[profile["key"]]: continue
        if selected_profiles is not None and profile["key"] not in selected_profiles: continue
        network,path,mode=profile["network"],profile["path"],profile["mode"]
        proto=profile.get("protocol","vless")
        label=profile.get("subscription_label",profile["key"].replace("_","-"))
        common=f"type={network}&security=tls&sni={host}&fp=chrome&host={host}&path={quote(path,safe='')}"
        if mode: common+=f"&mode={quote(mode,safe='')}"
        uid=client["client_uuid"]
        title=quote("abysstunnel-"+client["name"]+"-"+label)
        if proto=="vless":
            url=f"vless://{uid}@{host}:443?{common}&encryption=none#{title}"
        elif proto=="trojan":
            url=f"trojan://{uid}@{host}:443?{common}#{title}"
        elif proto=="vmess":
            vmess={"v":"2","ps":"abysstunnel-"+client["name"]+"-"+label,"add":host,"port":"443","id":uid,"aid":"0","scy":"auto","net":"ws","type":"none","host":host,"path":path,"tls":"tls","sni":host,"alpn":""}
            url="vmess://"+base64.b64encode(json.dumps(vmess,separators=(",",":")).encode()).decode()
        elif proto=="shadowsocks":
            ss_password=base64.b64encode(hashlib.sha256(uid.encode()).digest()[:16]).decode()
            combined_password=get_ss2022_server_password()+":"+ss_password
            # SIP022 requires the AEAD-2022 method and a percent-encoded server:user PSK pair.
            userinfo="2022-blake3-aes-128-gcm:"+quote(combined_password,safe="")
            plugin=quote("v2ray-plugin;tls;host="+host+";path="+path,safe="")
            url=f"ss://{userinfo}@{host}:443/?plugin={plugin}#{title}"
        else:
            continue
        links.append({"key":profile["key"],"label":profile["label"],"url":url})
    return links

def subscription_text(links):
    return base64.b64encode("\n".join(item["url"] for item in links).encode()).decode()

def subscription_userinfo(client):
    """Standard subscription metadata consumed by compatible clients."""
    used=max(0,int(client.get("used_bytes") or 0))
    quota=0 if client.get("quota_bytes") is None else max(0,int(client["quota_bytes"]))
    expire=0
    value=client.get("expires_at")
    if value:
        try:
            dt=datetime.fromisoformat(str(value).replace("Z","+00:00"))
            if dt.tzinfo is None: dt=dt.replace(tzinfo=timezone.utc)
            expire=max(0,int(dt.timestamp()))
        except (TypeError,ValueError,OverflowError):
            expire=0
    return f"upload=0; download={used}; total={quota}; expire={expire}"

def render_subscription_page(client, links, sub_url, qr_url, usage_history=None):
    usage_history=usage_history or []
    quota=client["quota_bytes"]
    used_bytes=max(0,int(client["used_bytes"] or 0))
    usage=used_bytes/1024**3
    quota_text="نامحدود" if quota is None else f"{quota/1024**3:.2f} GB"
    usage_pct=0 if quota is None or int(quota)<=0 else min(100,round(used_bytes/int(quota)*100))
    remaining_text="نامحدود" if quota is None else f"{max(0,int(quota)-used_bytes)/1024**3:.2f} GB"
    expiry_raw=client.get("expires_at")
    expiry=str(expiry_raw)[:10] if expiry_raw else "بدون انقضا"
    created_display=str(client.get("created_at") or "")[:10] or "—"
    profile_labels=[item["label"] for item in links]
    profile_summary="، ".join(profile_labels[:3]) + (f" و {len(profile_labels)-3} مورد دیگر" if len(profile_labels)>3 else "")
    cards="".join(
        '<div class="profile-choice" data-profile-choice="'+html_escape(item["key"],quote=True)+'"><a class="profile" href="'+html_escape(item["url"],quote=True)+'"><span class="profile-icon">↗</span><span><b>'+html_escape(item["label"])+'</b><small>TLS · '+html_escape(item["label"])+'</small></span><span class="profile-open">باز کردن</span></a><div class="profile-marks"><button type="button" data-mark="ok" data-profile="'+html_escape(item["key"],quote=True)+'">✓ کار کرد</button><button type="button" data-mark="fail" data-profile="'+html_escape(item["key"],quote=True)+'">× کار نکرد</button><small data-result="'+html_escape(item["key"],quote=True)+'"></small></div></div>'
        for item in links
    )
    template="""<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="dark"><meta name="theme-color" content="#080b12"><title>Abyss Tunnel · اشتراک خصوصی</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(ellipse at 50% -15%,#163a43 0,transparent 48%),#080b12;color:#edf5f7;font:15px system-ui,-apple-system,sans-serif}.shell{width:min(820px,100%);margin:auto;padding:28px 16px 44px}.top,.row,.profile{display:flex;align-items:center;justify-content:space-between;gap:14px}.brand{font-size:12px;letter-spacing:.18em;color:#8de8d6;font-weight:800}.badge{font-size:11px;color:#8de8d6;border:1px solid #275c58;padding:7px 10px;border-radius:99px}.hero{margin:25px 0 16px;padding:25px;border:1px solid #25434b;border-radius:24px;background:linear-gradient(135deg,rgba(18,39,49,.96),rgba(13,20,32,.97));box-shadow:0 22px 70px #0005}.eyebrow{font-size:11px;color:#8de8d6;letter-spacing:.12em}.hero h1{font-size:clamp(25px,6vw,38px);line-height:1.2;margin:12px 0 8px;overflow-wrap:anywhere}.muted,small{color:#91a3b4;line-height:1.8}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:14px 0}.metric,.panel{background:#101722;border:1px solid #222f3f;border-radius:16px;padding:16px;min-width:0}.metric small{display:block;font-size:11px}.metric b{display:block;font-size:16px;margin-top:7px;overflow-wrap:anywhere}.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0 0 12px}.section-head h2{font-size:16px;margin:0}.profiles{display:grid;gap:9px}.profile{padding:13px;text-decoration:none;color:#edf5f7;border:1px solid #263447;border-radius:13px;background:#0b111b;min-width:0}.profile:hover{border-color:#76e4d1;background:#101e27}.profile-icon{width:34px;height:34px;display:grid;place-items:center;border-radius:10px;background:#173b3c;color:#8de8d6;flex-shrink:0}.profile>span:nth-child(2){flex:1;min-width:0}.profile b,.profile small{display:block;overflow-wrap:anywhere}.profile-open{font-size:12px;color:#8de8d6;white-space:nowrap}.profile-marks{display:flex;flex-wrap:wrap;align-items:center;gap:6px;padding:6px 2px 2px}.profile-marks button{border:1px solid #2a3a4c;background:#101923;color:#b9c9d7;border-radius:8px;padding:6px 9px;font:inherit;font-size:11px;cursor:pointer}.profile-marks button[data-selected="true"][data-mark="ok"]{border-color:#4f9e87;color:#8de8d6;background:#102b26}.profile-marks button[data-selected="true"][data-mark="fail"]{border-color:#9c5a60;color:#ffb4b4;background:#2b151a}.profile-marks small{font-size:10px}.carrier-tools{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.6fr);gap:12px;align-items:center;margin-bottom:13px;padding:13px;border:1px solid #263748;border-radius:12px;background:#0b111b}.carrier-tools label{font-size:12px;color:#9aabbd}.carrier-tools select{width:100%;margin-top:6px;padding:10px;border:1px solid #2a3b4d;border-radius:9px;background:#080d15;color:#edf5f7}.share{display:grid;grid-template-columns:minmax(0,1fr) 160px;gap:16px;align-items:center}.linkbox{direction:ltr;text-align:left;width:100%;background:#080d15;color:#c6d6df;border:1px solid #2a3b4d;border-radius:10px;padding:12px;font:12px ui-monospace,monospace;overflow-wrap:anywhere}.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;margin-top:9px;padding:11px 14px;border-radius:10px;border:1px solid #2b4651;background:#152630;color:#eaf8f6;font:inherit;cursor:pointer;text-decoration:none}.btn.primary{background:#8de8d6;color:#061412;border-color:#8de8d6;font-weight:800}.qr{display:block;width:160px;max-width:100%;padding:9px;border-radius:13px;background:#fff;aspect-ratio:1}.footer{text-align:center;font-size:11px;color:#65778a;margin-top:24px;line-height:1.9}.warning{color:#d8c58a;font-size:12px;margin-top:12px;line-height:1.8}.usage-panel{margin:0 0 14px}.usage-track{height:7px;margin:12px 0;border-radius:99px;background:var(--ab-line);overflow:hidden}.usage-track span{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,var(--ab-accent),var(--ab-accent-hi));transition:width .2s ease}.usage-visual{display:grid;grid-template-columns:150px minmax(0,1fr);gap:20px;align-items:center}.usage-gauge{width:142px;max-width:100%;aspect-ratio:1;border-radius:50%;display:grid;place-items:center;background:conic-gradient(var(--ab-accent) calc(var(--usage)*1%),var(--ab-line) 0);box-shadow:0 8px 22px rgba(0,0,0,.09),inset 0 1px rgba(255,255,255,.06);position:relative}.usage-gauge:before{content:"";position:absolute;inset:10px;border-radius:50%;background:var(--ab-panel);border:1px solid var(--ab-line)}.usage-gauge>span{position:relative;z-index:1;font-size:21px;font-weight:800;text-align:center}.usage-gauge small{display:block;font-size:10px;font-weight:500}.usage-detail{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.usage-detail>div{padding:14px;border:1px solid var(--ab-line);border-radius:13px;background:var(--ab-glass)}.usage-detail small,.usage-detail b{display:block}.usage-detail b{margin-top:7px;font-size:17px;overflow-wrap:anywhere}.usage-chart-ranges{display:flex;gap:5px;flex-shrink:0}.usage-chart-ranges button{min-width:39px;min-height:30px;padding:5px 8px;border-radius:9px;border:1px solid var(--ab-line);background:rgba(230,230,235,.025);color:var(--ab-muted);font:600 11px Vazirmatn,Tahoma,sans-serif;cursor:pointer}.usage-chart-ranges button[aria-pressed="true"]{border-color:rgba(210,212,218,.42);background:linear-gradient(145deg,rgba(200,202,208,.20),rgba(110,112,118,.10));color:var(--ab-text);box-shadow:inset 0 1px rgba(255,255,255,.08)}.usage-chart-wrap{width:100%;min-width:0;overflow:hidden}.usage-chart-wrap canvas{display:block;width:100%;height:155px;max-width:100%;border-radius:10px}.usage-chart-note{min-height:22px;margin-top:5px;font-size:11px;color:var(--ab-muted);line-height:1.7}.usage-chart-legend{display:flex;align-items:center;gap:7px;font-size:10px;color:var(--ab-muted);margin-top:5px}.usage-chart-legend span{display:inline-block;width:17px;height:2px;background:#d0d1d5;box-shadow:0 0 8px rgba(210,212,218,.2)}.service-details-panel{display:none}.service-details-mobile-metrics{display:none}.service-details-identity{display:grid;gap:6px;padding:11px;border-radius:12px;background:rgba(230,230,235,.025);border:1px solid var(--ab-line);margin-bottom:9px}.service-details-identity small{font-size:11px}.service-details-identity strong{font-size:17px;overflow-wrap:anywhere}.service-details-list{display:grid;gap:2px;margin:0}.service-details-list>div{display:grid;grid-template-columns:minmax(0,.9fr) minmax(0,1.1fr);align-items:start;gap:6px;padding:8px 0;border-bottom:1px solid rgba(178,181,187,.10)}.service-details-list dt{color:var(--ab-muted);font-size:10px;line-height:1.7}.service-details-list dd{margin:0;color:var(--ab-text);font-size:10px;font-weight:700;line-height:1.7;overflow-wrap:anywhere}.service-copy{display:flex;width:100%;min-height:38px;margin-top:11px;padding:8px;font-size:12px}@media(max-width:1100px){.service-details-panel{display:none!important}}@media(max-width:560px){.usage-chart-panel{min-width:0}.usage-chart-panel .section-head{align-items:flex-start}.usage-chart-ranges button{min-width:35px;padding:5px 6px}.usage-chart-wrap canvas{height:150px}}@media(max-width:500px){.usage-visual{grid-template-columns:105px minmax(0,1fr);gap:12px}.usage-gauge{width:104px}.usage-gauge:before{inset:7px}.usage-gauge>span{font-size:17px}.usage-detail{grid-template-columns:1fr}.usage-detail>div{padding:10px}}@media(max-width:560px){.shell{padding:18px 11px 30px}.hero{padding:19px;border-radius:19px}.grid{grid-template-columns:1fr 1fr}.share{grid-template-columns:1fr}.qr{width:145px;margin:8px auto 0}.profile{gap:9px;padding:11px}.profile-open{font-size:11px}.metric,.panel{padding:13px}}@media(max-width:360px){.grid{grid-template-columns:1fr}.profile-open{display:none}}
</style><style id="abyss-premium-upgrade">
:root{color-scheme:dark;--abyss-bg:#070a10;--abyss-panel:#101722;--abyss-line:#263748;--abyss-mint:#8de8d6;--abyss-text:#edf3fb;--abyss-muted:#9aabbd}
html{scroll-behavior:smooth}body{background-color:var(--abyss-bg)}body:before{content:"";position:fixed;inset:0;pointer-events:none;z-index:-1;background:radial-gradient(ellipse at 80% -10%,rgba(43,130,125,.16),transparent 42%),radial-gradient(ellipse at 0% 40%,rgba(37,66,107,.13),transparent 42%)}
.card,.panel,.box,.section,.stat,.metric,.client-card{border-color:var(--abyss-line)!important;box-shadow:0 12px 36px rgba(0,0,0,.14);transition:border-color .18s ease,transform .18s ease,box-shadow .18s ease}
button,.btn,a.button{transition:filter .15s ease,transform .15s ease,box-shadow .15s ease}button:hover,.btn:hover,a.button:hover{filter:brightness(1.08);transform:translateY(-1px)}
button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--abyss-mint);outline-offset:3px}
input,select,textarea{max-width:100%;min-width:0}table{display:block;max-width:100%;overflow-x:auto;border-collapse:collapse}main,.container,.wrap{min-width:0}
@media(max-width:600px){body{font-size:14px}main,.container,.wrap{padding-left:12px!important;padding-right:12px!important}.card,.panel,.box{border-radius:15px!important}.row{flex-wrap:wrap}.row>*{max-width:100%}button,.btn{min-height:42px}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;transition:none!important;animation:none!important}}
</style><style id="abyss-subscription-reference">
:root{color-scheme:dark;--ab-bg:#020202;--ab-panel:rgba(13,13,14,.96);--ab-line:rgba(178,181,187,.18);--ab-accent:#b9bbc1;--ab-accent-hi:#f0f0f2;--ab-text:#eeeef0;--ab-muted:#a2a2a7;--ab-glass:rgba(230,230,235,.035);--abyss-mint:#a9b9ac}
html,body{background-color:#020202!important;color:#eeeef0!important}
body{background-image:radial-gradient(1px 1px at 8% 14%,rgba(220,222,226,.45) 0,transparent 1.4px),radial-gradient(1px 1px at 72% 36%,rgba(220,222,226,.32) 0,transparent 1.4px),radial-gradient(1px 1px at 35% 81%,rgba(220,222,226,.38) 0,transparent 1.4px),radial-gradient(ellipse at 82% 14%,rgba(185,187,193,.055),transparent 38%),linear-gradient(145deg,#020202,#070707 58%,#030303)!important}
body:before{z-index:0!important;opacity:.28!important;background:linear-gradient(118deg,transparent 0 16%,rgba(200,202,208,.045) 16.08%,transparent 16.24% 43%,rgba(185,188,194,.025) 43.08%,transparent 43.24% 72%,rgba(220,221,225,.035) 72.08%,transparent 72.22%)!important}
.shell{position:relative;z-index:1}
.brand{color:#d3d5da!important;letter-spacing:.18em}
.abyss-brand-row{display:flex;align-items:center;gap:9px;letter-spacing:.14em;direction:ltr}
.abyss-logo-mark{display:inline-block;width:27px;height:27px;flex:0 0 27px;border-radius:50%;position:relative;background:radial-gradient(circle at center,#050505 0 27%,transparent 29%);isolation:isolate}
.abyss-logo-mark:before{content:"";position:absolute;inset:-2px;border-radius:50%;background:repeating-conic-gradient(from 0deg,rgba(210,213,218,.6) 0deg .55deg,transparent .7deg 3.2deg);mask:radial-gradient(circle,transparent 0 27%,#000 30% 63%,transparent 76%);opacity:.62}
.brand-name{display:grid;gap:2px;color:#e4e5e8;font-size:12px;font-weight:800;letter-spacing:.16em}
.brand-name small{display:block;font-size:9px;letter-spacing:.22em;opacity:.75;text-align:center}
.badge,.eyebrow,.profile-open{color:#c1c4ca!important}
.badge{border-color:rgba(178,181,187,.22)!important;background:rgba(230,230,235,.035)!important}
.hero{border-color:rgba(178,181,187,.20)!important;background:linear-gradient(150deg,rgba(19,19,21,.98),rgba(5,5,6,.98))!important;box-shadow:0 22px 70px rgba(0,0,0,.45),inset 0 1px 0 rgba(255,255,255,.035)!important}
.metric,.panel{background:linear-gradient(145deg,rgba(17,17,19,.97),rgba(8,8,9,.97))!important;border-color:rgba(178,181,187,.18)!important;box-shadow:0 14px 36px rgba(0,0,0,.20),inset 0 1px 0 rgba(255,255,255,.025)!important}
.profile,.carrier-tools{background:rgba(10,10,11,.94)!important;border-color:rgba(178,181,187,.18)!important;color:#eeeef0!important}
.profile:hover{border-color:rgba(195,198,205,.42)!important;background:rgba(22,22,24,.98)!important}
.profile-icon{background:rgba(195,198,205,.09)!important;color:#d2d4d8!important}
.profile-marks button{border-color:rgba(178,181,187,.20)!important;background:rgba(230,230,235,.035)!important;color:#c3c5ca!important}
.profile-marks button[data-selected="true"][data-mark="ok"]{border-color:#6e9b7a!important;color:#b7d6bb!important;background:#101810!important}
.profile-marks button[data-selected="true"][data-mark="fail"]{border-color:#9c5a60!important;color:#ffb4b4!important;background:#241316!important}
.carrier-tools select,.linkbox{background:#070708!important;border-color:rgba(178,181,187,.2)!important;color:#dddfe3!important}
.btn{border-color:rgba(178,181,187,.25)!important;background:rgba(230,230,235,.045)!important;color:#ececef!important}
.btn.primary{background:linear-gradient(145deg,#c8c9cc,#96989e)!important;color:#09090a!important;border-color:rgba(225,226,230,.42)!important;font-weight:800}
.usage-track{background:rgba(178,181,187,.12)!important}
.usage-track span{background:linear-gradient(90deg,#9eafa2,#d2d4d8)!important}
.usage-gauge{background:conic-gradient(var(--ab-accent) calc(var(--usage)*1%),var(--ab-line) 0)!important}
.usage-gauge:before{background:#0c0c0d!important;border-color:rgba(178,181,187,.18)!important}
.footer{color:#888a90!important}
.abyss-utility-links a{border-color:rgba(178,181,187,.18)!important;background:rgba(230,230,235,.035)!important;color:#aeb0b6!important}
.warning{color:#bdbfc5!important}
@media(max-width:700px){body:before{display:none!important}.shell{padding-top:18px!important}.brand-name{font-size:11px!important}}
@media(min-width:1101px){
 .shell{width:min(1480px,100%);padding:22px clamp(24px,3vw,48px) 36px;display:grid;grid-template-columns:repeat(24,minmax(0,1fr));grid-auto-rows:min-content;grid-auto-flow:row;gap:14px;align-items:start;align-content:start}
 .shell>.top{grid-column:1/-1!important;grid-row:1!important;margin:0;min-width:0}
 .shell>.hero,.shell>.grid{display:none!important}
 .shell>.service-details-panel{display:block!important;grid-column:20/-1!important;grid-row:2!important;margin:0;min-width:0;align-self:stretch}
 .shell>.usage-panel{grid-column:15/20!important;grid-row:2!important;margin:0;align-self:stretch}
 .shell>.usage-chart-panel{grid-column:7/15!important;grid-row:2!important;margin:0;align-self:stretch}
 .shell>.share-panel{grid-column:1/7!important;grid-row:2!important;margin:0!important;align-self:stretch}
 .shell>.profiles-panel{grid-column:1/-1!important;grid-row:3!important;margin:0;align-self:start}
 .shell>.profiles-panel .profiles{grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}
 .shell>.footer{grid-column:1/-1!important;grid-row:4!important;margin-top:0}
 .shell>#abyssTroubleshoot{grid-column:7/-1!important;grid-row:5!important;width:100%;min-width:0;margin:0!important}
 .shell>#abyssTroubleshoot+.panel{grid-column:1/7!important;grid-row:5!important;width:100%;min-width:0;margin:0!important}
 .shell>#abyssTroubleshoot+.panel+.panel{grid-column:1/-1!important;grid-row:6!important;width:100%;min-width:0;margin:0!important}
 .usage-visual{grid-template-columns:112px minmax(0,1fr);gap:12px}
 .usage-gauge{width:110px}
 .usage-gauge:before{inset:8px}
 .usage-gauge>span{font-size:18px}
 .usage-detail{grid-template-columns:1fr;gap:8px}
 .usage-detail>div{padding:10px}
 .usage-detail b{font-size:14px}
 .carrier-tools{grid-template-columns:minmax(0,1fr);gap:8px}
 .share{grid-template-columns:minmax(0,1fr) 112px;gap:10px}
 .qr{width:112px}
 .profile{gap:9px;padding:11px}
 .profile-open{font-size:11px}
}
@media(min-width:851px) and (max-width:1100px){.shell{width:min(920px,100%);padding:24px 20px 38px}}
@media(max-width:700px){
 .shell{display:flex!important;flex-direction:column!important;align-items:stretch!important;gap:12px!important}
 .shell>.service-details-panel{display:block!important;order:1;margin:0!important}
 .shell>.hero,.shell>.grid{display:none!important}
 .shell>.share-panel{order:2;margin:0!important}
 .shell>.profiles-panel{order:3;margin:0!important}
 .shell>.usage-panel{order:4;margin:0!important}
 .shell>.usage-chart-panel{order:5;margin:0!important}
 .shell>.footer{order:6;margin:0!important}
 .shell>#abyssTroubleshoot{order:7}
 .shell>#abyssTroubleshoot+.panel{order:8}
 .shell>#abyssTroubleshoot+.panel+.panel{order:9}
 .service-details-mobile-metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:7px;margin-top:10px}
 .service-details-mobile-metrics>div{min-width:0;padding:9px 7px;border:1px solid var(--ab-line);border-radius:10px;background:var(--ab-glass)}
 .service-details-mobile-metrics small,.service-details-mobile-metrics strong{display:block;overflow-wrap:anywhere}
 .service-details-mobile-metrics small{font-size:10px}
 .service-details-mobile-metrics strong{margin-top:5px;font-size:12px}
}
</style><style>html,body,button,input,select,textarea{font-family:'Vazirmatn',Tahoma,system-ui,sans-serif}</style></head><body data-sub-url="__SUB_URL__"><main class="shell"><header class="top"><div class="abyss-brand-row"><img class="abyss-logo-image" src="/brand-logo" alt="" aria-hidden="true"><span class="brand-name">ABYSS TUNNEL<small>• I T A •</small></span></div><span class="badge">PRIVATE SUBSCRIPTION</span></header><section class="panel service-details-panel"><div class="section-head"><h2>مشخصات سرویس</h2><span class="badge">فعال</span></div><div class="service-details-identity"><small>نام سرویس</small><strong>__CLIENT_NAME__</strong></div><dl class="service-details-list"><div><dt>پروفایل‌ها</dt><dd>__PROFILE_SUMMARY__</dd></div><div><dt>تاریخ ایجاد</dt><dd>__CREATED__</dd></div><div><dt>اعتبار تا</dt><dd>__EXPIRY__</dd></div></dl><div class="service-details-mobile-metrics" aria-label="خلاصه مصرف سرویس"><div><small>حجم کل</small><strong>__QUOTA__</strong></div><div><small>مصرف‌شده</small><strong>__USED__ GB</strong></div><div><small>باقی‌مانده</small><strong>__REMAINING__</strong></div></div><button class="btn primary service-copy" onclick="copySub()">کپی لینک اشتراک</button></section><section class="hero"><div class="eyebrow">YOUR CONNECTION · YOUR CONTROL</div><h1>اشتراک خصوصی شما</h1><p class="muted">پروفایل موردنظرت را انتخاب کن یا لینک اشتراک را در کلاینت سازگار وارد کن.</p><div class="row"><div><small>نام سرویس</small><div style="font-size:19px;font-weight:800;overflow-wrap:anywhere">__CLIENT_NAME__</div></div><button class="btn primary" onclick="copySub()">کپی لینک اشتراک</button></div></section><section class="grid"><div class="metric"><small>مصرف‌شده</small><b>__USED__ GB</b></div><div class="metric"><small>حجم کل</small><b>__QUOTA__</b></div><div class="metric"><small>باقی‌مانده</small><b>__REMAINING__</b></div><div class="metric"><small>اعتبار تا</small><b>__EXPIRY__</b></div></section><section class="panel usage-panel"><div class="row"><b>مصرف ترافیک <span class="help-dot" title="نمودار درصد حجم مصرف‌شده از سقف مجاز سرویس را نشان می‌دهد.">؟</span></b><span>__USAGE_PERCENT__٪</span></div><div class="usage-visual"><div class="usage-gauge" style="--usage:__USAGE_PERCENT__" role="img" aria-label="مصرف __USAGE_PERCENT__ درصد"><span>__USAGE_PERCENT__٪<small>مصرف‌شده</small></span></div><div class="usage-detail"><div><small>حجم مصرف‌شده</small><b>__USED__ GB</b></div><div><small>حجم باقی‌مانده</small><b>__REMAINING__</b></div></div></div><div class="usage-track" role="progressbar" aria-label="مصرف ترافیک" aria-valuemin="0" aria-valuemax="100" aria-valuenow="__USAGE_PERCENT__"><span style="width:__USAGE_PERCENT__%"></span></div><small class="muted">حجم مصرفی از آمار ثبت‌شدهٔ Xray محاسبه می‌شود؛ ممکن است با تأخیر کوتاهی به‌روز شود.</small></section><section class="panel usage-chart-panel"><div class="section-head"><h2 id="clientUsageChartTitle">نمودار مصرف</h2><div class="usage-chart-ranges" role="group" aria-label="بازهٔ نمودار مصرف"><button type="button" data-usage-days="7" aria-pressed="false">7d</button><button type="button" data-usage-days="30" aria-pressed="true">30d</button><button type="button" data-usage-days="90" aria-pressed="false">90d</button></div></div><div class="usage-chart-wrap"><canvas id="clientUsageChart" role="img" aria-label="نمودار تاریخی مصرف سرویس"></canvas></div><div id="clientUsageChartNote" class="usage-chart-note" aria-live="polite">در حال آماده‌سازی نمودار…</div><div class="usage-chart-legend"><span></span> مصرف ثبت‌شدهٔ سرویس (GB)</div></section><section class="panel profiles-panel"><div class="section-head"><h2>پروفایل‌های اتصال</h2><span class="badge">__COUNT__ PROFILES</span></div><div class="carrier-tools"><div><label for="carrierSelect">شبکه‌ای که الان با آن تست می‌کنی</label><select id="carrierSelect"><option value="auto">انتخاب خودکار</option><option value="mci">همراه اول</option><option value="irancell">ایرانسل</option><option value="rightel">رایتل</option><option value="wifi">وای‌فای / سایر</option></select></div><div><small>نتیجهٔ هر پروفایل را روی همین دستگاه ثبت کن تا پروفایل‌های موفق برای همین شبکه بالاتر نمایش داده شوند.</small><br><small>نتیجه روی همین دستگاه ذخیره و به‌صورت آماری برای پیشنهادهای اپراتور ثبت می‌شود.</small></div></div><div class="profiles" id="profileChoices">__PROFILES__</div><p class="warning">اگر کلاینت شما از لینک اشتراک پشتیبانی می‌کند، لینک اصلی را وارد کنید تا همه پروفایل‌ها یکجا اضافه شوند.</p></section><section class="panel share-panel" style="margin-top:14px"><div class="section-head"><h2>لینک واحد اشتراک</h2><span class="badge">ONE LINK</span></div><p class="muted">همین یک لینک را هم در مرورگر باز کن و هم در برنامهٔ سازگار وارد کن؛ مرورگر صفحه مدیریت اشتراک را می‌بیند و برنامه، فهرست پروفایل‌ها و اطلاعات حجم را دریافت می‌کند.</p><div class="share"><div><input class="linkbox" readonly value="__SUB_URL__" aria-label="Subscription URL"><button class="btn primary" onclick="copySub()">کپی لینک واحد</button></div><img class="qr" src="__QR_URL__" alt="QR code for subscription link" width="160" height="160"></div></section><footer class="footer">ABYSS TUNNEL · PRIVATE BY DESIGN<br>این صفحه را فقط با صاحب سرویس به اشتراک بگذار؛ لینک اشتراک مانند رمز دسترسی عمل می‌کند.<div class="abyss-utility-links" style="justify-content:center"><a href="https://github.com/bodisbos-cmd/Void" target="_blank" rel="noopener">⌘ GitHub</a><a href="https://github.com/bodisbos-cmd/Void/stargazers" target="_blank" rel="noopener">☆ ستاره دادن</a><a href="#support-link-not-configured" onclick="if(this.getAttribute('href')==='#support-link-not-configured'){alert('لینک حمایت مالی هنوز در تنظیمات سرویس ثبت نشده است.');return false}">◇ حمایت از پروژه</a></div></footer></main><script>async function copySub(){const u=document.body.dataset.subUrl;try{await navigator.clipboard.writeText(u);alert('لینک اشتراک کپی شد')}catch(e){const x=document.querySelector('.linkbox');x.focus();x.select();alert('لینک را به‌صورت دستی کپی کن')}}</script><script id="client-usage-chart">
const clientUsageHistory=__USAGE_HISTORY__;
(()=>{
 const canvas=document.getElementById('clientUsageChart'),note=document.getElementById('clientUsageChartNote');
 if(!canvas||!note)return;
 const ctx=canvas.getContext('2d');
 if(!ctx){note.textContent='نمایش نمودار در این مرورگر پشتیبانی نمی‌شود.';return}
 const buttons=[...document.querySelectorAll('[data-usage-days]')];
 let days=30;
 const number=new Intl.NumberFormat('fa-IR',{maximumFractionDigits:1});
 const gb=value=>Math.max(0,Number(value)||0)/1073741824;
 function draw(){
  const ratio=Math.min(2,window.devicePixelRatio||1);
  const width=Math.max(220,Math.floor(canvas.getBoundingClientRect().width||300));
  const height=155;
  canvas.width=Math.round(width*ratio);canvas.height=Math.round(height*ratio);
  ctx.setTransform(ratio,0,0,ratio,0,0);ctx.clearRect(0,0,width,height);
  const now=Math.floor(Date.now()/1000),cutoff=now-days*86400;
  let points=(Array.isArray(clientUsageHistory)?clientUsageHistory:[])
   .filter(p=>Number.isFinite(Number(p.at))&&Number(p.at)>=cutoff&&Number(p.at)<=now+60)
   .map(p=>({at:Number(p.at),value:gb(p.used_bytes)})).sort((a,b)=>a.at-b.at);
  if(points.length>144){const step=Math.ceil(points.length/144);const all=points;points=all.filter((p,i)=>i%step===0);if(points[points.length-1].at!==all[all.length-1].at)points.push(all[all.length-1])}
  const pad={left:38,right:9,top:9,bottom:25},plotW=Math.max(30,width-pad.left-pad.right),plotH=height-pad.top-pad.bottom;
  const maxValue=Math.max(1,...points.map(p=>p.value))*1.08;
  ctx.font='10px Vazirmatn,Tahoma,sans-serif';ctx.lineWidth=1;
  for(let i=0;i<=4;i++){
   const y=pad.top+plotH*i/4;
   ctx.strokeStyle='rgba(190,192,198,.12)';ctx.beginPath();ctx.moveTo(pad.left,y);ctx.lineTo(width-pad.right,y);ctx.stroke();
   ctx.fillStyle='rgba(190,192,198,.76)';ctx.textAlign='left';ctx.textBaseline='middle';
   ctx.fillText(number.format(maxValue*(1-i/4)),2,y);
  }
  if(points.length){
   const span=Math.max(1,points[points.length-1].at-points[0].at);
   const x=p=>pad.left+(p.at-points[0].at)/span*plotW;
   const y=p=>pad.top+plotH-(p.value/maxValue)*plotH;
   ctx.fillStyle='rgba(205,207,213,.07)';ctx.beginPath();ctx.moveTo(x(points[0]),pad.top+plotH);
   points.forEach(p=>ctx.lineTo(x(p),y(p)));ctx.lineTo(x(points[points.length-1]),pad.top+plotH);ctx.closePath();ctx.fill();
   ctx.strokeStyle='rgba(220,222,228,.94)';ctx.lineWidth=2;ctx.lineJoin='round';ctx.lineCap='round';ctx.beginPath();
   points.forEach((p,i)=>{if(i===0)ctx.moveTo(x(p),y(p));else ctx.lineTo(x(p),y(p))});ctx.stroke();
   const last=points[points.length-1];ctx.fillStyle='#e3e4e7';ctx.beginPath();ctx.arc(x(last),y(last),3,0,Math.PI*2);ctx.fill();
   [points[0],points[Math.floor((points.length-1)/2)],last].forEach((p,i)=>{
    const label=new Date(p.at*1000).toLocaleDateString('fa-IR',{month:'numeric',day:'numeric'});
    ctx.fillStyle='rgba(190,192,198,.76)';ctx.textBaseline='top';ctx.textAlign=i===0?'left':i===2?'right':'center';
    ctx.fillText(label,x(p),height-18);
   });
  }
  canvas.dataset.renderedPoints=String(points.length);canvas.dataset.periodDays=String(days);
  note.textContent=points.length<2?'تاریخچه پس از ثبت نمونه‌های ساعتی تکمیل می‌شود.':'نمایش '+number.format(points.length)+' نمونهٔ ثبت‌شده در '+number.format(days)+' روز گذشته.';
 }
 buttons.forEach(button=>button.addEventListener('click',()=>{days=Number(button.dataset.usageDays);buttons.forEach(item=>item.setAttribute('aria-pressed',String(item===button)));draw()}));
 window.addEventListener('resize',draw,{passive:true});
 if(document.fonts&&document.fonts.ready)document.fonts.ready.then(draw).catch(()=>{});
 draw();
})();
</script><script id="abyss-profile-results">(()=>{const select=document.getElementById('carrierSelect'),list=document.getElementById('profileChoices');if(!select||!list)return;const prefix='abyss-profile-results:';const storageKey=()=>prefix+select.value;const read=()=>{try{return JSON.parse(localStorage.getItem(storageKey())||'{}')}catch(e){return {}}};function paint(){const data=read();list.querySelectorAll('[data-profile-choice]').forEach(card=>{const key=card.dataset.profileChoice,value=data[key]||'';card.querySelectorAll('[data-mark]').forEach(b=>b.dataset.selected=String(b.dataset.mark===value));const out=card.querySelector('[data-result]');if(out)out.textContent=value==='ok'?'برای این شبکه موفق بود':value==='fail'?'برای این شبکه ناموفق بود':''});const cards=[...list.querySelectorAll('[data-profile-choice]')];cards.sort((a,b)=>{const rank=x=>({ok:0,'':1,fail:2})[data[x.dataset.profileChoice]||''];return rank(a)-rank(b)});cards.forEach(x=>list.appendChild(x))}select.value=localStorage.getItem(prefix+'carrier')||'auto';select.addEventListener('change',()=>{localStorage.setItem(prefix+'carrier',select.value);paint()});list.querySelectorAll('[data-mark]').forEach(b=>b.addEventListener('click',async()=>{const d=read();d[b.dataset.profile]=b.dataset.mark;localStorage.setItem(storageKey(),JSON.stringify(d));paint();try{await fetch(location.pathname+'/feedback',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({carrier:select.value,profile_key:b.dataset.profile,result:b.dataset.mark})})}catch(e){}}));paint()})();</script></body></html>"""
    return (template.replace("__SUB_URL__",html_escape(sub_url,quote=True))
        .replace("__CLIENT_NAME__",html_escape(client["name"]))
        .replace("__PROFILE_SUMMARY__",html_escape(profile_summary))
        .replace("__CREATED__",html_escape(created_display))
        .replace("__USED__",f"{usage:.3f}")
        .replace("__QUOTA__",html_escape(quota_text))
        .replace("__REMAINING__",html_escape(remaining_text))
        .replace("__USAGE_PERCENT__",str(usage_pct))
        .replace("__EXPIRY__",html_escape(expiry))
        .replace("__PROFILES__",cards)
        .replace("__COUNT__",str(len(links)))
        .replace("__QR_URL__",html_escape(qr_url,quote=True))
        .replace("__USAGE_HISTORY__",json.dumps(usage_history,separators=(",",":")))
        .replace("__SUB_JSON__",json.dumps(sub_url))).replace("<style>html,body,button,input,select,textarea{font-family:'Vazirmatn',Tahoma,system-ui,sans-serif}</style></head>",ABYSS_THEME_CSS+ABYSS_THEME_POLISH_CSS+"<style>html,body,button,input,select,textarea{font-family:'Vazirmatn',Tahoma,system-ui,sans-serif}</style></head>").replace("</body>",ABYSS_THEME_JS+"</body>")

@app.get("/api/clients/{cid}/subscription")
async def subscription_link(cid:str,r:Request):
    require_admin(r); require_client_access(r,cid)
    with db() as c: row=c.execute("SELECT sub_token FROM clients WHERE id=?",(cid,)).fetchone()
    if not row: raise HTTPException(404,"Client not found")
    base=get_base_url(r); token=row["sub_token"]
    single_url=f"{base}/sub/{token}"
    return JSONResponse({"url":single_url,"page_url":single_url,"subscription_url":single_url,"qr_url":f"{single_url}/qr"},headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow"})

@app.get("/sub/{token}")
async def subscription(token:str,r:Request):
    """One shareable URL: browsers get the branded page; subscription clients get Base64."""
    client=active_subscription_client(token)
    links=make_subscription_links(client,r)
    accept=r.headers.get("accept","").lower()
    agent=r.headers.get("user-agent","").lower()
    browser_request=("text/html" in accept and any(x in agent for x in ("mozilla","chrome","safari","firefox","edg/","opr/")))
    headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow","Vary":"Accept, User-Agent","Subscription-Userinfo":subscription_userinfo(client),"Profile-Update-Interval":"6"}
    if browser_request:
        base=get_base_url(r)
        page=render_subscription_page(client,links,f"{base}/sub/{token}",f"{base}/sub/{token}/qr",get_client_usage_history(client["id"]))
        return HTMLResponse(page,headers=headers)
    return PlainTextResponse(subscription_text(links),headers=headers)

@app.post("/sub/{token}/feedback")
async def submit_profile_feedback(token:str,r:Request):
    client=active_subscription_client(token)
    if not rate_check(r,"profile-feedback:"+client["id"],limit=30,window=60):
        raise HTTPException(429,"Too many feedback reports")
    body=await r.json()
    if not isinstance(body,dict):
        raise HTTPException(422,"JSON object required")
    carrier=body.get("carrier")
    profile_key=body.get("profile_key")
    result=body.get("result")
    if carrier not in {"auto","mci","irancell","rightel","wifi"}:
        raise HTTPException(422,"Unsupported carrier")
    if profile_key not in {p["key"] for p in PROFILES}:
        raise HTTPException(422,"Unsupported profile")
    if result not in {"ok","fail"}:
        raise HTTPException(422,"Result must be ok or fail")
    with db() as c:
        c.execute("INSERT INTO profile_feedback(client_id,carrier,profile_key,result,created_at,user_agent) VALUES(?,?,?,?,?,?) ON CONFLICT(client_id,carrier,profile_key) DO UPDATE SET result=excluded.result,created_at=excluded.created_at,user_agent=excluded.user_agent",(client["id"],carrier,profile_key,result,utc_now(),r.headers.get("user-agent","")[:160]))
    return {"ok":True,"message":"نتیجه برای پیشنهادهای همین اپراتور ثبت شد."}

@app.get("/sub/{token}/qr")
async def subscription_qr(token:str,r:Request):
    client=active_subscription_client(token)
    url=f"{get_base_url(r)}/sub/{token}"
    qr=qrcode.make(url,image_factory=SvgPathImage,box_size=7,border=2)
    buffer=io.BytesIO(); qr.save(buffer)
    return Response(buffer.getvalue(),media_type="image/svg+xml",headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow"})

@app.get("/s/{token}",response_class=HTMLResponse)
async def subscription_page(token:str,r:Request):
    client=active_subscription_client(token)
    links=make_subscription_links(client,r)
    base=get_base_url(r); sub_url=f"{base}/sub/{token}"
    page=render_subscription_page(client,links,sub_url,f"{base}/sub/{token}/qr",get_client_usage_history(client["id"]))
    return HTMLResponse(page,headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow","Subscription-Userinfo":subscription_userinfo(client),"Profile-Update-Interval":"6"})

@app.get("/api/backup/sqlite")
async def backup_database(r:Request):
    require_root(r)
    stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target=DATA_DIR/("abyss-backup-"+stamp+"-"+uuid.uuid4().hex[:8]+".sqlite3")
    with db() as source:
        dest=sqlite3.connect(target)
        try: source.backup(dest)
        finally: dest.close()
    event("INFO","Administrator created a database backup.")
    return FileResponse(target,media_type="application/vnd.sqlite3",filename=target.name,
        headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow"},
        background=BackgroundTask(target.unlink,missing_ok=True))

@app.post("/api/restore")
async def restore_database(r:Request):
    require_root(r); require_csrf(r)
    raw=await r.body()
    if not raw or len(raw)>100*1024*1024: raise HTTPException(413,"Backup must be between 1 byte and 100 MB")
    async with restore_lock:
        candidate=DATA_DIR/(".restore-candidate-"+uuid.uuid4().hex+".sqlite3")
        candidate.write_bytes(raw)
        old=None
        try:
            check=sqlite3.connect(candidate)
            try:
                try:
                    if check.execute("PRAGMA integrity_check").fetchone()[0]!="ok":
                        raise HTTPException(422,"Backup database integrity check failed")
                    tables={x[0] for x in check.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    if not {"admins","clients","settings"}.issubset(tables):
                        raise HTTPException(422,"Incompatible Void backup")
                    required_columns={
                        "admins":{"id","password_hash","password_changed_at"},
                        "clients":{"id","name","client_uuid","sub_token","enabled","created_at"},
                        "settings":{"key","value"},
                    }
                    for table,required in required_columns.items():
                        columns={row[1] for row in check.execute("PRAGMA table_info("+table+")")}
                        if not required.issubset(columns):
                            raise HTTPException(422,"Backup schema is incompatible with this release")
                except sqlite3.DatabaseError as exc:
                    raise HTTPException(422,"Backup is not a valid SQLite database") from exc
            finally:
                check.close()
            stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            old=DATA_DIR/("pre-restore-"+stamp+".sqlite3")
            if DB_PATH.exists():
                src=sqlite3.connect(DB_PATH,timeout=30)
                dst=sqlite3.connect(old,timeout=30)
                try:
                    src.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    src.backup(dst)
                finally:
                    dst.close()
                    src.close()
            candidate.replace(DB_PATH)
            Path(str(DB_PATH)+"-wal").unlink(missing_ok=True)
            Path(str(DB_PATH)+"-shm").unlink(missing_ok=True)
            try:
                init_db()
                await start_xray()
            except Exception:
                # If the restored configuration cannot be applied, put the prior
                # database back while retaining its dated backup for manual recovery.
                if old and old.exists():
                    rollback=DATA_DIR/".restore-rollback.sqlite3"
                    shutil.copy2(old,rollback)
                    rollback.replace(DB_PATH)
                    Path(str(DB_PATH)+"-wal").unlink(missing_ok=True)
                    Path(str(DB_PATH)+"-shm").unlink(missing_ok=True)
                    init_db()
                    try:
                        await start_xray()
                    except Exception as rollback_error:
                        LOG.exception("Xray failed after restoring the previous database: %s",rollback_error)
                raise
            event("WARNING","Database restore completed; a pre-restore database copy was retained.")
            return {"ok":True,"message":"Restore completed; a pre-restore database copy was retained."}
        except HTTPException:
            raise
        except Exception as e:
            LOG.exception("Database restore failed")
            raise HTTPException(500,"Restore failed; previous database retained when available") from e
        finally:
            candidate.unlink(missing_ok=True)

@app.get("/api/resellers")
async def list_resellers(r:Request):
    require_admin(r); owner=owner_id_for(r)
    with db() as c:
        rows=[dict(x) for x in c.execute("SELECT id,username,quota_bytes,enabled,created_at,parent_id FROM resellers ORDER BY created_at DESC")] if owner is None else [dict(x) for x in c.execute("SELECT id,username,quota_bytes,enabled,created_at,parent_id FROM resellers WHERE parent_id=? ORDER BY created_at DESC",(owner,))]
        for row in rows: row["allocated_bytes"]=reseller_allocated(c,row["id"]); row["remaining_bytes"]=row["quota_bytes"]-row["allocated_bytes"]
    return {"resellers":rows}
@app.post("/api/resellers")
async def create_reseller(r:Request):
    require_admin(r); require_csrf(r); body=await r.json(); owner=owner_id_for(r)
    username=str(body.get("username","")).strip(); password=str(body.get("password","")); quota=body.get("quota_gb")
    if not username or len(username)>48 or not username.replace("_","").replace("-","").isalnum() or username=="admin": raise HTTPException(422,"Invalid username")
    if len(password)<14 or len(password)>256 or not any(x.isalpha() for x in password) or not any(x.isdigit() for x in password): raise HTTPException(422,"Password must be at least 14 characters and include letters and numbers")
    if not isinstance(quota,(int,float)) or isinstance(quota,bool) or not 0.1<=quota<=100000: raise HTTPException(422,"Invalid quota allocation")
    quota_bytes=int(float(quota)*1024**3)
    rid=str(uuid.uuid4())
    try:
        with db() as c:
            c.execute("BEGIN IMMEDIATE")
            if owner is not None:
                assert_reseller_chain_enabled(c,owner)
                parent=c.execute("SELECT quota_bytes FROM resellers WHERE id=?",(owner,)).fetchone()
                if quota_bytes>int(parent["quota_bytes"])-reseller_allocated(c,owner):
                    raise HTTPException(422,"Allocation exceeds your remaining quota")
            c.execute("INSERT INTO resellers(id,username,password_hash,quota_bytes,enabled,parent_id,created_at) VALUES(?,?,?,?,1,?,?)",(rid,username,password_hash(password),quota_bytes,owner,utc_now()))
    except sqlite3.IntegrityError: raise HTTPException(409,"Username already exists")
    event("INFO",f"Created reseller {username!r} with quota allocation.")
    return {"id":rid,"username":username,"quota_bytes":quota_bytes}
@app.patch("/api/resellers/{rid}")
async def update_reseller(rid:str,r:Request):
    require_admin(r); require_csrf(r); body=await r.json(); owner=owner_id_for(r)
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        if owner is not None:
            assert_reseller_chain_enabled(c,owner)
        row=c.execute("SELECT * FROM resellers WHERE id=?",(rid,)).fetchone()
        if not row or (owner is not None and row["parent_id"]!=owner): raise HTTPException(404,"Reseller not found")
        updates={}
        if "username" in body:
            username=str(body["username"]).strip()
            if not username or len(username)>48 or not username.replace("_","").replace("-","").isalnum() or username=="admin":
                raise HTTPException(422,"Invalid username")
            updates["username"]=username
        if "password" in body and body["password"] is not None and str(body["password"]):
            password=str(body["password"])
            if len(password)<14 or len(password)>256 or not any(x.isalpha() for x in password) or not any(x.isdigit() for x in password):
                raise HTTPException(422,"Password must be at least 14 characters and include letters and numbers")
            updates["password_hash"]=password_hash(password)
        if "enabled" in body:
            if not isinstance(body["enabled"],bool): raise HTTPException(422,"enabled must be boolean")
            updates["enabled"]=int(body["enabled"])
        if "quota_gb" in body:
            q=body["quota_gb"]
            if not isinstance(q,(int,float)) or isinstance(q,bool) or not 0.1<=q<=100000: raise HTTPException(422,"Invalid quota")
            amount=int(float(q)*1024**3)
            if amount<reseller_allocated(c,rid): raise HTTPException(422,"Cannot lower allocation below already delegated volume")
            if owner is not None:
                siblings=int(c.execute("SELECT COALESCE(SUM(quota_bytes),0) n FROM resellers WHERE parent_id=? AND id<>?",(owner,rid)).fetchone()["n"] or 0)
                clients=int(c.execute("SELECT COALESCE(SUM(quota_bytes),0) n FROM clients WHERE owner_id=?",(owner,)).fetchone()["n"] or 0)
                parent=c.execute("SELECT quota_bytes,enabled FROM resellers WHERE id=?",(owner,)).fetchone()
                if not parent or not parent["enabled"]: raise HTTPException(403,"Parent reseller account is disabled")
                if siblings+clients+amount>int(parent["quota_bytes"]): raise HTTPException(422,"Allocation exceeds parent quota")
            updates["quota_bytes"]=amount
        if not updates: raise HTTPException(422,"No supported changes")
        try:
            c.execute("UPDATE resellers SET "+", ".join(k+"=?" for k in updates)+" WHERE id=?",(*updates.values(),rid))  # nosec B608: keys are added only by fixed-field validation branches above
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409,"Username already exists") from exc
    return {"ok":True}
@app.delete("/api/resellers/{rid}")
async def delete_reseller(rid:str,r:Request):
    require_admin(r); require_csrf(r); owner=owner_id_for(r)
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        row=c.execute("SELECT * FROM resellers WHERE id=?",(rid,)).fetchone()
        if not row or (owner is not None and row["parent_id"]!=owner): raise HTTPException(404,"Reseller not found")
        has_clients=c.execute("SELECT 1 FROM clients WHERE owner_id=? LIMIT 1",(rid,)).fetchone()
        has_children=c.execute("SELECT 1 FROM resellers WHERE parent_id=? LIMIT 1",(rid,)).fetchone()
        if has_clients or has_children or reseller_allocated(c,rid):
            raise HTTPException(409,"Delete this reseller's clients and child resellers before deleting the account")
        c.execute("DELETE FROM resellers WHERE id=?",(rid,))
    return {"ok":True}

@app.get("/health")
async def health():
    with db() as c:
        c.execute("SELECT 1").fetchone()
    # If Xray is part of this image, a healthy HTTP process alone is not
    # sufficient: report unhealthy until the actual tunnel engine is running.
    xray_required=Path(XRAY_BIN).exists()
    xray_running=bool(not xray_required or (xray_proc is not None and xray_proc.poll() is None))
    payload={"ok":xray_running,"xray":"running" if xray_running else "stopped"}
    return JSONResponse(payload,status_code=200 if xray_running else 503)
@app.exception_handler(Exception)
async def unhandled(r:Request,e:Exception):
    LOG.exception("Unhandled error: %s",e)
    if r.url.path.startswith("/api/"): return JSONResponse({"detail":"Internal server error"},status_code=500)
    return HTMLResponse("<h1>Internal server error</h1>",status_code=500)


@app.post("/api/password")
async def change_password(r: Request):
    require_admin(r)
    require_csrf(r,allow_viewer=True)
    body = await r.json()
    current = str(body.get("current_password", ""))
    new = str(body.get("new_password", ""))
    if len(new) < 14 or len(new) > 256 or not any(ch.isalpha() for ch in new) or not any(ch.isdigit() for ch in new):
        raise HTTPException(400, "New password must be 14–256 characters and include letters and numbers")
    if r.session.get("admin") is True:
        admin_id=r.session.get("admin_id","owner-admin")
        with db() as c:
            row=c.execute("SELECT password_hash FROM panel_admins WHERE id=?",(admin_id,)).fetchone()
            if not row or not verify_password(current,row["password_hash"]):
                raise HTTPException(403,"Current password is incorrect")
            changed=utc_now(); hashed=password_hash(new)
            c.execute("UPDATE panel_admins SET password_hash=?,password_changed_at=? WHERE id=?",(hashed,changed,admin_id))
            if is_root(r):
                c.execute("UPDATE admins SET password_hash=?,password_changed_at=? WHERE id=1",(hashed,changed))
        r.session["admin_password_changed_at"]=changed
        if is_root(r):
            try: (DATA_DIR/"INITIAL_ADMIN_PASSWORD.txt").unlink(missing_ok=True)
            except OSError: event("WARNING","Could not remove the initial administrator password file.")
    else:
        with db() as c:
            row=c.execute("SELECT id,password_hash FROM resellers WHERE id=?",(owner_id_for(r),)).fetchone()
            if not row or not verify_password(current,row["password_hash"]):
                raise HTTPException(403,"Current password is incorrect")
            c.execute("UPDATE resellers SET password_hash=? WHERE id=?",(password_hash(new),owner_id_for(r)))
    event("INFO","Account password changed.")
    return {"ok":True}
# Register the optional platform extension after the core app and helpers are defined.
try:
    from app.extended import install_extended
except ModuleNotFoundError:
    import importlib.util
    _extension_spec = importlib.util.spec_from_file_location("abyss_extended", Path(__file__).with_name("extended.py"))
    _extension_module = importlib.util.module_from_spec(_extension_spec)
    _extension_spec.loader.exec_module(_extension_module)
    install_extended = _extension_module.install_extended
install_extended(app, globals())
@app.get("/api-docs",response_class=HTMLResponse)
async def protected_api_docs(r:Request):
    require_admin(r)
    return HTMLResponse("""<!doctype html><html><head><meta charset="utf-8"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Void API Docs</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css"><style>html,body,button,input,select,textarea{font-family:'Vazirmatn',Tahoma,system-ui,sans-serif}</style></head><body style="margin:0;background:#080b12"><div id="swagger-ui"></div><script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script><script>SwaggerUIBundle({url:'/api-docs/openapi.json',dom_id:'#swagger-ui',deepLinking:true,persistAuthorization:false})</script></body></html>""",headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow"})

@app.get("/api-docs/redoc",response_class=HTMLResponse)
async def protected_redoc_docs(r:Request):
    require_admin(r)
    return HTMLResponse("""<!doctype html><html><head><meta charset="utf-8"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Void API Reference</title><style>html,body,button,input,select,textarea{font-family:'Vazirmatn',Tahoma,system-ui,sans-serif}</style></head><body style="margin:0;background:#080b12"><redoc spec-url="/api-docs/openapi.json"></redoc><script src="https://cdn.jsdelivr.net/npm/redoc@2/bundles/redoc.standalone.js"></script></body></html>""",headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow"})

@app.get("/api-docs/openapi.json")
async def protected_openapi_schema(r:Request):
    require_admin(r)
    return app.openapi()
