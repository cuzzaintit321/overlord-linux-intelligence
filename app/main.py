import asyncio, csv, io, json, os, platform, secrets, shutil, socket, sqlite3, subprocess, time
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import psutil
from fastapi import FastAPI, HTTPException, Header, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT=Path(__file__).resolve().parent
DB=Path(os.environ.get('OVERLORD_DB',str(ROOT.parent/'data'/'overlord.db')))
TOKEN=os.environ.get('OVERLORD_TOKEN','')
HOSTNAME=socket.gethostname()
CLIENTS=set()
SAMPLES=deque(maxlen=120)

def con():
    DB.parent.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(DB,timeout=10)
    c.row_factory=sqlite3.Row
    c.execute('PRAGMA journal_mode=WAL')
    return c

def initialize():
    with con() as c:
        c.executescript('''CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,at TEXT NOT NULL,kind TEXT NOT NULL,severity TEXT NOT NULL,title TEXT NOT NULL,details TEXT NOT NULL DEFAULT '{}');
        CREATE TABLE IF NOT EXISTS rules(id INTEGER PRIMARY KEY,name TEXT NOT NULL,metric TEXT NOT NULL,operator TEXT NOT NULL,threshold REAL NOT NULL,cooldown INTEGER NOT NULL DEFAULT 300,enabled INTEGER NOT NULL DEFAULT 1,last_trigger REAL NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY,at TEXT NOT NULL,body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS snapshots(id INTEGER PRIMARY KEY,at TEXT NOT NULL,data TEXT NOT NULL);''')
        if not c.execute('SELECT count(*) FROM rules').fetchone()[0]:
            c.executemany('INSERT INTO rules(name,metric,operator,threshold,cooldown) VALUES(?,?,?,?,?)', [('High CPU','cpu','>',90,300),('Memory pressure','memory','>',90,300),('Low disk capacity','disk','>',90,300)])

def stamp(): return datetime.now(timezone.utc).isoformat(timespec='seconds')
def log(kind, severity,title, details=None):
    with con() as c:
        c.execute('INSERT INTO events(at,kind,severity,title,details) VALUES(?,?,?,?,?)',(stamp(),kind,severity,title,json.dumps(details or {})))

def cmd(args, timeout=3):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=timeout,check=False)
        return {'ok':p.returncode==0,'output':(p.stdout or p.stderr)[-12000:],'code':p.returncode}
    except (FileNotFoundError,subprocess.TimeoutExpired,OSError) as e:return {'ok':False,'output':str(e),'code':-1}

def telemetry():
    disk=psutil.disk_usage('/')
    n=psutil.net_io_counters()
    try: temps={k: [{'label':x.label,'current':x.current} for x in v] for k,v in psutil.sensors_temperatures().items()}
    except Exception:temps={}
    return {'at':stamp(),'hostname':HOSTNAME,'os':platform.platform(),'uptime':int(time.time()-psutil.boot_time()),'cpu':psutil.cpu_percent(interval=None),'cpu_per_core':psutil.cpu_percent(interval=None,percpu=True),'load':list(os.getloadavg()) if hasattr(os,'getloadavg') else [],'memory':psutil.virtual_memory().percent,'memory_total':psutil.virtual_memory().total,'swap':psutil.swap_memory().percent,'disk':disk.percent,'disk_free':disk.free,'disk_total':disk.total,'network':{'sent':n.bytes_sent,'received':n.bytes_recv},'temps':temps,'processes':len(psutil.pids())}

def inspect_rules(t):
    with con() as c:
        for r in c.execute('SELECT * FROM rules WHERE enabled=1').fetchall():
            current=t.get(r['metric'])
            if current is None: continue
            matched={'>':lambda a,b:a>b,'>=':lambda a,b:a>=b,'<':lambda a,b:a<b,'<=':lambda a,b:a<=b}.get(r['operator'],lambda a,b:False)(current,r['threshold'])
            if matched and time.time()-r['last_trigger']>=r['cooldown']:
                c.execute('UPDATE rules SET last_trigger=? WHERE id=?',(time.time(),r['id']))
                c.execute('INSERT INTO events(at,kind,severity,title,details) VALUES(?,?,?,?,?)',(stamp(),'rule','warning',r['name'],json.dumps({'metric':r['metric'],'value':current,'threshold':r['threshold']})))

async def collector():
    while True:
        try:
            t=telemetry(); SAMPLES.append(t);inspect_rules(t)
            for ws in list(CLIENTS):
                try:await ws.send_json({'type':'telemetry','data':t})
                except Exception:CLIENTS.discard(ws)
        except Exception:pass
        await asyncio.sleep(2)

@asynccontextmanager
async def lifespan(app):
    initialize();psutil.cpu_percent(None)
    task=asyncio.create_task(collector())
    yield
    task.cancel()
    try:await task
    except asyncio.CancelledError:pass

app=FastAPI(title='OVERLORD Linux Intelligence',version='1.0.0',lifespan=lifespan)
app.mount('/static',StaticFiles(directory=ROOT/'static'),name='static')

def auth(x_overlord_token:Optional[str]=Header(default=None)):
    if TOKEN and not secrets.compare_digest(x_overlord_token or '',TOKEN):raise HTTPException(401,'Invalid token')

def rows(query,params=()):
    with con() as c:return [dict(r) for r in c.execute(query,params).fetchall()]

@app.get('/')
def index():return FileResponse(ROOT/'static'/'index.html')
@app.get('/api/status')
def status(x:Optional[str]=Header(None,alias='x-overlord-token')):
    auth(x);return {'telemetry':telemetry(),'history':list(SAMPLES),'token_required':bool(TOKEN)}
@app.get('/api/processes')
def processes(x:Optional[str]=Header(None,alias='x-overlord-token')):
    auth(x);out=[]
    for p in psutil.process_iter(['pid','name','username','cpu_percent','memory_percent','status']):
        try:out.append(p.info)
        except (psutil.NoSuchProcess,psutil.AccessDenied):continue
    return sorted(out,key=lambda p:(p.get('memory_percent') or 0),reverse=True)[:120]
@app.get('/api/disks')
def disks(x:Optional[str]=Header(None,alias='x-overlord-token')):
    auth(x);out=[]
    for p in psutil.disk_partitions(all=False):
        try:u=psutil.disk_usage(p.mountpoint);out.append({'device':p.device,'mount':p.mountpoint,'fstype':p.fstype,'total':u.total,'used':u.used,'percent':u.percent})
        except (PermissionError,OSError):continue
    return out
@app.get('/api/network')
def network(x:Optional[str]=Header(None,alias='x-overlord-token')):
    auth(x);data=[]
    for name,addresses in psutil.net_if_addrs().items():
        data.append({'name':name,'addresses':[a.address for a in addresses if a.family in (socket.AF_INET,socket.AF_INET6)],'up':psutil.net_if_stats().get(name).isup if name in psutil.net_if_stats() else False})
    return data
@app.get('/api/services')
def services(x:Optional[str]=Header(None,alias='x-overlord-token')):
    auth(x);r=cmd(['systemctl','list-units','--type=service','--all','--no-pager','--no-legend','--plain'],5)
    items=[]
    if r['ok']:
        for l in r['output'].splitlines()[:200]:
            p=l.split(None,4)
            if len(p)>=4:items.append({'name':p[0],'load':p[1],'active':p[2],'sub':p[3],'description':p[4] if len(p)>4 else ''})
    return {'available':r['ok'],'items':items,'error':None if r['ok'] else r['output']}
@app.get('/api/containers')
def containers(x:Optional[str]=Header(None,alias='x-overlord-token')):
    auth(x);r=cmd(['docker','ps','-a','--format','{{json .}}'],5)
    items=[]
    if r['ok']:
        for l in r['output'].splitlines():
            try:items.append(json.loads(l))
            except ValueError:pass
    return {'available':r['ok'],'items':items,'error':None if r['ok'] else 'Docker unavailable or permission denied; monitoring works without Docker.'}
@app.get('/api/events')
def events(limit:int=80,x:Optional[str]=Header(None,alias='x-overlord-token')):
    auth(x);return rows('SELECT * FROM events ORDER BY id DESC LIMIT ?',(max(1,min(limit,300)),))
@app.get('/api/rules')
def rules(x:Optional[str]=Header(None,alias='x-overlord-token')):
    auth(x);return rows('SELECT * FROM rules ORDER BY id DESC')
class Rule(BaseModel):
    name:str=Field(min_length=2,max_length=120)
    metric:str
    operator:str
    threshold:float=Field(ge=0,le=100)
    cooldown:int=Field(default=300,ge=30,le=86400)
    enabled:bool=True
@app.post('/api/rules')
def add_rule(rule:Rule,x:Optional[str]=Header(None,alias='x-overlord-token')):
    auth(x)
    if rule.metric not in ('cpu','memory','disk','swap') or rule.operator not in ('>','>=','<','<='):raise HTTPException(400,'Invalid metric or operator')
    with con() as c:
        rid=c.execute('INSERT INTO rules(name,metric,operator,threshold,cooldown,enabled) VALUES(?,?,?,?,?,?)',(rule.name,rule.metric,rule.operator,rule.threshold,rule.cooldown,int(rule.enabled))).lastrowid
    log('config','info','Automation created',{'rule_id':rid});return {'id':rid}
@app.delete('/api/rules/{rid}')
def delete_rule(rid:int,x:Optional[str]=Header(None,alias='x-overlord-token')):
    auth(x)
    with con() as c:
        if not c.execute('DELETE FROM rules WHERE id=?',(rid,)).rowcount:raise HTTPException(404,'Not found')
    log('config','info','Automation removed',{'rule_id':rid});return {'ok':True}
@app.post('/api/snapshots')
def snapshot(x:Optional[str]=Header(None,alias='x-overlord-token')):
    auth(x)
    data={'telemetry':telemetry(),'disks':disks(x),'network':network(x),'containers':containers(x)}
    with con() as c:rid=c.execute('INSERT INTO snapshots(at,data) VALUES(?,?)',(stamp(),json.dumps(data))).lastrowid
    log('snapshot','info','System inventory snapshot saved',{'id':rid});return {'id':rid}
@app.get('/api/snapshots')
def snapshots(x:Optional[str]=Header(None,alias='x-overlord-token')):
    auth(x);return rows('SELECT id,at FROM snapshots ORDER BY id DESC LIMIT 50')
@app.get('/api/snapshots/{sid}')
def snapshot_detail(sid:int,x:Optional[str]=Header(None,alias='x-overlord-token')):
    auth(x);rr=rows('SELECT * FROM snapshots WHERE id=?',(sid,))
    if not rr:raise HTTPException(404)
    return {'id':rr[0]['id'],'at':rr[0]['at'],'data':json.loads(rr[0]['data'])}
@app.get('/api/export')
def export(x:Optional[str]=Header(None,alias='x-overlord-token')):
    auth(x)
    data={table:rows('SELECT * FROM '+table) for table in ('events','rules','snapshots','notes')}
    return data
@app.get('/api/diagnostics')
def diagnostics(x:Optional[str]=Header(None,alias='x-overlord-token')):
    auth(x);t=telemetry();findings=[]
    for key,display in [('cpu','CPU'),('memory','Memory'),('disk','Root filesystem'),('swap','Swap')]:
        if t[key]>=90:findings.append({'severity':'critical','title':f'{display} at {t[key]}%','recommendation':'Inspect top processes and recent events; avoid automatic restarts.'})
        elif t[key]>=75:findings.append({'severity':'warning','title':f'{display} at {t[key]}%','recommendation':'Review usage trends and capacity.'})
    if not findings:findings=[{'severity':'good','title':'No threshold violations detected','recommendation':'Review logs and system history for intermittent problems.'}]
    return {'findings':findings,'source':'Local telemetry only; heuristic diagnostics, not AI'}
@app.websocket('/ws')
async def ws_endpoint(ws:WebSocket):
    if TOKEN and not secrets.compare_digest(ws.query_params.get('token',''),TOKEN):
        await ws.close(code=1008);return
    await ws.accept();CLIENTS.add(ws)
    try:
        while True:await ws.receive_text()
    except WebSocketDisconnect:pass
    finally:CLIENTS.discard(ws)
