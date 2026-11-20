import os, time, secrets, hashlib, sqlite3, smtplib, hmac
from email.message import EmailMessage
from flask import Flask, request, session, render_template, redirect, url_for, g, abort
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from werkzeug.middleware.proxy_fix import ProxyFix
ph=PasswordHasher(time_cost=3,memory_cost=65536,parallelism=2)
dummy=ph.hash(secrets.token_urlsafe(32))
def digest(x): return hashlib.sha256(x.encode()).hexdigest()
def create_app(config=None):
 a=Flask(__name__); a.config.update(SECRET_KEY=os.getenv('SECRET_KEY') or secrets.token_hex(32), DATABASE=os.getenv('DATABASE','tasksecure.db'), SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.getenv('PRODUCTION')=='1', MAX_CONTENT_LENGTH=16384, RESET_SENDER=None)
 if config:a.config.update(config)
 if os.getenv('TRUST_PROXY')=='1':a.wsgi_app=ProxyFix(a.wsgi_app,x_for=1,x_proto=1)
 def db():
  if 'db' not in g:g.db=sqlite3.connect(a.config['DATABASE'],timeout=15);g.db.row_factory=sqlite3.Row
  return g.db
 @a.teardown_appcontext
 def close(e):
  if 'db' in g:g.db.close()
 with a.app_context():
  db().executescript('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE,password TEXT,role TEXT DEFAULT "student"); CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,uid INTEGER,expires INTEGER); CREATE TABLE IF NOT EXISTS resets(token TEXT PRIMARY KEY,uid INTEGER,expires INTEGER); CREATE TABLE IF NOT EXISTS limits(k TEXT PRIMARY KEY,n INTEGER,level INTEGER,until INTEGER,last INTEGER); CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY,uid INTEGER,title TEXT);');db().commit()
 def audit(event,uid=None):a.logger.warning('security_event=%s uid=%s',event,uid)
 def verify(encoded,p):
  try:return ph.verify(encoded,p)
  except VerificationError:return False
 def keys(email,kind='login'):return [kind+':account:'+digest(email),kind+':ip:'+digest(request.remote_addr or '')]
 def remaining(ks):
  return max([0]+[max(0,r['until']-int(time.time())) for k in ks if (r:=db().execute('SELECT * FROM limits WHERE k=?',(k,)).fetchone())])
 def fail(ks, thresholds=(5,20)):
  now=int(time.time())
  for k,threshold in zip(ks,thresholds):
   r=db().execute('SELECT * FROM limits WHERE k=?',(k,)).fetchone(); n,level=(r['n'],r['level']) if r and now-r['last']<3600 else (0,0);n+=1;until=0
   if n>=threshold:level+=1;n=0;until=now+min(900,60*2**min(level-1,4))
   db().execute('INSERT OR REPLACE INTO limits VALUES(?,?,?,?,?)',(k,n,level,until,now))
  db().commit()
 def user():
  return db().execute('SELECT users.* FROM users JOIN sessions ON users.id=sessions.uid WHERE token=? AND expires>?',(digest(session.get('sid','')),int(time.time()))).fetchone()
 @a.before_request
 def csrf():
  if request.method=='POST' and not hmac.compare_digest(session.get('csrf','!'),request.form.get('csrf','')):abort(400)
  if 'csrf' not in session:session['csrf']=secrets.token_urlsafe(32)
 @a.after_request
 def headers(r):
  r.headers['Cache-Control']='no-store';r.headers['Referrer-Policy']='no-referrer';r.headers['X-Content-Type-Options']='nosniff';r.headers['Content-Security-Policy']="default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'";return r
 def page(title,msg='',status=200,**kw):return render_template('index.html',title=title,msg=msg,**kw),status
 def valid(p):return 12<=len(p)<=128
 def email_input():return request.form.get('email','').strip().lower()[:254]
 def institutional_email(e):
  local,sep,domain=e.rpartition('@')
  domain=domain.lower()
  authorized=domain=='edu.pe' or domain.endswith('.edu.pe')
  return bool(local and sep and authorized)
 @a.route('/',methods=['GET','POST'])
 def login():
  if request.method=='GET':return page('Iniciar sesión')
  e=email_input();p=request.form.get('password','');ks=keys(e);d=db();d.execute('BEGIN IMMEDIATE')
  if not institutional_email(e):return page('Iniciar sesión','Solo se permiten correos institucionales universitarios que terminen en .edu.pe.',400)
  if (wait:=remaining(ks)):return page('Iniciar sesión',f'Acceso temporalmente bloqueado. Reintente en {wait} segundos.',429)
  u=d.execute('SELECT * FROM users WHERE email=?',(e,)).fetchone()
  ok=verify(u['password'] if u else dummy,p[:128]) and len(p)<=128
  if not u or not ok:
   fail(ks);audit('login_failed');wait=remaining(ks);return page('Iniciar sesión',f'Acceso temporalmente bloqueado. Reintente en {wait} segundos.' if wait else 'Correo electrónico o contraseña incorrectos.',429 if wait else 401)
  d.execute('DELETE FROM sessions WHERE token=?',(digest(session.get('sid','')),));d.execute('DELETE FROM limits WHERE k=?',(ks[0],));session.clear();sid=secrets.token_urlsafe(32);session.update(sid=sid,csrf=secrets.token_urlsafe(32));d.execute('INSERT INTO sessions VALUES(?,?,?)',(digest(sid),u['id'],int(time.time())+1800));d.commit();audit('login_success',u['id']);return redirect('/dashboard')
 @a.route('/register',methods=['GET','POST'])
 def register():
  if request.method=='GET':return page('Registro')
  e=email_input();p=request.form.get('password','');ks=keys(e,'register');db().execute('BEGIN IMMEDIATE')
  if remaining(ks):return page('Registro','Demasiadas solicitudes.',429)
  fail(ks,(5,20))
  if not institutional_email(e):return page('Registro','Solo se permiten correos institucionales universitarios que terminen en .edu.pe.',400)
  if not valid(p):return page('Registro','Contraseña de 12 a 128 caracteres requerida.',400)
  db().execute('INSERT OR IGNORE INTO users(email,password) VALUES(?,?)',(e,ph.hash(p)));db().commit();return page('Registro','Solicitud procesada. Puede intentar iniciar sesión.')
 @a.route('/dashboard',methods=['GET','POST'])
 def dashboard():
  u=user()
  if not u:return redirect('/')
  if request.method=='POST':
   title=request.form.get('task','').strip()
   if not 3<=len(title)<=120:abort(400)
   db().execute('INSERT INTO tasks(uid,title) VALUES(?,?)',(u['id'],title));db().commit()
  return page('Panel de tareas',u=u,tasks=db().execute('SELECT * FROM tasks WHERE uid=?',(u['id'],)).fetchall())
 @a.post('/logout')
 def logout():
  db().execute('DELETE FROM sessions WHERE token=?',(digest(session.get('sid','')),));db().commit();session.clear();return redirect('/')
 def replace(uid,p):
  db().execute('UPDATE users SET password=? WHERE id=?',(ph.hash(p),uid));db().execute('DELETE FROM sessions WHERE uid=?',(uid,));db().execute('DELETE FROM resets WHERE uid=?',(uid,));db().commit();audit('password_updated',uid)
 @a.route('/change',methods=['GET','POST'])
 def change():
  u=user()
  if not u:return redirect('/')
  if request.method=='GET':return page('Cambiar contraseña')
  db().execute('BEGIN IMMEDIATE');u=user()
  if not u:return redirect('/')
  p=request.form.get('password','');ks=keys(u['email'],'change')
  if remaining(ks):return page('Cambiar contraseña','Acceso temporalmente bloqueado.',429)
  if not verify(u['password'],request.form.get('current','')[:128]):fail(ks);return page('Cambiar contraseña','Credenciales incorrectas.',401)
  if not valid(p):return page('Cambiar contraseña','Contraseña de 12 a 128 caracteres requerida.',400)
  replace(u['id'],p);session.clear();return redirect('/')
 def send(e,t):
  if a.config['RESET_SENDER']:return a.config['RESET_SENDER'](e,t)
  m=EmailMessage();m['Subject']='Recuperación TaskSecure';m['From']=os.environ['SMTP_USER'];m['To']=e;m.set_content(os.environ['BASE_URL'].rstrip('/')+'/reset#token='+t)
  with smtplib.SMTP_SSL(os.environ['SMTP_HOST'],int(os.getenv('SMTP_PORT','465')),timeout=10) as s:s.login(os.environ['SMTP_USER'],os.environ['SMTP_PASSWORD']);s.send_message(m)
 @a.route('/forgot',methods=['GET','POST'])
 def forgot():
  if request.method=='GET':return page('Recuperar contraseña')
  e=email_input();ks=keys(e,'forgot');db().execute('BEGIN IMMEDIATE')
  if not institutional_email(e):return page('Recuperar contraseña','Solo se permiten correos institucionales universitarios que terminen en .edu.pe.',400)
  if remaining(ks):return page('Recuperar contraseña','Demasiadas solicitudes.',429)
  fail(ks,(3,15));u=db().execute('SELECT * FROM users WHERE email=?',(e,)).fetchone()
  if u:
   t=secrets.token_urlsafe(32);db().execute('BEGIN IMMEDIATE');db().execute('DELETE FROM resets WHERE uid=?',(u['id'],));db().execute('INSERT INTO resets VALUES(?,?,?)',(digest(t),u['id'],int(time.time())+900));db().commit();audit('reset_requested',u['id'])
   try:send(e,t)
   except Exception:audit('mail_delivery_failed',u['id'])
  return page('Recuperar contraseña','Si existe la cuenta, recibirá instrucciones por correo.')
 @a.route('/reset',methods=['GET','POST'])
 def reset():
  if request.method=='GET':return page('Restablecer contraseña')
  p=request.form.get('password','');t=request.form.get('token','');db().execute('BEGIN IMMEDIATE');r=db().execute('SELECT * FROM resets WHERE token=? AND expires>?',(digest(t),int(time.time()))).fetchone()
  if not r:return page('Restablecer contraseña','Enlace inválido o expirado.',400)
  if not valid(p):return page('Restablecer contraseña','Contraseña de 12 a 128 caracteres requerida.',400)
  replace(r['uid'],p);session.clear();return redirect('/')
 return a
if __name__=='__main__':create_app().run()
