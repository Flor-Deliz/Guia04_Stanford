import pytest,sqlite3
from app import create_app
@pytest.fixture
def setup(tmp_path):
 tokens=[];a=create_app({'TESTING':True,'DATABASE':str(tmp_path/'test.db'),'RESET_SENDER':lambda e,t:tokens.append(t)});c=a.test_client()
 def post(path,**fields):
  c.get(path if path!='/logout' else '/');
  with c.session_transaction() as s:fields['csrf']=s['csrf']
  return c.post(path,data=fields)
 post('/register',email='a@institucion.edu.pe',password='Password12345!');return a,c,post,tokens

def test_invalid(setup):
 a,c,p,t=setup
 response=p('/',email='a@institucion.edu.pe',password='wrong')
 assert response.status_code==401
 assert b'Correo electr\xc3\xb3nico o contrase\xc3\xb1a incorrectos.' in response.data

def test_brute(setup):
 a,c,p,t=setup
 for _ in range(4):assert p('/',email='a@institucion.edu.pe',password='wrong').status_code==401
 assert p('/',email='a@institucion.edu.pe',password='wrong').status_code==429

def test_reset_reuse(setup):
 a,c,p,t=setup;p('/forgot',email='a@institucion.edu.pe');assert p('/reset',token=t[0],password='NewPassword123!').status_code==302;assert p('/reset',token=t[0],password='NewPassword123!').status_code==400

def test_expired(setup):
 a,c,p,t=setup;assert p('/',email='a@institucion.edu.pe',password='Password12345!').status_code==302
 with sqlite3.connect(a.config['DATABASE']) as d:d.execute('UPDATE sessions SET expires=0')
 assert c.get('/dashboard').status_code==302

def test_institutional_email_required(setup):
 a,c,p,t=setup
 assert p('/register',email='a@gmail.com',password='Password12345!').status_code==400
 assert p('/',email='a@gmail.com',password='Password12345!').status_code==400
 assert p('/forgot',email='a@gmail.com').status_code==400
 assert p('/register',email='a@unsaac.edu.pe',password='Password12345!').status_code==200
 assert p('/register',email='a@estudiantes.unsaac.edu.pe',password='Password12345!').status_code==200
 assert p('/register',email='a@universidad.edu.pe',password='Password12345!').status_code==200
