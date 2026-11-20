# Aula Segura – Stanford (prototipo académico)

Prototipo Flask de autenticación y gestión básica de tareas para la Guía Práctica N.º 04. No es una aplicación oficial ni está afiliada a Stanford.

## Estructura

- `app.py`: aplicación Flask, autenticación, sesiones, recuperación y tareas.
- `templates/index.html`: interfaz HTML con formularios CSRF.
- `static/app.js`: lectura segura del token desde el fragmento del enlace de recuperación.
- `static/password-recommendations.js`: ayuda visual de longitud de contraseña (no sustituye validación del servidor).
- `test_auth.py`: suite automatizada.
- `requirements.txt`: dependencias.
- `Procfile`: comando de inicio para Render/Gunicorn.

## Ejecutar en Windows (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest -v test_auth.py
python -m pytest -v test_auth.py --junitxml=resultados.xml
python app.py
```

Abrir `http://127.0.0.1:5000`.

## Variables de entorno

En desarrollo, la aplicación genera una clave temporal si no existe `SECRET_KEY`. En producción, configura una clave fija y privada:

- `SECRET_KEY`: clave aleatoria larga generada fuera del repositorio.
- `PRODUCTION=1`: activa cookies `Secure` y HSTS.
- `DATABASE`: ruta de base de datos. En hosting debe apuntar a almacenamiento persistente si se necesita conservar datos.
- `BASE_URL`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`: configuración para SMTP_SSL de recuperación.
- `TRUST_PROXY=1`: solo si se ha confirmado que el proveedor y la cadena de proxy permiten confiar en un salto `X-Forwarded-For`.

No publiques `.env`, secretos, contraseñas SMTP ni bases de datos con información real.

## Despliegue Render

- Runtime: Python 3
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn "app:create_app()" --workers 1 --threads 2 --access-logfile -`
- Variables: `SECRET_KEY` y `PRODUCTION=1`.

**Limitaciones que deben declararse:** el sistema de archivos del plan gratuito de Render es efímero; SQLite puede perder datos al reiniciar o desplegar. Para persistencia, usar una base de datos administrada (por ejemplo PostgreSQL) o un disco persistente disponible en el plan elegido. El envío SMTP de este prototipo requiere un servidor compatible; si el hosting bloquea SMTP, integrar un proveedor de correo por HTTPS antes de afirmar que la recuperación por correo está operativa.

## Controles implementados en el código

Argon2id; consultas SQL parametrizadas; mensajes genéricos en login; limitación progresiva por cuenta e IP (la IP depende de la configuración del proxy); sesiones registradas en servidor con vencimiento de 30 minutos; regeneración del identificador al autenticar; revocación de sesiones al cambiar/restablecer contraseña; tokens de recuperación aleatorios con digest SHA-256, vencimiento de 15 minutos y consumo de un solo uso; CSRF en POST; cabeceras de seguridad; renderizado con autoescape de Jinja.

La suite ampliada incluida en esta entrega debe ejecutarse en el entorno Windows del equipo antes de reportar sus resultados. Las cinco pruebas PASSED que aparecen en las capturas corresponden a la ejecución anterior, no constituyen por sí mismas una ejecución de esta versión corregida.
