# Portal de autenticación

Aplicación de ejemplo para el Ejercicio 1.2. Incluye una interfaz web y una API JSON desarrolladas con Flask, con persistencia en SQLite.

## Requisitos

- Python 3.10 o superior
- `pip`

## Instalación y ejecución

En PowerShell, desde la carpeta del proyecto:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python auth_app.py
```

Abre [http://127.0.0.1:5000](http://127.0.0.1:5000) para usar el prototipo web. La base de datos `auth.db` se crea en el directorio actual al iniciar la aplicación.

Para ejecutar las pruebas:

```powershell
python -m pytest -q
```

## Funcionalidades

- Registro e inicio de sesión desde la interfaz web o la API.
- Contraseñas almacenadas con hash `scrypt`; la longitud permitida es de 10 a 128 caracteres.
- Sesiones con expiración, cierre y revocación al cambiar o restablecer la contraseña.
- Límite de intentos fallidos por cuenta y por IP, con bloqueo progresivo.
- Tokens de restablecimiento de un solo uso y con vencimiento.
- Protección CSRF en formularios web y cabeceras HTTP de seguridad.

## API JSON

Las rutas de la API aceptan y responden JSON:

| Método | Ruta | Descripción |
| --- | --- | --- |
| `POST` | `/register` | Registrar una cuenta (`email`, `password`). |
| `POST` | `/login` | Iniciar sesión; devuelve un token. |
| `GET` | `/me` | Consultar la cuenta autenticada. |
| `POST` | `/logout` | Cerrar la sesión autenticada. |
| `POST` | `/password/change` | Cambiar la contraseña autenticada (`actual`, `nueva`). |
| `POST` | `/password/forgot` | Solicitar un restablecimiento (`email`). |
| `POST` | `/password/reset` | Restablecer la contraseña (`token`, `nueva`). |

Para las rutas que requieren autenticación, envía el token en la cabecera:

```http
Authorization: Bearer <token>
```

La aplicación también incluye páginas web para iniciar sesión, registrarse y acceder al panel.

## Configuración

- `AUTH_DB`: ruta de la base de datos SQLite; por defecto, `auth.db`.
- `COOKIE_SECURE`: al establecerlo en `1`, las cookies se envían únicamente por HTTPS. En desarrollo local queda desactivado.

## Nota

Este proyecto es un prototipo educativo, no una configuración lista para producción. El envío del correo de restablecimiento está simulado y debe implementarse antes de usar esa función en un entorno real. Para producción, también se debe desplegar detrás de HTTPS y configurar `COOKIE_SECURE=1`.
