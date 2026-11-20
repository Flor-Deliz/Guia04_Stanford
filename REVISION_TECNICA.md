# Revisión técnica de Aula Segura – Stanford

## Alcance

Se revisaron los archivos `app.py` y `test_auth.py` compartidos por el estudiante y se integraron con la plantilla `templates/index.html` del ZIP del proyecto. Se preparó una versión corregida y una suite ampliada. La sintaxis Python fue comprobada con `py_compile`; no fue posible ejecutar pytest en el entorno de preparación porque Flask/argon2-cffi no estaban instalados y el entorno no tuvo acceso a Internet para instalarlos.

## Cambios realizados

1. Se centralizó la creación de la aplicación mediante `create_app()` y se mantuvo el comando Gunicorn compatible con Render.
2. Se reforzó el requisito de `SECRET_KEY` cuando `PRODUCTION=1`.
3. Se mantuvo Argon2id para el almacenamiento de contraseñas.
4. Se implementaron límites progresivos por cuenta e IP; la dirección IP real detrás del proxy requiere configurar y validar `TRUST_PROXY` según el proveedor.
5. Se corrigió el conteo de solicitudes de registro para que sea un límite de abuso del endpoint y no un fallo de login.
6. Se conservó el mensaje genérico de credenciales incorrectas y la política de correo `.edu.pe`.
7. Se mantuvieron sesiones de servidor con 30 minutos de vigencia, regeneración tras login y revocación al cambiar/restablecer contraseña.
8. Se hizo atómico el consumo del token de recuperación y el cambio de contraseña, para reducir el riesgo de reutilización concurrente.
9. Se añadió JavaScript para leer `#token=...` del enlace de recuperación y completar el formulario; el fragmento se elimina del historial visible. El correo real todavía requiere variables SMTP válidas y una prueba de entrega.
10. Se añadieron pruebas para CSRF, rotación de sesión, revocación de sesiones, expiración de token, límite por IP y cabeceras.
11. Se amplió `.gitignore` para excluir bases de datos, secretos, entornos virtuales, cachés y reportes locales.

## Resultado de pruebas: distinguir versiones

La captura del estudiante demuestra que la versión anterior ejecutó cinco pruebas y obtuvo `5 passed` (incluye `test_invalid`, `test_brute`, `test_reset_reuse`, `test_expired` y `test_institutional_email_required`). La suite ampliada de esta entrega contiene más casos y debe ejecutarse nuevamente en el equipo con `python -m pytest -v test_auth.py`. No se debe afirmar que la suite ampliada pasó hasta obtener la salida real.

## Limitaciones pendientes de validación en el entorno del estudiante

- Ejecutar la suite ampliada y guardar `resultados.xml` generado realmente.
- Probar el dominio Render y las rutas de login, registro, dashboard, cambio y recuperación.
- Probar entrega SMTP real; el código registra el fallo sin revelar secretos, pero el envío no se confirma solo por solicitar la recuperación.
- Configurar un proveedor de correo por HTTPS si el plan de hosting bloquea SMTP.
- Configurar almacenamiento persistente o PostgreSQL; el disco efímero del plan gratuito puede perder SQLite.
- Verificar la IP cliente detrás del proxy antes de activar `TRUST_PROXY=1`.
- Tomar capturas reales del sitio desplegado para las cinco evidencias de la plantilla.
- El código actual no implementa autorización por roles ni CRUD completo de tareas; no se deben declarar esas funciones como realizadas.
