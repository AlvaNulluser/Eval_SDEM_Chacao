# SDEM Chacao (Versión MySQL)
Sistema de Detección de Enlaces Maliciosos para empresas de importación y exportación del Municipio Chacao.

## 1. Preparar la base de datos MySQL
1. Inicia tu servidor MySQL (XAMPP, Laragon, WAMP o MySQL Server).
2. Ejecuta el script `schema.sql` en phpMyAdmin o en tu cliente MySQL para crear la base de datos `sdem_chacao`.
3. Renombra el archivo `.env.example` a `.env` y coloca tus credenciales de MySQL (`MYSQL_USER`, `MYSQL_PASSWORD`, etc.) y tu propia `SECRET_KEY`.

> Si ya tenías una base creada con una versión anterior del esquema, volvé a crear las tablas
> desde cero: los timestamps pasaron de `VARCHAR` a `DATETIME` y se agregaron índices.

## 2. Instalar dependencias y arrancar el servidor
```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

## 3. Acceder al sistema
Abre `http://127.0.0.1:8000` en tu navegador.
- **Admin:** `admin` / `Admin#2026`
- **Analista:** `analista` / `Analista#2026`
- **Auditor:** `auditor` / `Auditor#2026`
- **Empleado:** `empleado` / `Empleado#2026`

## 4. Roles y permisos
La matriz de permisos se valida en el backend, no solo en la interfaz:

| Rol | Nivel | Accesos |
| --- | --- | --- |
| Administrador | 4 | Todo: usuarios, bitácora, mapa, análisis, panel |
| Analista de seguridad | 3 | Panel, análisis, correos, mapa, bitácora |
| Auditor | 2 | Panel, mapa, bitácora (solo lectura) |
| Empleado | 1 | Analizador de enlaces y correos |

## 5. Pruebas
Los tests usan SQLite en un directorio temporal, así que no necesitan un servidor MySQL:
```bash
pip install -r requirements-dev.txt
pytest
```

## 6. Configuración
- `SECRET_KEY`: clave usada para firmar los tokens JWT. **Definila en `.env`**; sin ella se
  usa una clave de desarrollo conocida.
- `DATABASE_URL`: si está definida, reemplaza la cadena de conexión de MySQL
  (por ejemplo `DATABASE_URL=sqlite:///./local.db`). Los tests la usan.

## 7. Estructura
```
main.py              Punto de entrada para `uvicorn main:app`
app/
  main.py            Rutas y lógica de la API
  database.py        Modelos y conexión SQLAlchemy
static/
  index.html         Interfaz
  app.js             Lógica del cliente
  vendor/            Tailwind y Leaflet incluidos localmente (sin CDN)
tests/               Suite de pytest
schema.sql           Esquema MySQL
```
