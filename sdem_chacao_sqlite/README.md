# SDEM Chacao (Versión SQLite)
Sistema de Detección de Enlaces Maliciosos para empresas de importación y exportación del Municipio Chacao.

Esta versión guarda los datos en un archivo `sdem_chacao.db` que se crea automáticamente
junto al proyecto. No requiere instalar ni configurar un servidor de base de datos.

## 1. Instalar dependencias y arrancar el servidor
```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

## 2. Acceder al sistema
Abre `http://127.0.0.1:8000` en tu navegador.
- **Admin:** `admin` / `Admin#2026`
- **Analista:** `analista` / `Analista#2026`
- **Auditor:** `auditor` / `Auditor#2026`
- **Empleado:** `empleado` / `Empleado#2026`

## 3. Roles y permisos
La matriz de permisos se valida en el backend, no solo en la interfaz:

| Rol | Nivel | Accesos |
| --- | --- | --- |
| Administrador | 4 | Todo: usuarios, bitácora, mapa, análisis, panel |
| Analista de seguridad | 3 | Panel, análisis, correos, mapa, bitácora |
| Auditor | 2 | Panel, mapa, bitácora (solo lectura) |
| Empleado | 1 | Analizador de enlaces y correos |

## 4. Pruebas
```bash
pip install -r requirements-dev.txt
pytest
```

## 5. Configuración
- `SECRET_KEY`: clave usada para firmar los tokens JWT. Definila como variable de entorno;
  sin ella se usa una clave de desarrollo conocida.
- `DATABASE_URL`: ruta alternativa del archivo SQLite (por ejemplo `sqlite:///./otra.db`).

## 6. Estructura
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
```
