# SDEM Chacao · Detección de Enlaces Maliciosos

Sistema de detección de enlaces maliciosos para empresas de importación y
exportación del Municipio Chacao. Analiza URL y correos con un motor heurístico
y deja trazabilidad de cada análisis, con cuatro roles y bitácora de auditoría.

El repositorio incluye **una demo que corre 100% en el navegador** y **dos
backends FastAPI equivalentes** (SQLite y MySQL) con la misma API y la misma
interfaz. La demo no envía datos a ningún tercero; los backends guardan todo en
una base local.

## Qué incluye

- **Analizador de URL** con doce criterios heurísticos ponderados (protocolo, IP,
  `@`, punycode, subdominios, TLD, acortadores, palabras de phishing,
  suplantación de marcas, codificación hexadecimal, puertos atípicos y longitud).
- **Análisis de correo completo**: extrae los enlaces del cuerpo del mensaje,
  conserva su orden y los evalúa uno por uno.
- **Panel** con métricas por veredicto y distribución de resultados.
- **Mapa de empresas** del municipio sobre Leaflet/OpenStreetMap.
- **Usuarios y roles** con jerarquía de cuatro niveles y bloqueo a los tres
  intentos fallidos.
- **Bitácora de auditoría** de cada acción, exportable a CSV.

## Estructura

```
.
├── index.html                  Demo en el navegador (sin backend)
├── css/styles.css
├── js/app.js
├── docs/SDEM-Chacao.md         Documentación funcional
├── sdem_chacao_sqlite/         Backend FastAPI + SQLite
└── sdem_chacao_mysql/          Backend FastAPI + MySQL
```

Cada backend tiene su propio `README.md`, sus `tests/` y su `app/`.

## Requisitos

- **Demo**: cualquier navegador moderno. No requiere instalar nada.
- **Backends**: Python 3.12 o superior (probado con 3.14).

## Demo en el navegador

```bash
python3 -m http.server 8000
# abrir http://localhost:8000/
```

Los datos viven en `localStorage`, así que cada navegador arranca con un juego de
análisis de ejemplo ya cargado.

### Cuentas de prueba

| Usuario  | Contraseña    | Rol                   |
| -------- | ------------- | --------------------- |
| admin    | Admin#2026    | Administrador         |
| analista | Analista#2026 | Analista de seguridad |
| auditor  | Auditor#2026  | Auditor               |
| empleado | Empleado#2026 | Empleado              |
| jperez   | Perez#2026    | Empleado              |
| mgomez   | Gomez#2026    | Analista de seguridad |

## Backends

### SQLite (cero configuración)

```bash
cd sdem_chacao_sqlite
pip install -r requirements.txt
uvicorn main:app --reload
```

La base `sdem_chacao.db` se crea sola al arrancar.

### MySQL

```bash
cd sdem_chacao_mysql
pip install -r requirements.txt
mysql -u root -p < schema.sql        # crea la base y las tablas
cp .env.example .env                # completar credenciales y SECRET_KEY
uvicorn main:app --reload
```

Ambos backends escuchan en `http://127.0.0.1:8000` y sirven la misma interfaz.

## API

| Método | Ruta                  | Roles (nivel)      |
| ------ | --------------------- | ------------------ |
| POST   | `/api/login`          | público            |
| POST   | `/api/analyze-url`    | 1, 3, 4            |
| POST   | `/api/analyze-email`  | 1, 3, 4            |
| GET    | `/api/dashboard`      | 2, 3, 4            |
| POST   | `/api/users`          | 4 (Administrador)  |
| POST   | `/api/companies`      | 3, 4               |

La autorización se valida **en el servidor**; ocultar una sección en la interfaz
no alcanza.

## Motor heurístico

Cada criterio suma puntos y el total (tope 100) define el veredicto:

| Criterio                                        | Puntos |
| ----------------------------------------------- | ------ |
| Protocolo no seguro (HTTP)                      | +15    |
| IP en lugar de dominio                          | +35    |
| Símbolo `@` en la URL                           | +30    |
| Dominio punycode (`xn--`)                       | +30    |
| Más de tres puntos en el dominio                | +20    |
| TLD de alto riesgo (`.xyz`, `.top`, `.tk`, …)   | +25    |
| Acortador conocido (`bit.ly`, `t.co`, …)        | +20    |
| Palabras de phishing (`login`, `clave`, …)      | +15    |
| Suplantación de marca (SENIAT, DHL, Maersk, …)  | +40    |
| Codificación hexadecimal (`%XX`)                | +15    |
| Puerto atípico o inválido                       | +25    |
| URL de más de 75 caracteres                     | +15    |

| Puntaje | Veredicto    |
| ------- | ------------ |
| 0–24    | Seguro       |
| 25–54   | Sospechoso   |
| 55–100  | Malicioso    |

Los criterios, la matriz de permisos y el modelo de datos están detallados en
[`docs/SDEM-Chacao.md`](docs/SDEM-Chacao.md).

## Roles

| Rol                   | Nivel | Accesos                                        |
| --------------------- | ----- | ---------------------------------------------- |
| Administrador         | 4     | Todo: usuarios, bitácora, mapa, análisis, panel |
| Analista de seguridad | 3     | Panel, análisis, correos, mapa, bitácora        |
| Auditor               | 2     | Panel, mapa, bitácora (solo lectura)            |
| Empleado              | 1     | Analizador de enlaces y correos                 |

## Pruebas

Cada backend trae su suite (13 pruebas) y corre contra un archivo SQLite
temporal, así que no necesita un servidor MySQL:

```bash
cd sdem_chacao_sqlite
pip install -r requirements-dev.txt
pytest
```

## Seguridad

- Contraseñas con bcrypt; tokens JWT firmados con `SECRET_KEY` (definila en
  `.env`; sin ella se usa una clave de desarrollo conocida).
- Bloqueo de la cuenta tras tres intentos fallidos, persistido en la base.
- Autorización por nivel en cada endpoint.
- Salida escapada en el cliente para evitar XSS con las URL analizadas.
- La demo hashea con SHA-256 en `localStorage`: es solo demostración, no un
  esquema de autenticación real.

## Limitaciones conocidas

- El mapa usa tiles de OpenStreetMap: sin internet se ve el marcador y los
  controles, pero no el mapa de fondo. Leaflet y los íconos son locales.
- La variante MySQL está probada con SQLite; requiere un servidor MySQL real
  para verificarse de punta a punta.
- La demo reinicia el contador de intentos fallidos al recargar la página.
