# SDEM Chacao · Detección de Enlaces Maliciosos

Sistema de detección de enlaces maliciosos para empresas de importación y
exportación del Municipio Chacao. Analiza URL y correos con un motor heurístico
que se ejecuta en el navegador: no envía datos a terceros.

## Estructura del proyecto

```
.
├── index.html              # Estructura de la interfaz (solo HTML)
├── css/
│   └── styles.css          # Todos los estilos
├── js/
│   └── app.js              # Lógica: autenticación, motor heurístico y vistas
├── docs/
│   └── SDEM-Chacao.md      # Documentación funcional y matriz de permisos
├── sdem_chacao.zip         # Variante con backend FastAPI + SQLite
└── sdem_chacao_mysql.zip   # Variante con backend FastAPI + MySQL
```

## Ejecución de la demo (solo navegador)

Los módulos `crypto.subtle` y `localStorage` requieren un contexto seguro, así
que conviene servir la carpeta con un servidor local en lugar de abrir
`index.html` con doble clic:

```bash
python3 -m http.server 8000
```

Luego abrir <http://localhost:8000/>.

### Cuentas de prueba

| Usuario  | Contraseña    | Rol                  |
| -------- | ------------- | -------------------- |
| admin    | Admin#2026    | Administrador        |
| analista | Analista#2026 | Analista de seguridad|
| auditor  | Auditor#2026  | Auditor              |
| empleado | Empleado#2026 | Empleado             |
| jperez   | Perez#2026    | Empleado             |
| mgomez   | Gomez#2026    | Analista de seguridad|

Bloqueo de la cuenta tras 3 intentos fallidos.

## Backends (FastAPI)

Cada archivo `.zip` contiene una variante del servidor con la misma interfaz:

- `sdem_chacao.zip` — SQLAlchemy + SQLite.
- `sdem_chacao_mysql.zip` — SQLAlchemy + MySQL (`schema.sql` y `.env.example`
  incluidos).

Pasos generales:

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

Consultar el `README.md` dentro de cada zip para la configuración de la base de
datos.
