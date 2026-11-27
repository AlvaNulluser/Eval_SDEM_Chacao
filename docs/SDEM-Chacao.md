# SDEM Chacao — Documentación funcional

Sistema de Detección de Enlaces Maliciosos para empresas de importación y
exportación del Municipio Chacao. Este documento describe el alcance, las
reglas de negocio y el modelo de datos que comparten la demo y los backends.

## 1. Alcance

El sistema recibe una URL (o el texto de un correo), la evalúa con un motor
heurístico local y devuelve un veredicto con el detalle de los indicadores
encontrados. Además registra cada análisis en una bitácora, administra usuarios
con cuatro niveles de permiso y ubica empresas del municipio en un mapa.

No consulta listas negras externas ni envía el contenido analizado a terceros.

## 2. Roles y permisos

| Rol                   | Nivel | Accesos                                         |
| --------------------- | ----- | ----------------------------------------------- |
| Administrador         | 4     | Todo: usuarios, bitácora, mapa, análisis, panel |
| Analista de seguridad | 3     | Panel, análisis, correos, mapa, bitácora        |
| Auditor               | 2     | Panel, mapa, bitácora (solo lectura)            |
| Empleado              | 1     | Analizador de enlaces y correos                 |

Reglas:

- El acceso se valida en el servidor; ocultar la sección en la interfaz es solo
  presentación.
- Un usuario con nivel 2 (Auditor) no puede analizar aunque conozca la ruta de
  la API.
- Solo el nivel 4 crea usuarios; los niveles 3 y 4 registran empresas.
- Tras tres intentos fallidos la cuenta queda bloqueada hasta que se rehabilite
  en la base.

## 3. Motor heurístico

Cada criterio detectado suma puntos. El puntaje final se limita a 100.

| Criterio                                          | Puntos |
| ------------------------------------------------- | ------ |
| Protocolo no seguro (`http://`)                   | +15    |
| Dirección IP en lugar de dominio                  | +35    |
| Símbolo `@` en la URL                             | +30    |
| Dominio punycode (`xn--`)                         | +30    |
| Más de tres puntos en el dominio                  | +20    |
| TLD de alto riesgo (`.xyz`, `.top`, `.tk`, `.zip`) | +25    |
| Acortador (`bit.ly`, `tinyurl.com`, `t.co`, …)     | +20    |
| Palabras de phishing (`login`, `clave`, `factura`) | +15    |
| Suplantación de marca (SENIAT, DHL, Maersk, …)     | +40    |
| Codificación hexadecimal (`%XX`)                   | +15    |
| Puerto atípico o inválido                         | +25    |
| URL de más de 75 caracteres                       | +15    |

### 3.1 Umbrales

| Puntaje | Veredicto  |
| ------- | ---------- |
| 0–24    | Seguro     |
| 25–54   | Sospechoso |
| 55–100  | Malicioso  |

Los mismos umbrales (55 / 25) se aplican en la demo y en los backends.

### 3.2 Análisis de correo

1. Se extraen las URL del cuerpo con una expresión regular.
2. Se recorta la puntuación final de cada coincidencia (`,`, `.`, `)`, `;`…).
3. Se deduplican conservando el orden de aparición.
4. Cada enlace se evalúa con el mismo motor y se devuelve la lista completa.

## 4. Modelo de datos

### `users`

| Campo             | Tipo         | Notas                          |
| ----------------- | ------------ | ------------------------------ |
| `id`              | entero       | clave primaria                 |
| `username`        | texto (50)   | único                          |
| `hashed_password` | texto (255)  | bcrypt                         |
| `role`            | texto (50)   | nombre del rol                 |
| `level`           | entero       | 1 a 4                          |
| `failed_attempts` | entero       | intentos fallidos acumulados   |
| `locked`          | booleano     | bloqueo por intentos fallidos  |

### `analysis_history`

| Campo       | Tipo           | Notas                   |
| ----------- | -------------- | ----------------------- |
| `id`        | entero         | clave primaria          |
| `url`       | texto          | URL analizada           |
| `status`    | texto (20)     | veredicto               |
| `score`     | entero         | 0 a 100                 |
| `findings`  | texto          | indicadores separados   |
| `timestamp` | fecha y hora   | índice                  |

### `audit_logs`

| Campo       | Tipo         | Notas                   |
| ----------- | ------------ | ----------------------- |
| `id`        | entero       | clave primaria          |
| `timestamp` | fecha y hora | índice                  |
| `user`      | texto (50)   | índice                  |
| `action`    | texto (50)   | tipo de evento          |
| `detail`    | texto        | descripción del evento  |

### `companies`

| Campo  | Tipo       | Notas          |
| ------ | ---------- | -------------- |
| `id`   | entero     | clave primaria |
| `name` | texto(120) | empresa        |
| `lat`  | decimal    | latitud        |
| `lon`  | decimal    | longitud       |

## 5. API

| Método | Ruta                 | Cuerpo                       | Respuesta                                  |
| ------ | -------------------- | ---------------------------- | ------------------------------------------ |
| POST   | `/api/login`         | `{username, password}`       | `{token, username, role, level}`           |
| POST   | `/api/analyze-url`   | `{url}`                      | `{url, status, score, findings, timestamp}` |
| POST   | `/api/analyze-email` | `{content}`                  | `{extracted_count, results[]}`             |
| GET    | `/api/dashboard`     | —                            | `{metrics, recent[], logs[], companies[]}` |
| POST   | `/api/users`         | `{username, password, role}` | `{message}`                                |
| POST   | `/api/companies`     | `{name, lat, lon}`           | `{message}`                                |

Códigos: `401` sin token o token vencido, `403` permisos insuficientes o cuenta
bloqueada, `400` datos inválidos (usuario repetido, contraseña débil).

## 6. Seguridad

- Contraseñas con bcrypt; nunca se devuelven al cliente.
- Token JWT con vencimiento de 8 horas.
- Contraseña mínima: 8 caracteres, mayúscula, minúscula, número y símbolo.
- Toda salida que provenga de una URL se escapa en el cliente antes de
  insertarse en el DOM.
- La bitácora registra inicio y cierre de sesión, bloqueos, análisis, creación de
  usuarios y registro de empresas.

## 7. Vistas

| Vista               | Visible para            |
| ------------------- | ----------------------- |
| Panel y distribución | niveles 2, 3 y 4        |
| Analizadores        | niveles 1, 3 y 4        |
| Criterios heurísticos | niveles 1, 3 y 4      |
| Últimos análisis    | niveles 2, 3 y 4        |
| Mapa                | niveles 2, 3 y 4        |
| Usuarios            | nivel 4                 |
| Bitácora            | niveles 2, 3 y 4        |
