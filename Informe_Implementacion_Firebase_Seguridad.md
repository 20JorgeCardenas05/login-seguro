# Informe de Implementación — Firebase Authentication y Seguridad del Sistema

**Proyecto:** Sistema de Registro y Autenticación Segura  
**Autores:** Baltazar Jiménez Juan Pablo · Cárdenas Puente Jorge Rafael  
**Materia:** Desarrollo de Software Seguro — 6.° Semestre  

---

## Índice

1. [Arquitectura General](#1-arquitectura-general)
2. [Implementación de Firebase Authentication (Google)](#2-implementación-de-firebase-authentication-google)
3. [Seguridad en el Almacenamiento de Contraseñas (Salt + SHA-256)](#3-seguridad-en-el-almacenamiento-de-contraseñas-salt--sha-256)
4. [Protección contra Ataques de Fuerza Bruta](#4-protección-contra-ataques-de-fuerza-bruta)
5. [Tokens CSRF](#5-tokens-csrf)
6. [Gestión Segura de Sesiones](#6-gestión-segura-de-sesiones)
7. [Encabezados de Seguridad HTTP](#7-encabezados-de-seguridad-http)
8. [Protección a Nivel de Servidor (.htaccess)](#8-protección-a-nivel-de-servidor-htaccess)
9. [Validación y Sanitización de Entradas](#9-validación-y-sanitización-de-entradas)
10. [Control de Acceso por Roles](#10-control-de-acceso-por-roles)
11. [Cierre Seguro de Sesión](#11-cierre-seguro-de-sesión)
12. [Matriz de Pruebas](#12-matriz-de-pruebas)

---

## 1. Arquitectura General

El sistema es una aplicación web PHP que ofrece **dos vías de autenticación**:

| Vía | Flujo |
|-----|-------|
| **Local** (usuario/contraseña) | Formulario → `login.php` → verifica hash en MySQL → sesión PHP |
| **Firebase** (Google) | Botón Google → popup Firebase Auth → `idToken` → `firebase_login.php` valida token → busca/crea usuario en BD → lee rol → sesión PHP |

Ambos caminos terminan en la misma sesión PHP tradicional (`$_SESSION`) y comparten la **misma tabla `usuarios`**, lo que permite gestionar roles de forma unificada desde el panel de administración sin importar el proveedor de autenticación.

### Estructura de archivos relevante

```
├── config/
│   ├── database.php          # Conexión PDO a MySQL (XAMPP)
│   └── firebase.php          # Constantes de configuración Firebase
├── includes/
│   └── seguridad.php         # Funciones de hash, CSRF, sesión, brute-force
├── js/
│   └── firebase-auth.js      # Lógica cliente: popup Google, envío de idToken
├── database/
│   └── login_seguro.sql      # Script DDL (tablas: usuarios, intentos_fallidos, registro_sesiones)
├── login.php                 # Página de inicio de sesión (local + botón Google)
├── firebase_login.php        # Endpoint que valida el idToken de Firebase
├── registro.php              # Registro de usuario local
├── bienvenida.php            # Área protegida (rol usuario)
├── admin.php                 # Panel administrativo (rol admin)
├── logout.php                # Cierre seguro de sesión
└── .htaccess                 # Reglas de seguridad Apache
```

---

## 2. Implementación de Firebase Authentication (Google)

### Paso 1 — Crear proyecto en Firebase Console

1. Ir a [Firebase Console](https://console.firebase.google.com/) y crear un nuevo proyecto.
2. En **Authentication → Sign-in method**, habilitar el proveedor **Google**.
3. Agregar `localhost` en **Authentication → Settings → Authorized domains** para pruebas locales.

### Paso 2 — Configurar credenciales en el servidor

En `config/firebase.php` se definen las constantes con los valores del proyecto Firebase:

```php
define('FIREBASE_API_KEY',              getenv('FIREBASE_API_KEY')              ?: 'TU_API_KEY');
define('FIREBASE_AUTH_DOMAIN',          getenv('FIREBASE_AUTH_DOMAIN')          ?: 'tu-proyecto.firebaseapp.com');
define('FIREBASE_PROJECT_ID',           getenv('FIREBASE_PROJECT_ID')           ?: 'tu-proyecto');
define('FIREBASE_APP_ID',              getenv('FIREBASE_APP_ID')              ?: '...');
define('FIREBASE_MESSAGING_SENDER_ID', getenv('FIREBASE_MESSAGING_SENDER_ID') ?: '...');
define('FIREBASE_MEASUREMENT_ID',      getenv('FIREBASE_MEASUREMENT_ID')      ?: '...');
```

Estos valores se usan tanto en la validación del servidor como para inyectar la configuración en el JS del cliente. Soportan variables de entorno como alternativa más segura.

### Paso 3 — Inyectar configuración en el cliente

En `login.php` se genera un objeto JavaScript con las constantes PHP:

```php
<script>
    window.FIREBASE_CONFIG = {
        apiKey:            "<?= addslashes(FIREBASE_API_KEY) ?>",
        authDomain:        "<?= addslashes(FIREBASE_AUTH_DOMAIN) ?>",
        projectId:         "<?= addslashes(FIREBASE_PROJECT_ID) ?>",
        appId:             "<?= addslashes(FIREBASE_APP_ID) ?>",
        messagingSenderId: "<?= addslashes(FIREBASE_MESSAGING_SENDER_ID) ?>",
        measurementId:     "<?= addslashes(FIREBASE_MEASUREMENT_ID) ?>"
    };
</script>
```

Se cargan los SDKs compat de Firebase (v12.9.0) desde CDN:

```html
<script src="https://www.gstatic.com/firebasejs/12.9.0/firebase-app-compat.js"></script>
<script src="https://www.gstatic.com/firebasejs/12.9.0/firebase-auth-compat.js"></script>
<script src="js/firebase-auth.js"></script>
```

### Paso 4 — Flujo del cliente (`js/firebase-auth.js`)

1. Verifica que la `apiKey` sea válida (no el placeholder). Si no lo es, deshabilita el botón.
2. Inicializa Firebase con `firebase.initializeApp(config)`.
3. Al hacer clic en el botón **"Continuar con Google"**:
   - Abre popup con `auth.signInWithPopup(provider)`.
   - Obtiene el `idToken` JWT con `result.user.getIdToken()`.
   - Envía un `fetch POST` a `firebase_login.php` con `{ idToken, csrf_token }`.
4. Si el servidor responde `{ ok: true, redirect: "bienvenida.php" }`, redirige.
5. Si hay error, muestra un mensaje amigable mapeado desde los códigos de Firebase (`auth/popup-closed-by-user`, `auth/popup-blocked`, etc.).

### Paso 5 — Validación del token en el servidor (`firebase_login.php`)

1. Recibe el `idToken` vía POST (JSON).
2. **Valida CSRF:** compara `csrf_token` contra `$_SESSION['csrf_token']` con `hash_equals`.
3. **Valida el idToken** llamando a la API de Firebase Identity Toolkit (`accounts:lookup`) vía cURL (con verificación SSL activa).
4. Extrae el **email** del usuario de los claims del token.
5. **Busca o crea al usuario en la BD** mediante `obtenerOCrearUsuarioFirebase(email, nombre)` — si ya existe (por email), devuelve su rol actual; si no, lo inserta con `proveedor = 'firebase'` y `rol = 'usuario'`.
6. Crea la **sesión PHP** con `session_regenerate_id(true)` usando el **rol real** de la BD.
7. Redirige a `admin.php` si es admin, o a `bienvenida.php` si es usuario normal.

### Paso 6 — Persistencia de usuarios Firebase en la BD

Cuando un usuario entra por primera vez con Google, se crea un registro en la tabla `usuarios` con:

| Campo | Valor |
|-------|-------|
| `nombre_usuario` | Derivado del email (parte antes de `@`, sanitizado) |
| `email` | Email de la cuenta Google |
| `salt` | `''` (vacío, no aplica) |
| `hash_contrasena` | `''` (vacío, la autenticación la maneja Google) |
| `proveedor` | `'firebase'` |
| `rol` | `'usuario'` (puede cambiarse desde el panel admin) |

En logins posteriores, `obtenerOCrearUsuarioFirebase()` simplemente lee el rol existente de la BD, permitiendo que un administrador haya promovido al usuario entre sesiones.

### Paso 7 — Compatibilidad con popups (COOP)

Para que `signInWithPopup` funcione sin problemas, se envía el header:

```
Cross-Origin-Opener-Policy: same-origin-allow-popups
```

Configurado tanto en `seguridad.php` como en `.htaccess`.

---

## 3. Seguridad en el Almacenamiento de Contraseñas (Salt + SHA-256)

### Diagrama del flujo

```
┌──────────────┐    ┌──────────────┐    ┌──────────────────────────┐
│  Contraseña  │ +  │  Sal (salt)  │ →  │  SHA-256(sal + password)  │
│  texto plano │    │  32 bytes    │    │  = hash 64 chars hex      │
└──────────────┘    │  (random)    │    └──────────────────────────┘
                    └──────────────┘
```

### Paso 1 — Generar sal única por usuario

```php
function generarSal(): string {
    return bin2hex(random_bytes(32)); // 64 caracteres hexadecimales
}
```

Se usa `random_bytes()` (CSPRNG del sistema operativo), no `rand()` ni `mt_rand()`.

### Paso 2 — Calcular el hash

```php
function generarHash(string $contrasena, string $sal): string {
    return hash('sha256', $sal . $contrasena);
}
```

La sal se concatena **antes** de la contraseña para evitar ataques de extensión de longitud.

### Paso 3 — Almacenar en base de datos

En la tabla `usuarios`:
- `salt VARCHAR(64)` — la sal en hexadecimal (vacío para usuarios Firebase).
- `hash_contrasena VARCHAR(64)` — el hash SHA-256 resultante (vacío para usuarios Firebase).
- `proveedor ENUM('local', 'firebase')` — indica el método de autenticación.
- `email VARCHAR(255)` — email del usuario (usado como identificador único para Firebase).

Ambos se insertan con **prepared statements** (PDO) para prevenir inyección SQL.

### Paso 4 — Verificar al iniciar sesión

```php
function verificarHash(string $contrasena, string $sal, string $hashAlmacenado): bool {
    $hashCalculado = generarHash($contrasena, $sal);
    return hash_equals($hashAlmacenado, $hashCalculado);
}
```

`hash_equals()` realiza una **comparación en tiempo constante**, previniendo ataques de timing side-channel.

### ¿Por qué cada usuario tiene su propia sal?

Si dos usuarios eligen la misma contraseña, sus hashes son diferentes porque cada uno tiene una sal única. Esto anula las **tablas rainbow** (diccionarios precalculados).

---

## 4. Protección contra Ataques de Fuerza Bruta

| Parámetro | Valor |
|-----------|-------|
| Máx. intentos fallidos | 5 |
| Tiempo de bloqueo | 15 minutos |

### Funcionamiento

1. Cada intento fallido se registra en `intentos_fallidos` con el **nombre de usuario** y la **IP del cliente**.
2. Antes de cada intento de login, `verificarBloqueo()` cuenta los intentos en los últimos 15 minutos para **ese usuario O esa IP**.
3. Si se exceden los 5 intentos, se bloquea el acceso y se informa cuántos minutos restan.
4. Tras un login exitoso, `limpiarIntentosFallidos()` elimina los registros previos de ese par usuario/IP.

### Detalle de seguridad: mensajes genéricos

```php
return ['exito' => false, 'mensaje' => 'Credenciales inválidas. Verifique su usuario y contraseña.'];
```

Se usa el mismo mensaje sin importar si el usuario no existe o si la contraseña es incorrecta, para **no revelar la existencia de cuentas**.

---

## 5. Tokens CSRF

### Generación

```php
function generarTokenCSRF(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}
```

### Validación

```php
function validarTokenCSRF(string $token): bool {
    $valido = hash_equals($_SESSION['csrf_token'], $token);
    unset($_SESSION['csrf_token']); // Se regenera después de cada uso
    return $valido;
}
```

- Se inyecta como campo `<input type="hidden">` en los formularios de login y registro.
- En el flujo Firebase, se envía junto con el `idToken` en el cuerpo JSON.
- Tras cada validación, el token se **regenera** (single-use).

---

## 6. Gestión Segura de Sesiones

La función `iniciarSesionSegura()` configura las cookies de sesión con los siguiente flags:

| Flag | Valor | Propósito |
|------|-------|-----------|
| `lifetime` | `0` | Cookie muere al cerrar el navegador |
| `secure` | `true` si HTTPS | No enviar cookie por HTTP plano |
| `httponly` | `true` | Prevenir acceso desde JavaScript (mitiga XSS) |
| `samesite` | `Strict` | Prevenir envío cross-site (mitiga CSRF) |

Tras un login exitoso se llama a `session_regenerate_id(true)` para **prevenir session fixation**: el ID anterior se invalida y se genera uno nuevo.

---

## 7. Encabezados de Seguridad HTTP

Enviados en cada respuesta vía `iniciarSesionSegura()`:

| Header | Valor | Protección |
|--------|-------|------------|
| `X-Frame-Options` | `DENY` | Clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME-type sniffing |
| `X-XSS-Protection` | `1; mode=block` | XSS reflectado (legacy) |
| `Content-Security-Policy` | Política estricta (ver abajo) | XSS, inyección de recursos |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Filtración de URLs |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Abuso de APIs del navegador |
| `Cache-Control` | `no-store, no-cache, must-revalidate` | Datos sensibles en caché |
| `Cross-Origin-Opener-Policy` | `same-origin-allow-popups` | Aislamiento de contexto + popups Firebase |

Se elimina `X-Powered-By` para no revelar la versión de PHP.

### CSP (Content Security Policy) detallada

```
default-src 'self';
script-src  'self' 'unsafe-inline' https://www.gstatic.com https://www.googleapis.com https://apis.google.com;
style-src   'self' 'unsafe-inline';
img-src     'self' data: https://www.gstatic.com https://lh3.googleusercontent.com;
font-src    'self' https://www.gstatic.com https://fonts.gstatic.com;
connect-src 'self' https://www.googleapis.com https://securetoken.googleapis.com
                   https://identitytoolkit.googleapis.com https://www.gstatic.com;
frame-src   'self' https://accounts.google.com https://*.firebaseapp.com;
form-action 'self';
frame-ancestors 'none';
base-uri    'self';
```

Permite solo los dominios estrictamente necesarios para Firebase Auth y bloquea todo lo demás.

---

## 8. Protección a Nivel de Servidor (.htaccess)

| Regla | Efecto |
|-------|--------|
| `Options -Indexes` | Deshabilita listado de directorios |
| `ServerSignature Off` | Oculta versión de Apache |
| `Header unset X-Powered-By` | Elimina header que revela PHP |
| `FilesMatch` para `.sql`, `.log`, `.env`, `.bak`, etc. | Bloquea acceso directo a archivos sensibles |
| `RewriteRule ^(includes\|config)/ - [F,L]` | Prohíbe acceso HTTP a carpetas `includes/` y `config/` |

La carpeta `css/` también tiene su propio `.htaccess` con `Options -Indexes`.

---

## 9. Validación y Sanitización de Entradas

### Sanitización (prevención de XSS)

```php
function sanitizarEntrada(string $entrada): string {
    $entrada = trim($entrada);
    $entrada = stripslashes($entrada);
    $entrada = htmlspecialchars($entrada, ENT_QUOTES, 'UTF-8');
    return $entrada;
}
```

Se aplica a **todos** los campos de texto antes de procesarlos (excepto la contraseña, que no se sanitiza para no alterar su valor).

### Validación de usuario

- Mínimo 3 caracteres, máximo 50.
- Solo letras, números y guiones bajos (`/^[a-zA-Z0-9_]+$/`).

### Validación de contraseña

- Mínimo 8 caracteres, máximo 64.
- Debe contener al menos: 1 mayúscula, 1 minúscula, 1 número, 1 carácter especial.

### Prevención de inyección SQL

Toda consulta usa **PDO con prepared statements** y `ATTR_EMULATE_PREPARES => false`:

```php
$stmt = $db->prepare("SELECT ... WHERE nombre_usuario = :usuario");
$stmt->execute([':usuario' => $usuario]);
```

---

## 10. Control de Acceso por Roles

La tabla `usuarios` tiene los campos `rol ENUM('usuario', 'admin')` y `proveedor ENUM('local', 'firebase')`.

| Página | Acceso requerido | Verificación |
|--------|-----------------||--------------|
| `login.php` | Público | Si ya tiene sesión, redirige según rol |
| `registro.php` | Público | — |
| `bienvenida.php` | Autenticado | `$_SESSION['usuario_autenticado'] === true` |
| `admin.php` | Autenticado + Admin | `esAdministrador()` verifica `$_SESSION['rol_usuario'] === 'admin'` |

Si un usuario normal intenta acceder a `admin.php`, es redirigido a `bienvenida.php`.

### Gestión de Roles desde el Panel de Administración

El panel `admin.php` incluye un botón de **cambio de rol** por cada usuario registrado (tanto locales como Firebase):

1. Se muestra una tabla con todos los usuarios, incluyendo columna de **proveedor** (🔑 Local / 🌐 Google) y botón de acción.
2. El botón **⬆ Hacer Admin** / **⬇ Quitar Admin** envía un POST protegido con CSRF.
3. La función `cambiarRolUsuario(int $idUsuario)` ejecuta un `UPDATE` que alterna el rol:

```php
function cambiarRolUsuario(int $idUsuario): bool {
    $sql = "UPDATE usuarios
            SET rol = CASE WHEN rol = 'admin' THEN 'usuario' ELSE 'admin' END
            WHERE id = :id";
    // ...
}
```

4. Se muestra un mensaje de confirmación tras el cambio.
5. El nuevo rol se aplica en el **próximo inicio de sesión** del usuario afectado.

Esto permite que un administrador **promueva a admin a un usuario que entró con Google**, sin necesidad de que ese usuario tenga contraseña local.

---

## 11. Cierre Seguro de Sesión

En `logout.php` se realizan tres pasos:

1. **Vaciar variables:** `$_SESSION = []`
2. **Destruir cookie:** `setcookie(session_name(), '', time() - 42000, ...)` con los mismos flags seguros.
3. **Destruir sesión:** `session_destroy()`

Esto asegura que el ID de sesión anterior no pueda ser reutilizado.

---

## 12. Matriz de Pruebas

### 12.1 Pruebas Funcionales — Login Local

| ID | Caso de Prueba | Datos de Entrada | Resultado Esperado | Criterio de Aceptación |
|----|----------------|------------------|--------------------|------------------------|
| F-01 | Login exitoso con credenciales válidas | Usuario y contraseña correctos | Redirige a `bienvenida.php` y crea sesión | `$_SESSION['usuario_autenticado'] === true` |
| F-02 | Login con usuario inexistente | Usuario inventado + contraseña | Muestra "Credenciales inválidas" | Mensaje genérico, no revela si el usuario existe |
| F-03 | Login con contraseña incorrecta | Usuario válido + contraseña errónea | Muestra "Credenciales inválidas" | Mismo mensaje que F-02 |
| F-04 | Login con campos vacíos | Ambos campos en blanco | Muestra "Todos los campos son obligatorios" | No se intenta autenticar |
| F-05 | Login de administrador | Credenciales de admin | Redirige a `admin.php` | `$_SESSION['rol_usuario'] === 'admin'` |

### 12.2 Pruebas Funcionales — Registro

| ID | Caso de Prueba | Datos de Entrada | Resultado Esperado | Criterio de Aceptación |
|----|----------------|------------------|--------------------|------------------------|
| R-01 | Registro exitoso | Usuario nuevo + contraseña válida | Mensaje "Usuario registrado exitosamente" | Se inserta en BD con sal y hash |
| R-02 | Registro con usuario duplicado | Usuario ya existente | Muestra "El nombre de usuario ya está en uso" | No se inserta duplicado |
| R-03 | Contraseña sin mayúscula | `password1!` | Muestra error de requisito de mayúscula | Registro rechazado |
| R-04 | Contraseña sin número | `Password!` | Muestra error de requisito de número | Registro rechazado |
| R-05 | Contraseña sin carácter especial | `Password1` | Muestra error de requisito de carácter especial | Registro rechazado |
| R-06 | Contraseña menor a 8 caracteres | `Ab1!` | Muestra error de longitud mínima | Registro rechazado |
| R-07 | Contraseñas no coinciden | Campo confirmar diferente | Muestra "Las contraseñas no coinciden" | Registro rechazado |
| R-08 | Usuario con caracteres inválidos | `user@name` | Muestra error: solo letras, números y `_` | Registro rechazado |

### 12.3 Pruebas Funcionales — Firebase (Google)

| ID | Caso de Prueba | Precondiciones | Resultado Esperado | Criterio de Aceptación |
|----|----------------|----------------|--------------------|------------------------|
| G-01 | Login con Google exitoso | Firebase configurado, cuenta Google válida | Popup se abre, autentica y redirige a `bienvenida.php` | Sesión PHP creada con `proveedor = 'firebase'`, usuario creado en BD |
| G-02 | Popup cerrado por el usuario | — | Muestra "La ventana emergente se cerró" | No se crea sesión, puede reintentar |
| G-03 | Popup bloqueado por navegador | Popups deshabilitados | Muestra "El navegador bloqueó la ventana emergente" | Informa habilitar popups |
| G-04 | Firebase sin configurar | `apiKey` con placeholder | Botón deshabilitado + aviso | No se permite clic |
| G-05 | idToken con `aud` incorrecto | Token de otro proyecto | Servidor rechaza con 401 | Mensaje: "El token no pertenece a este proyecto" |
| G-06 | idToken expirado | Token con `exp` en el pasado | Servidor rechaza con 401 | Mensaje: "El token expiró" |
| G-07 | Segundo login con Google (usuario ya existe) | Mismo email en BD | Lee rol existente de BD, no crea duplicado | Sesión con rol actual (puede ser admin) |
| G-08 | Login con Google de usuario promovido a admin | Admin cambió rol previamente | Redirige a `admin.php` | `$_SESSION['rol_usuario'] === 'admin'` |

### 12.4 Pruebas de Seguridad — CSRF

| ID | Caso de Prueba | Método | Resultado Esperado | Criterio de Aceptación |
|----|----------------|--------|--------------------|------------------------|
| S-01 | Envío de formulario sin token CSRF | POST a `login.php` sin campo `csrf_token` | Muestra "Solicitud inválida" | No se procesa el login |
| S-02 | Envío con token CSRF alterado | Token modificado manualmente | Muestra "Solicitud inválida" | Token rechazado por `hash_equals` |
| S-03 | Reutilización de token CSRF | Reenviar mismo token tras primera petición | Rechazado | Token se elimina tras uso único |
| S-04 | CSRF en endpoint Firebase | POST a `firebase_login.php` sin `csrf_token` | Responde JSON `400` con "Token CSRF inválido" | No se valida el idToken |

### 12.5 Pruebas de Seguridad — Fuerza Bruta

| ID | Caso de Prueba | Método | Resultado Esperado | Criterio de Aceptación |
|----|----------------|--------|--------------------|------------------------|
| B-01 | 5 intentos fallidos consecutivos | Contraseña incorrecta × 5 | Bloqueo de 15 minutos | Cuenta inaccesible durante el periodo |
| B-02 | 6.° intento tras bloqueo | Intento durante el bloqueo | Muestra "Demasiados intentos fallidos" + minutos restantes | Sin consulta de hash en BD |
| B-03 | Login exitoso tras esperar bloqueo | Credenciales correctas pasados 15 min | Login exitoso + limpieza de intentos | Tabla `intentos_fallidos` limpia |

### 12.6 Pruebas de Seguridad — Headers y Acceso

| ID | Caso de Prueba | Método | Resultado Esperado | Criterio de Aceptación |
|----|----------------|--------|--------------------|------------------------|
| H-01 | Verificar header X-Frame-Options | Inspeccionar respuesta HTTP | `DENY` | Presente en todas las páginas |
| H-02 | Verificar CSP | Inspeccionar respuesta HTTP | Política restrictiva con dominios Firebase permitidos | No permite scripts/recursos externos no autorizados |
| H-03 | Acceso directo a `includes/seguridad.php` | GET `/includes/seguridad.php` | HTTP 403 Forbidden | .htaccess bloquea carpeta |
| H-04 | Acceso directo a `config/database.php` | GET `/config/database.php` | HTTP 403 Forbidden | .htaccess bloquea carpeta |
| H-05 | Acceso a `database/login_seguro.sql` | GET `/database/login_seguro.sql` | HTTP 403 Forbidden | FilesMatch bloquea `.sql` |
| H-06 | Listado de directorio raíz | GET `/` sin `index.php` | Redirige a `login.php` (no lista archivos) | `Options -Indexes` activo |

### 12.7 Pruebas de Seguridad — Inyección SQL y XSS

| ID | Caso de Prueba | Datos de Entrada | Resultado Esperado | Criterio de Aceptación |
|----|----------------|------------------|--------------------|------------------------|
| I-01 | SQL injection en campo usuario | `' OR 1=1 --` | Credenciales inválidas (no inyecta) | PDO prepared statements previenen la inyección |
| I-02 | XSS en campo usuario | `<script>alert(1)</script>` | Texto escapado, no se ejecuta script | `htmlspecialchars` neutraliza el payload |
| I-03 | XSS almacenado vía registro | Registrar usuario con nombre `<img onerror=...>` | Rechazado por regex de validación (`^[a-zA-Z0-9_]+$`) | Solo alfanuméricos y guiones bajos permitidos |

### 12.8 Pruebas de Control de Acceso

| ID | Caso de Prueba | Precondiciones | Resultado Esperado | Criterio de Aceptación |
|----|----------------|----------------|--------------------|------------------------|
| A-01 | Acceso a `bienvenida.php` sin sesión | No autenticado | Redirige a `login.php` | `$_SESSION['usuario_autenticado']` no existe |
| A-02 | Acceso a `admin.php` como usuario normal | Sesión con `rol = 'usuario'` | Redirige a `bienvenida.php` | `esAdministrador()` retorna `false` |
| A-03 | Acceso a `admin.php` como admin | Sesión con `rol = 'admin'` | Muestra panel administrativo | `esAdministrador()` retorna `true` |
| A-04 | Navegación tras logout | Sesión destruida, botón "atrás" del navegador | Página no muestra datos (caché deshabilitada) | Headers `Cache-Control: no-store` impiden cache |

### 12.9 Pruebas de Gestión de Roles (Admin)

| ID | Caso de Prueba | Precondiciones | Resultado Esperado | Criterio de Aceptación |
|----|----------------|----------------|--------------------|------------------------|
| RL-01 | Promover usuario local a admin | Admin logueado, usuario local existe | Rol cambia a `admin`, muestra "Rol actualizado correctamente" | BD refleja `rol = 'admin'` para ese usuario |
| RL-02 | Promover usuario Firebase a admin | Admin logueado, usuario Firebase existe | Rol cambia a `admin` | Próximo login con Google redirige a `admin.php` |
| RL-03 | Degradar admin a usuario | Admin logueado, otro admin existe | Rol cambia a `usuario` | BD refleja `rol = 'usuario'` |
| RL-04 | Cambio de rol sin token CSRF | POST directo sin `csrf_token` | Muestra "Token CSRF inválido" | No se modifica el rol |
| RL-05 | Cambio de rol como usuario normal | Sesión con `rol = 'usuario'`, POST a `admin.php` | Redirige a `bienvenida.php` | `esAdministrador()` bloquea el acceso |
| RL-06 | Verificar proveedor en tabla | Usuario local y Firebase en BD | Columna muestra 🔑 Local y 🌐 Google respectivamente | Campo `proveedor` se muestra correctamente |

---

> **Resumen de mecanismos de seguridad implementados:**
> Hashing con sal (SHA-256), protección contra fuerza bruta, tokens CSRF de un solo uso, sesiones seguras (HttpOnly, SameSite, Secure), headers HTTP defensivos (CSP, X-Frame-Options, COOP), validación y sanitización de entradas, prepared statements PDO, control de acceso basado en roles con gestión dinámica desde el panel admin (aplica tanto a usuarios locales como Firebase/Google), persistencia unificada de usuarios en BD, protección de archivos sensibles vía .htaccess, y validación de tokens Firebase en el servidor.
