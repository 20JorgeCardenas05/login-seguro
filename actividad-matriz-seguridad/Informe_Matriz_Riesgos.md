# Evaluación de Seguridad — Sistema de Login Seguro

## Materia: Desarrollo de Software Seguro | 6to Semestre

---

## 1. Descripción del Sistema de Login

El sistema **LoginSeguro** es una aplicación web desarrollada en **PHP** con base de datos **MySQL**, que implementa funcionalidades de registro e inicio de sesión de usuarios con un enfoque en la seguridad.

### Tecnologías utilizadas:
- **Backend:** PHP 8.x
- **Base de datos:** MySQL (PDO con prepared statements)
- **Frontend:** HTML5, CSS3
- **Servidor:** XAMPP (Apache + MySQL)

### Funcionalidades principales:
- Registro de usuarios con validación de contraseñas seguras (mínimo 8 caracteres, mayúsculas, minúsculas, números y caracteres especiales).
- Inicio de sesión con autenticación basada en hash SHA-256 con sal única por usuario.
- Panel de administración exclusivo para usuarios con rol `admin`.
- Protección contra fuerza bruta con bloqueo temporal tras 5 intentos fallidos.
- Protección CSRF mediante tokens únicos por formulario.
- Headers de seguridad HTTP (CSP, X-Frame-Options, X-XSS-Protection, etc.).
- Cookies de sesión configuradas con flags `HttpOnly`, `SameSite=Strict` y `Secure`.

---

## 2. Matriz de Riesgos Completada (basada en ISO/IEC 27001)

| # | Riesgo | Impacto | Probabilidad | Nivel de Riesgo | Medidas de Mitigación Implementadas |
|---|--------|---------|-------------|----------------|--------------------------------------|
| 1 | **Fuga de Información** | Alto | Baja | Medio | Se oculta el header `X-Powered-By` para no revelar la tecnología del servidor. Se envían headers `Cache-Control: no-store` y `Pragma: no-cache` para evitar almacenamiento en caché de datos sensibles. Los mensajes de error son genéricos ("Credenciales inválidas") para no revelar si un usuario existe o no. Se implementa `Referrer-Policy: strict-origin-when-cross-origin` para no filtrar URLs internas. |
| 2 | **Comunicación No Cifrada** | Alto | Media | Alto | Las cookies de sesión están configuradas con el flag `Secure` cuando HTTPS está disponible. Sin embargo, en el entorno de desarrollo local (XAMPP) se utiliza HTTP. **Recomendación:** En producción se debe configurar HTTPS obligatorio con certificado SSL/TLS. |
| 3 | **Inyección SQL** | Crítico | Muy Baja | Bajo | Se utiliza **PDO con prepared statements** (consultas parametrizadas) en todas las interacciones con la base de datos. Los parámetros se vinculan con placeholders (`:usuario`, `:ip`, etc.), impidiendo la inyección de código SQL malicioso. Las entradas del usuario se sanitizan con `htmlspecialchars()`, `trim()` y `stripslashes()`. |
| 4 | **Ataques de Fuerza Bruta** | Alto | Baja | Medio | Se implementa un sistema de **bloqueo temporal**: tras 5 intentos fallidos, la cuenta se bloquea por 15 minutos. Los intentos fallidos se registran en la tabla `intentos_fallidos` considerando tanto el nombre de usuario como la dirección IP. Tras un login exitoso, se limpian los intentos fallidos. Las contraseñas deben cumplir requisitos de complejidad (8+ caracteres, mayúsculas, minúsculas, números, caracteres especiales). |
| 5 | **XSS (Cross-Site Scripting)** | Alto | Baja | Medio | Todas las salidas al HTML se escapan con `htmlspecialchars($valor, ENT_QUOTES, 'UTF-8')`. Se envía el header `X-XSS-Protection: 1; mode=block`. Se implementa **Content Security Policy (CSP)** que restringe las fuentes de scripts (`script-src 'self'`). Se utiliza `X-Content-Type-Options: nosniff` para prevenir MIME-type sniffing. |
| 6 | **CSRF (Cross-Site Request Forgery)** | Alto | Baja | Medio | Se implementan **tokens CSRF** generados con `random_bytes(32)` y almacenados en la sesión. Cada formulario (login y registro) incluye un campo oculto `csrf_token`. El token se valida con `hash_equals()` (comparación en tiempo constante) antes de procesar cualquier solicitud POST. El token se regenera después de cada validación. Las cookies tienen el flag `SameSite=Strict` para prevenir envíos cross-site. Se configura `X-Frame-Options: DENY` para prevenir clickjacking. |
| 7 | **Almacenamiento Inseguro de Contraseñas** | Crítico | Muy Baja | Bajo | Las contraseñas **nunca se almacenan en texto plano**. Se utiliza un esquema de **Salt + Hash SHA-256**: cada usuario tiene una sal criptográficamente segura de 32 bytes (64 caracteres hex) generada con `random_bytes()`. La contraseña se concatena con la sal y se aplica `hash('sha256', sal + contraseña)`. La verificación usa `hash_equals()` para prevenir ataques de timing side-channel. |

---

## 3. Explicación de los Riesgos Identificados y su Investigación

### 3.1 Fuga de Información
**Definición:** Ocurre cuando el sistema revela información sensible (tecnologías usadas, existencia de usuarios, rutas internas, errores detallados) que un atacante puede usar para planificar un ataque.

**En nuestro sistema:** Se mitiga con mensajes de error genéricos que no indican si el usuario existe o no ("Credenciales inválidas. Verifique su usuario y contraseña."), headers que ocultan la tecnología del servidor, y políticas de caché que evitan el almacenamiento de datos sensibles en el navegador.

### 3.2 Comunicación No Cifrada
**Definición:** Cuando los datos viajan entre el cliente y el servidor sin cifrado, un atacante puede interceptar la comunicación mediante ataques Man-in-the-Middle (MitM) y capturar credenciales en texto plano.

**En nuestro sistema:** Las cookies están configuradas para activar el flag `Secure` cuando HTTPS está disponible. En el entorno de desarrollo local (HTTP) esto no se aplica, pero en producción se debe configurar HTTPS con certificado SSL/TLS.

### 3.3 Inyección SQL
**Definición:** La inyección SQL es una vulnerabilidad que permite a un atacante insertar código SQL malicioso en los campos de entrada, manipulando las consultas a la base de datos para acceder, modificar o eliminar información.

**En nuestro sistema:** Todas las consultas utilizan PDO con prepared statements. Por ejemplo:
```php
$sql = "SELECT salt, hash_contrasena, rol FROM usuarios WHERE nombre_usuario = :usuario AND activo = 1";
$stmt = $db->prepare($sql);
$stmt->execute([':usuario' => $usuario]);
```
Los parámetros se vinculan de forma segura, impidiendo la inyección.

### 3.4 Ataques de Fuerza Bruta
**Definición:** Consisten en probar sistemáticamente todas las combinaciones posibles de contraseñas hasta encontrar la correcta. También incluyen ataques de diccionario donde se prueban contraseñas comunes.

**En nuestro sistema:** Se bloquea la cuenta tras 5 intentos fallidos durante 15 minutos, registrando cada intento con usuario, IP y timestamp. Las contraseñas deben ser complejas (8+ caracteres con variedad de tipos).

### 3.5 XSS (Cross-Site Scripting)
**Definición:** Vulnerabilidad que permite a un atacante inyectar scripts maliciosos en páginas web vistas por otros usuarios, pudiendo robar cookies, sesiones o redirigir a sitios maliciosos.

**En nuestro sistema:** Se escapan todas las salidas al HTML con `htmlspecialchars()`, se implementa Content Security Policy, y se habilita la protección XSS nativa del navegador.

### 3.6 CSRF (Cross-Site Request Forgery)
**Definición:** Ataque que fuerza a un usuario autenticado a ejecutar acciones no deseadas en una aplicación web en la que está autenticado, mediante enlaces o formularios maliciosos en otros sitios.

**En nuestro sistema:** Se generan tokens CSRF criptográficamente seguros para cada formulario, se validan en el servidor antes de procesar la solicitud, y las cookies `SameSite=Strict` previenen el envío automático de cookies en peticiones cross-origin.

### 3.7 Almacenamiento Inseguro de Contraseñas
**Definición:** Almacenar contraseñas en texto plano, con cifrado reversible, o con algoritmos de hash débiles (MD5, SHA-1 sin sal), permitiendo que un atacante con acceso a la base de datos obtenga las contraseñas originales.

**En nuestro sistema:** Se usa SHA-256 con sal única por usuario. Cada usuario tiene una sal generada con `random_bytes(32)`, lo que significa que incluso si dos usuarios tienen la misma contraseña, sus hashes serán completamente diferentes. La verificación utiliza `hash_equals()` para evitar ataques de timing.

---

## 4. Norma ISO/IEC 27001

### ¿Qué es la norma ISO/IEC 27001 y cuál es su objetivo?
La **ISO/IEC 27001** es un estándar internacional publicado por la Organización Internacional de Normalización (ISO) y la Comisión Electrotécnica Internacional (IEC). Su objetivo es proporcionar un marco para establecer, implementar, mantener y mejorar continuamente un **Sistema de Gestión de Seguridad de la Información (SGSI)**.

El objetivo principal es **proteger la confidencialidad, integridad y disponibilidad** de la información a través de un proceso de gestión de riesgos, asegurando que se implementen controles de seguridad adecuados y proporcionales a los riesgos identificados.

### ¿Qué es un Sistema de Gestión de Seguridad de la Información (SGSI)?
Un **SGSI** es un conjunto de políticas, procedimientos, directrices y recursos asociados, gestionados colectivamente por una organización para proteger sus activos de información. Incluye:

- **Evaluación de riesgos:** Identificar amenazas y vulnerabilidades que podrían afectar la seguridad de la información.
- **Tratamiento de riesgos:** Implementar controles para mitigar los riesgos identificados.
- **Monitoreo continuo:** Revisar y mejorar constantemente los controles de seguridad.
- **Documentación:** Mantener registros de políticas, procedimientos y evidencias de cumplimiento.

### ¿Cómo se aplica la norma en el desarrollo de software?
En el desarrollo de software, la ISO/IEC 27001 se aplica a través de:

1. **Desarrollo seguro (Anexo A, Control A.8.25):** Establecer reglas para el desarrollo seguro de software, incluyendo validación de entradas, manejo seguro de errores y control de acceso.
2. **Gestión de vulnerabilidades (Anexo A, Control A.8.8):** Identificar y corregir vulnerabilidades técnicas mediante pruebas de penetración y análisis de código.
3. **Control de acceso (Anexo A, Control A.8.3):** Implementar autenticación robusta, gestión de roles y principio de mínimo privilegio.
4. **Cifrado (Anexo A, Control A.8.24):** Proteger datos en tránsito (HTTPS/TLS) y en reposo (hashing de contraseñas).
5. **Registro y monitoreo (Anexo A, Control A.8.15):** Registrar eventos de seguridad (intentos de login fallidos, accesos de administrador) para auditoría.

---

## 5. Recomendaciones para Mejorar la Seguridad

| # | Recomendación | Prioridad | Estado Actual |
|---|---------------|-----------|---------------|
| 1 | **Implementar HTTPS obligatorio** con certificado SSL/TLS para cifrar toda la comunicación. | Alta | No implementado (HTTP en desarrollo) |
| 2 | **Migrar a bcrypt o Argon2** para el hashing de contraseñas, ya que son algoritmos adaptativos más resistentes que SHA-256. | Media | Usa SHA-256 con sal |
| 3 | **Implementar autenticación de dos factores (2FA)** con códigos TOTP (Google Authenticator). | Media | No implementado |
| 4 | **Agregar límite de tasa (rate limiting)** a nivel de servidor para complementar el bloqueo de fuerza bruta a nivel de aplicación. | Media | Solo bloqueo por intentos |
| 5 | **Implementar registro de auditoría completo** con logs de todas las acciones administrativas. | Baja | Parcialmente implementado (registro de sesiones) |
| 6 | **Agregar política de expiración de sesiones** para cerrar sesiones inactivas automáticamente después de un tiempo configurable. | Media | No implementado |
| 7 | **Implementar CAPTCHA** en login y registro para dificultar ataques automatizados. | Baja | No implementado |

---

*Documento generado para la actividad de Evaluación de Seguridad — Desarrollo de Software Seguro, 6to Semestre.*
