<?php
/**
 * Funciones de seguridad: Hashing, Salting, Validación
 * Sistema de Registro y Autenticación Segura
 */

require_once __DIR__ . '/../config/database.php';

// Este modulo centraliza la seguridad compartida del proyecto: sesiones seguras,
// headers HTTP, validacion de entradas, hashing, autenticacion, CSRF y auditoria.

// ══════════════════════════════════════════
// INICIALIZACIÓN SEGURA DE SESIÓN Y HEADERS
// ══════════════════════════════════════════

/**
 * Inicia la sesión con parámetros seguros y envía headers de seguridad HTTP.
 * Debe llamarse ANTES de cualquier salida HTML.
 */
function iniciarSesionSegura(): void
{
    // Configurar cookies de sesión con flags de seguridad
    $esHTTPS = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'domain'   => '',
        'secure'   => $esHTTPS,      // Solo enviar cookie por HTTPS cuando esté disponible
        'httponly'  => true,          // Prevenir acceso JavaScript a la cookie (HttpOnly)
        'samesite'  => 'Strict',     // Prevenir envío cross-site (SameSite)
    ]);

    session_start();

    // ─── Headers de seguridad HTTP ───

    // Prevenir clickjacking: no permitir que la página se cargue en iframes
    header('X-Frame-Options: DENY');

    // Prevenir MIME-type sniffing
    header('X-Content-Type-Options: nosniff');

    // Habilitar protección XSS del navegador
    header('X-XSS-Protection: 1; mode=block');

    // Permitir popups cross-origin usados por Firebase Auth sin bloquear window.close/window.closed
    header('Cross-Origin-Opener-Policy: same-origin-allow-popups');

    // Ocultar información del servidor (X-Powered-By)
    header_remove('X-Powered-By');

    // Política de seguridad de contenido (CSP)
    header(
        "Content-Security-Policy: " .
        "default-src 'self'; " .
        "script-src 'self' 'unsafe-inline' https://www.gstatic.com https://www.googleapis.com https://apis.google.com; " .
        "style-src 'self' 'unsafe-inline'; " .
        "img-src 'self' data: https://www.gstatic.com https://lh3.googleusercontent.com; " .
        "font-src 'self' https://www.gstatic.com https://fonts.gstatic.com; " .
        "connect-src 'self' https://www.googleapis.com https://securetoken.googleapis.com https://identitytoolkit.googleapis.com https://www.gstatic.com; " .
        "frame-src 'self' https://accounts.google.com https://*.firebaseapp.com; " .
        "form-action 'self'; " .
        "frame-ancestors 'none'; " .
        "base-uri 'self'"
    );

    // Política de referencia: no enviar referrer a otros dominios
    header('Referrer-Policy: strict-origin-when-cross-origin');

    // Controlar permisos del navegador
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');

    // Cache control para páginas con datos sensibles
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
}

// ─── Constantes de seguridad ───
define('MAX_INTENTOS_FALLIDOS', 5);         // Máximo de intentos antes de bloqueo
define('TIEMPO_BLOQUEO_MINUTOS', 15);       // Minutos de bloqueo tras exceder intentos
define('LONGITUD_SAL', 32);                 // Bytes para generar la sal
define('MIN_LONGITUD_CONTRASENA', 8);       // Mínimo de caracteres en contraseña
define('MAX_LONGITUD_CONTRASENA', 64);      // Máximo de caracteres en contraseña
define('MAX_LONGITUD_USUARIO', 50);         // Máximo de caracteres en nombre de usuario

// ══════════════════════════════════════════
// FUNCIONES DE HASHING Y SALTING
// ══════════════════════════════════════════

/**
 * Genera una sal criptográficamente segura
 * @return string  Sal en formato hexadecimal (64 caracteres)
 */
function generarSal(): string
{
    return bin2hex(random_bytes(LONGITUD_SAL));
}

/**
 * Genera el hash SHA-256 de la contraseña concatenada con la sal
 * @param string $contrasena  Contraseña en texto plano
 * @param string $sal         Sal única del usuario
 * @return string             Hash SHA-256 en hexadecimal (64 caracteres)
 */
function generarHash(string $contrasena, string $sal): string
{
    // Concatenar sal + contraseña y aplicar SHA-256
    $cadena = $sal . $contrasena;
    return hash('sha256', $cadena);
}

/**
 * Verifica que una contraseña coincida con el hash almacenado
 * Usa comparación en tiempo constante para evitar ataques de timing
 * @param string $contrasena       Contraseña ingresada por el usuario
 * @param string $sal              Sal almacenada del usuario
 * @param string $hashAlmacenado   Hash almacenado del usuario
 * @return bool                    true si la contraseña es correcta
 */
function verificarHash(string $contrasena, string $sal, string $hashAlmacenado): bool
{
    $hashCalculado = generarHash($contrasena, $sal);
    // hash_equals previene ataques de timing side-channel
    return hash_equals($hashAlmacenado, $hashCalculado);
}

// ══════════════════════════════════════════
// FUNCIONES DE VALIDACIÓN DE ENTRADAS
// ══════════════════════════════════════════

/**
 * Sanitiza una cadena de texto para prevenir XSS
 * @param string $entrada  Texto a sanitizar
 * @return string          Texto sanitizado
 */
function sanitizarEntrada(string $entrada): string
{
    $entrada = trim($entrada);
    $entrada = stripslashes($entrada);
    $entrada = htmlspecialchars($entrada, ENT_QUOTES, 'UTF-8');
    return $entrada;
}

/**
 * Valida el nombre de usuario
 * @param string $usuario  Nombre de usuario a validar
 * @return array           ['valido' => bool, 'mensaje' => string]
 */
function validarUsuario(string $usuario): array
{
    if (empty($usuario)) {
        return ['valido' => false, 'mensaje' => 'El nombre de usuario es obligatorio.'];
    }

    if (strlen($usuario) < 3) {
        return ['valido' => false, 'mensaje' => 'El nombre de usuario debe tener al menos 3 caracteres.'];
    }

    if (strlen($usuario) > MAX_LONGITUD_USUARIO) {
        return ['valido' => false, 'mensaje' => 'El nombre de usuario no debe exceder ' . MAX_LONGITUD_USUARIO . ' caracteres.'];
    }

    // Solo letras, números y guiones bajos
    if (!preg_match('/^[a-zA-Z0-9_]+$/', $usuario)) {
        return ['valido' => false, 'mensaje' => 'El nombre de usuario solo puede contener letras, números y guiones bajos.'];
    }

    return ['valido' => true, 'mensaje' => ''];
}

/**
 * Valida la contraseña según requisitos de seguridad
 * @param string $contrasena  Contraseña a validar
 * @return array              ['valido' => bool, 'mensaje' => string]
 */
function validarContrasena(string $contrasena): array
{
    if (empty($contrasena)) {
        return ['valido' => false, 'mensaje' => 'La contraseña es obligatoria.'];
    }

    if (strlen($contrasena) < MIN_LONGITUD_CONTRASENA) {
        return ['valido' => false, 'mensaje' => 'La contraseña debe tener al menos ' . MIN_LONGITUD_CONTRASENA . ' caracteres.'];
    }

    if (strlen($contrasena) > MAX_LONGITUD_CONTRASENA) {
        return ['valido' => false, 'mensaje' => 'La contraseña no debe exceder ' . MAX_LONGITUD_CONTRASENA . ' caracteres.'];
    }

    if (!preg_match('/[A-Z]/', $contrasena)) {
        return ['valido' => false, 'mensaje' => 'La contraseña debe contener al menos una letra mayúscula.'];
    }

    if (!preg_match('/[a-z]/', $contrasena)) {
        return ['valido' => false, 'mensaje' => 'La contraseña debe contener al menos una letra minúscula.'];
    }

    if (!preg_match('/[0-9]/', $contrasena)) {
        return ['valido' => false, 'mensaje' => 'La contraseña debe contener al menos un número.'];
    }

    if (!preg_match('/[!@#$%^&*()_+\-=\[\]{};\':\"\\\\|,.<>\/?]/', $contrasena)) {
        return ['valido' => false, 'mensaje' => 'La contraseña debe contener al menos un carácter especial.'];
    }

    return ['valido' => true, 'mensaje' => ''];
}

// ══════════════════════════════════════════
// FUNCIONES DE PROTECCIÓN CONTRA FUERZA BRUTA
// ══════════════════════════════════════════

/**
 * Obtiene la dirección IP real del cliente
 * @return string  Dirección IP
 */
function obtenerIP(): string
{
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    } elseif (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
    return filter_var(trim($ip), FILTER_VALIDATE_IP) ?: '0.0.0.0';
}

/**
 * Registra un intento fallido de autenticación
 * @param string $usuario  Nombre de usuario intentado
 */
function registrarIntentoFallido(string $usuario): void
{
    $db  = obtenerConexion();
    $sql = "INSERT INTO intentos_fallidos (nombre_usuario, direccion_ip, fecha_intento)
            VALUES (:usuario, :ip, NOW())";
    $stmt = $db->prepare($sql);
    $stmt->execute([
        ':usuario' => $usuario,
        ':ip'      => obtenerIP()
    ]);
}

/**
 * Verifica si el usuario/IP está bloqueado por exceso de intentos fallidos
 * @param string $usuario  Nombre de usuario
 * @return array           ['bloqueado' => bool, 'minutos_restantes' => int]
 */
function verificarBloqueo(string $usuario): array
{
    $db  = obtenerConexion();
    $sql = "SELECT COUNT(*) as intentos, MAX(fecha_intento) as ultimo_intento
            FROM intentos_fallidos
            WHERE (nombre_usuario = :usuario OR direccion_ip = :ip)
              AND fecha_intento > DATE_SUB(NOW(), INTERVAL :minutos MINUTE)";
    $stmt = $db->prepare($sql);
    $stmt->execute([
        ':usuario' => $usuario,
        ':ip'      => obtenerIP(),
        ':minutos' => TIEMPO_BLOQUEO_MINUTOS
    ]);
    $resultado = $stmt->fetch();

    if ($resultado && (int)$resultado['intentos'] >= MAX_INTENTOS_FALLIDOS) {
        // Calcular minutos restantes de bloqueo
        $ultimoIntento   = strtotime($resultado['ultimo_intento']);
        $finBloqueo      = $ultimoIntento + (TIEMPO_BLOQUEO_MINUTOS * 60);
        $minutosRestantes = max(1, (int)ceil(($finBloqueo - time()) / 60));

        return ['bloqueado' => true, 'minutos_restantes' => $minutosRestantes];
    }

    return ['bloqueado' => false, 'minutos_restantes' => 0];
}

/**
 * Limpia los intentos fallidos después de un login exitoso
 * @param string $usuario  Nombre de usuario
 */
function limpiarIntentosFallidos(string $usuario): void
{
    $db  = obtenerConexion();
    $sql = "DELETE FROM intentos_fallidos
            WHERE nombre_usuario = :usuario AND direccion_ip = :ip";
    $stmt = $db->prepare($sql);
    $stmt->execute([
        ':usuario' => $usuario,
        ':ip'      => obtenerIP()
    ]);
}

// ══════════════════════════════════════════
// FUNCIONES DE GESTIÓN DE USUARIOS
// ══════════════════════════════════════════

/**
 * Verifica si un nombre de usuario ya existe en la base de datos
 * @param string $usuario  Nombre de usuario
 * @return bool            true si ya existe
 */
function existeUsuario(string $usuario): bool
{
    $db   = obtenerConexion();
    $sql  = "SELECT COUNT(*) FROM usuarios WHERE nombre_usuario = :usuario";
    $stmt = $db->prepare($sql);
    $stmt->execute([':usuario' => $usuario]);
    return (int)$stmt->fetchColumn() > 0;
}

/**
 * Registra un nuevo usuario en la base de datos
 * @param string $usuario     Nombre de usuario
 * @param string $contrasena  Contraseña en texto plano
 * @return array              ['exito' => bool, 'mensaje' => string]
 */
function registrarUsuario(string $usuario, string $contrasena): array
{
    // Validar usuario
    $valUsuario = validarUsuario($usuario);
    if (!$valUsuario['valido']) {
        return ['exito' => false, 'mensaje' => $valUsuario['mensaje']];
    }

    // Validar contraseña
    $valContrasena = validarContrasena($contrasena);
    if (!$valContrasena['valido']) {
        return ['exito' => false, 'mensaje' => $valContrasena['mensaje']];
    }

    // Verificar existencia
    if (existeUsuario($usuario)) {
        return ['exito' => false, 'mensaje' => 'El nombre de usuario ya está en uso.'];
    }

    // Generar sal y hash
    $sal  = generarSal();
    $hash = generarHash($contrasena, $sal);

    // Almacenar en base de datos
    $db   = obtenerConexion();
    $sql  = "INSERT INTO usuarios (nombre_usuario, salt, hash_contrasena) VALUES (:usuario, :sal, :hash)";
    $stmt = $db->prepare($sql);
    $stmt->execute([
        ':usuario' => $usuario,
        ':sal'     => $sal,
        ':hash'    => $hash
    ]);

    return ['exito' => true, 'mensaje' => 'Usuario registrado exitosamente.'];
}

/**
 * Autentica un usuario comparando su contraseña con el hash almacenado
 * @param string $usuario     Nombre de usuario
 * @param string $contrasena  Contraseña en texto plano
 * @return array              ['exito' => bool, 'mensaje' => string]
 */
function autenticarUsuario(string $usuario, string $contrasena): array
{
    // Verificar bloqueo por fuerza bruta
    $bloqueo = verificarBloqueo($usuario);
    if ($bloqueo['bloqueado']) {
        return [
            'exito'   => false,
            'mensaje' => "Demasiados intentos fallidos. Intente de nuevo en {$bloqueo['minutos_restantes']} minuto(s)."
        ];
    }

    // Buscar usuario en la base de datos
    $db   = obtenerConexion();
    $sql  = "SELECT salt, hash_contrasena, rol FROM usuarios WHERE nombre_usuario = :usuario AND activo = 1";
    $stmt = $db->prepare($sql);
    $stmt->execute([':usuario' => $usuario]);
    $user = $stmt->fetch();

    if (!$user) {
        // Registrar intento fallido incluso si el usuario no existe
        // para no revelar si el usuario existe o no
        registrarIntentoFallido($usuario);
        // MENSAJE GENÉRICO: no revelar si el usuario existe o no
        return ['exito' => false, 'mensaje' => 'Credenciales inválidas. Verifique su usuario y contraseña.'];
    }

    // Verificar hash de la contraseña
    if (verificarHash($contrasena, $user['salt'], $user['hash_contrasena'])) {
        // Login exitoso — limpiar intentos fallidos
        limpiarIntentosFallidos($usuario);
        // Registrar la sesión en el historial
        registrarSesion($usuario);
        return ['exito' => true, 'mensaje' => 'Autenticación exitosa.', 'rol' => $user['rol']];
    }

    // Contraseña incorrecta
    registrarIntentoFallido($usuario);
    return ['exito' => false, 'mensaje' => 'Credenciales inválidas. Verifique su usuario y contraseña.'];
}

// ══════════════════════════════════════════
// FUNCIONES DE REGISTRO DE SESIONES (ADMIN)
// ══════════════════════════════════════════

/**
 * Registra un inicio de sesión exitoso en el historial
 * @param string $usuario  Nombre de usuario que inició sesión
 */
function registrarSesion(string $usuario): void
{
    $db  = obtenerConexion();
    $sql = "INSERT INTO registro_sesiones (nombre_usuario, direccion_ip, fecha_login)
            VALUES (:usuario, :ip, NOW())";
    $stmt = $db->prepare($sql);
    $stmt->execute([
        ':usuario' => $usuario,
        ':ip'      => obtenerIP()
    ]);
}

/**
 * Obtiene el historial de todos los inicios de sesión (para administradores)
 * @param int $limite  Número máximo de registros a devolver
 * @return array       Lista de sesiones registradas
 */
function obtenerHistorialSesiones(int $limite = 100): array
{
    $db  = obtenerConexion();
    $sql = "SELECT rs.nombre_usuario, rs.direccion_ip, rs.fecha_login
            FROM registro_sesiones rs
            ORDER BY rs.fecha_login DESC
            LIMIT :limite";
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':limite', $limite, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll();
}

/**
 * Verifica si el usuario actual tiene rol de administrador
 * @return bool  true si es administrador
 */
function esAdministrador(): bool
{
    return isset($_SESSION['rol_usuario']) && $_SESSION['rol_usuario'] === 'admin';
}

/**
 * Obtiene todos los usuarios registrados (para el panel de administración)
 * @return array  Lista de usuarios con sus datos (sin contraseña en texto plano)
 */
function obtenerTodosLosUsuarios(): array
{
    $db  = obtenerConexion();
    $sql = "SELECT id, nombre_usuario, email, hash_contrasena, proveedor, rol, fecha_creacion
            FROM usuarios
            ORDER BY id ASC";
    $stmt = $db->prepare($sql);
    $stmt->execute();
    return $stmt->fetchAll();
}

/**
 * Busca o crea un usuario de Firebase en la base de datos.
 * Si ya existe (por email), devuelve su rol actual.
 * Si no existe, lo crea con rol 'usuario'.
 * @param string $email  Email del usuario de Google
 * @param string $nombre Nombre para mostrar
 * @return array         ['rol' => string]
 */
function obtenerOCrearUsuarioFirebase(string $email, string $nombre): array
{
    $db = obtenerConexion();

    // Buscar por email
    $sql  = "SELECT rol FROM usuarios WHERE email = :email AND activo = 1";
    $stmt = $db->prepare($sql);
    $stmt->execute([':email' => $email]);
    $user = $stmt->fetch();

    if ($user) {
        return ['rol' => $user['rol']];
    }

    // Generar un nombre_usuario único basado en el email
    $base = preg_replace('/[^a-zA-Z0-9_]/', '_', explode('@', $email)[0]);
    $nombreUsuario = substr($base, 0, 45);

    // Verificar si el nombre_usuario ya existe y añadir sufijo si es necesario
    $sqlCheck = "SELECT COUNT(*) FROM usuarios WHERE nombre_usuario = :usuario";
    $stmtCheck = $db->prepare($sqlCheck);
    $stmtCheck->execute([':usuario' => $nombreUsuario]);
    if ((int)$stmtCheck->fetchColumn() > 0) {
        $nombreUsuario = substr($base, 0, 42) . '_' . bin2hex(random_bytes(2));
    }

    // Insertar nuevo usuario Firebase
    $sql = "INSERT INTO usuarios (nombre_usuario, email, salt, hash_contrasena, proveedor, rol)
            VALUES (:usuario, :email, '', '', 'firebase', 'usuario')";
    $stmt = $db->prepare($sql);
    $stmt->execute([
        ':usuario' => $nombreUsuario,
        ':email'   => $email
    ]);

    return ['rol' => 'usuario'];
}

/**
 * Cambia el rol de un usuario (admin ↔ usuario)
 * @param int $idUsuario  ID del usuario a modificar
 * @return bool           true si se actualizó
 */
function cambiarRolUsuario(int $idUsuario): bool
{
    $db  = obtenerConexion();
    $sql = "UPDATE usuarios
            SET rol = CASE WHEN rol = 'admin' THEN 'usuario' ELSE 'admin' END
            WHERE id = :id";
    $stmt = $db->prepare($sql);
    $stmt->execute([':id' => $idUsuario]);
    return $stmt->rowCount() > 0;
}

/**
 * Obtiene el total de usuarios registrados
 * @return int  Número de usuarios
 */
function contarUsuarios(): int
{
    $db   = obtenerConexion();
    $sql  = "SELECT COUNT(*) FROM usuarios";
    $stmt = $db->prepare($sql);
    $stmt->execute();
    return (int)$stmt->fetchColumn();
}

/**
 * Genera un token CSRF y lo almacena en la sesión
 * @return string  Token CSRF
 */
function generarTokenCSRF(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Valida un token CSRF recibido desde un formulario
 * @param string $token  Token recibido
 * @return bool          true si el token es válido
 */
function validarTokenCSRF(string $token): bool
{
    if (empty($_SESSION['csrf_token'])) {
        return false;
    }
    $valido = hash_equals($_SESSION['csrf_token'], $token);
    // Regenerar token después de la validación
    unset($_SESSION['csrf_token']);
    return $valido;
}
