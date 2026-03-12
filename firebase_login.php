<?php
/**
 * Endpoint seguro para validar un ID Token de Firebase y crear la sesión PHP.
 * Flujo:
 * 1) El navegador obtiene el idToken con Firebase Auth (signInWithPopup).
 * 2) Envía idToken + csrf_token a este endpoint vía fetch POST.
 * 3) Aquí se valida el token contra Google y se crea la sesión tradicional.
 */

require_once __DIR__ . '/includes/seguridad.php';
require_once __DIR__ . '/config/firebase.php';

iniciarSesionSegura();
header('Content-Type: application/json; charset=utf-8');

/**
 * Respuesta JSON corta y consistente.
 */
function responderJson(int $status, array $payload): void
{
    http_response_code($status);
    echo json_encode($payload);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    responderJson(405, ['ok' => false, 'mensaje' => 'Método no permitido']);
}

// Obtener cuerpo (JSON o form-data)
$entrada = json_decode(file_get_contents('php://input'), true);
if (!is_array($entrada) || empty($entrada)) {
    $entrada = $_POST ?? [];
}

$csrfToken = $entrada['csrf_token'] ?? '';
$idToken   = trim($entrada['idToken'] ?? '');

if (!validarTokenCSRF($csrfToken)) {
    responderJson(400, [
        'ok'         => false,
        'mensaje'    => 'Token CSRF inválido. Recargue la página.',
        'csrf_token' => generarTokenCSRF()
    ]);
}

if ($idToken === '') {
    responderJson(400, [
        'ok'         => false,
        'mensaje'    => 'No se recibió el idToken de Firebase.',
        'csrf_token' => generarTokenCSRF()
    ]);
}

$verificacion = verificarIdTokenFirebase($idToken);

if (!$verificacion['valido']) {
    responderJson(401, [
        'ok'         => false,
        'mensaje'    => $verificacion['error'],
        'csrf_token' => generarTokenCSRF()
    ]);
}

$claims       = $verificacion['claims'];
$nombreSesion = $claims['name'] ?? ($claims['email'] ?? $claims['user_id'] ?? 'usuario_firebase');

// Crear sesión tradicional para reutilizar todo el sistema existente.
session_regenerate_id(true);
$_SESSION['usuario_autenticado'] = true;
$_SESSION['nombre_usuario']      = $nombreSesion;
$_SESSION['hora_login']          = date('Y-m-d H:i:s');
$_SESSION['rol_usuario']         = 'usuario';
$_SESSION['proveedor']           = 'firebase';

// Registrar en el historial
registrarSesion($nombreSesion);

// Nuevo token CSRF para futuras acciones.
$nuevoToken = generarTokenCSRF();

responderJson(200, [
    'ok'          => true,
    'redirect'    => 'bienvenida.php',
    'csrf_token'  => $nuevoToken,
    'displayName' => $nombreSesion,
]);

/**
 * Valida un ID Token usando Firebase Auth: accounts:lookup con la API key.
 */
function verificarIdTokenFirebase(string $idToken): array
{
    $url = 'https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=' . urlencode(FIREBASE_API_KEY);
    $payload = json_encode(['idToken' => $idToken]);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 5,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_POST           => true,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_POSTFIELDS     => $payload,
    ]);

    $respuesta = curl_exec($ch);
    $httpCode  = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    if ($respuesta === false) {
        $error = curl_error($ch);
        curl_close($ch);
        error_log('Error cURL accounts:lookup: ' . $error);
        return ['valido' => false, 'error' => 'No se pudo validar el token (conexión).'];
    }

    curl_close($ch);

    $json = json_decode($respuesta, true);

    if ($httpCode !== 200) {
        $detalle = $json['error']['message'] ?? trim($respuesta);
        error_log('accounts:lookup http ' . $httpCode . ' body: ' . $respuesta);
        return ['valido' => false, 'error' => 'Firebase rechazó el token: ' . $detalle];
    }

    if (!isset($json['users'][0])) {
        error_log('accounts:lookup sin usuarios en respuesta: ' . $respuesta);
        return ['valido' => false, 'error' => 'Respuesta de validación no válida.'];
    }

    $user = $json['users'][0];

    $claims = [
        'user_id' => $user['localId'] ?? '',
        'email'   => $user['email'] ?? '',
        'name'    => $user['displayName'] ?? ($user['email'] ?? ''),
    ];

    return ['valido' => true, 'claims' => $claims];
}
