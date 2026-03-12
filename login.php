<?php
/**
 * Página de Inicio de Sesión (Login)
 * Sistema de Registro y Autenticación Segura
 */

require_once __DIR__ . '/includes/seguridad.php';
require_once __DIR__ . '/config/firebase.php';
iniciarSesionSegura();

// Si ya tiene sesión activa, redirigir según rol
if (isset($_SESSION['usuario_autenticado']) && $_SESSION['usuario_autenticado'] === true) {
    if (esAdministrador()) {
        header('Location: admin.php');
    } else {
        header('Location: bienvenida.php');
    }
    exit;
}

$mensaje      = '';
$tipoMensaje  = '';
$usuarioInput = '';

// Procesar formulario de login (usuario/contraseña local)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Validar token CSRF
    $tokenCSRF = $_POST['csrf_token'] ?? '';
    if (!validarTokenCSRF($tokenCSRF)) {
        $mensaje     = 'Solicitud inválida. Recargue la página e intente de nuevo.';
        $tipoMensaje = 'error';
    } else {
        // Obtener y sanitizar entradas
        $usuario      = sanitizarEntrada($_POST['usuario'] ?? '');
        $contrasena   = $_POST['contrasena'] ?? '';
        $usuarioInput = $usuario;

        // Validaciones básicas antes de consultar la BD
        if (empty($usuario) || empty($contrasena)) {
            $mensaje     = 'Todos los campos son obligatorios.';
            $tipoMensaje = 'error';
        } else {
            // Autenticar usuario
            $resultado = autenticarUsuario($usuario, $contrasena);

            if ($resultado['exito']) {
                // Regenerar ID de sesión para prevenir session fixation
                session_regenerate_id(true);

                $_SESSION['usuario_autenticado'] = true;
                $_SESSION['nombre_usuario']      = $usuario;
                $_SESSION['hora_login']          = date('Y-m-d H:i:s');
                $_SESSION['rol_usuario']         = $resultado['rol'] ?? 'usuario';

                // Redirigir según el rol del usuario
                if ($_SESSION['rol_usuario'] === 'admin') {
                    header('Location: admin.php');
                } else {
                    header('Location: bienvenida.php');
                }
                exit;
            } else {
                $mensaje     = $resultado['mensaje'];
                $tipoMensaje = 'error';
            }
        }
    }
}

// Generar nuevo token CSRF
$csrfToken = generarTokenCSRF();
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Iniciar Sesión — Sistema Seguro</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="lock-icon">🔒</div>
        <h2>Iniciar Sesión</h2>
        <p class="subtitle">Ingrese sus credenciales para acceder</p>

        <?php if ($mensaje): ?>
            <div class="alert alert-<?= $tipoMensaje === 'success' ? 'success' : 'error' ?>">
                <?= htmlspecialchars($mensaje, ENT_QUOTES, 'UTF-8') ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="login.php" autocomplete="off" novalidate>
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8') ?>">

            <div class="form-group">
                <label for="usuario">Nombre de Usuario</label>
                <input
                    type="text"
                    id="usuario"
                    name="usuario"
                    value="<?= htmlspecialchars($usuarioInput, ENT_QUOTES, 'UTF-8') ?>"
                    placeholder="Ingrese su usuario"
                    maxlength="50"
                    required
                >
            </div>

            <div class="form-group">
                <label for="contrasena">Contraseña</label>
                <input
                    type="password"
                    id="contrasena"
                    name="contrasena"
                    placeholder="Ingrese su contraseña"
                    maxlength="64"
                    required
                >
            </div>

            <button type="submit" class="btn btn-primary">Iniciar Sesión</button>

            <div class="oauth-divider">
                <span></span>
                <strong>o</strong>
                <span></span>
            </div>

            <button type="button" id="btn-google" class="btn btn-google" aria-live="polite">
                <span class="google-icon">G</span>
                Continuar con Google (Firebase)
            </button>

            <div id="firebase-alert" class="alert alert-warning" style="display: none;"></div>
        </form>

        <p class="link-text">
            ¿No tiene cuenta? <a href="registro.php">Registrarse</a>
        </p>
    </div>

    <script>
        // Configuración pública del proyecto Firebase (no contiene secretos).
        window.FIREBASE_CONFIG = {
            apiKey: "<?= addslashes(FIREBASE_API_KEY) ?>",
            authDomain: "<?= addslashes(FIREBASE_AUTH_DOMAIN) ?>",
            projectId: "<?= addslashes(FIREBASE_PROJECT_ID) ?>",
            appId: "<?= addslashes(FIREBASE_APP_ID) ?>",
            messagingSenderId: "<?= addslashes(FIREBASE_MESSAGING_SENDER_ID) ?>",
            measurementId: "<?= addslashes(FIREBASE_MEASUREMENT_ID) ?>"
        };
    </script>
    <script src="https://www.gstatic.com/firebasejs/12.9.0/firebase-app-compat.js" crossorigin="anonymous"></script>
    <script src="https://www.gstatic.com/firebasejs/12.9.0/firebase-auth-compat.js" crossorigin="anonymous"></script>
    <script src="js/firebase-auth.js"></script>
</body>
</html>
