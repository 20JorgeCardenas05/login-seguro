<?php
/**
 * Página de Registro de Usuario
 * Sistema de Registro y Autenticación Segura
 */

require_once __DIR__ . '/includes/seguridad.php';
iniciarSesionSegura();

$mensaje      = '';
$tipoMensaje  = '';
$usuarioInput = '';

// Procesar formulario de registro
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Validar token CSRF
    $tokenCSRF = $_POST['csrf_token'] ?? '';
    if (!validarTokenCSRF($tokenCSRF)) {
        $mensaje     = 'Solicitud inválida. Recargue la página e intente de nuevo.';
        $tipoMensaje = 'error';
    } else {
        // Obtener y sanitizar entradas
        $usuario        = sanitizarEntrada($_POST['usuario'] ?? '');
        $contrasena     = $_POST['contrasena'] ?? '';  // No sanitizar la contraseña (altera el valor)
        $confirmar      = $_POST['confirmar_contrasena'] ?? '';
        $usuarioInput   = $usuario;

        // Verificar que las contraseñas coincidan
        if ($contrasena !== $confirmar) {
            $mensaje     = 'Las contraseñas no coinciden.';
            $tipoMensaje = 'error';
        } else {
            // Registrar usuario
            $resultado = registrarUsuario($usuario, $contrasena);
            if ($resultado['exito']) {
                $mensaje      = $resultado['mensaje'] . ' Ahora puede iniciar sesión.';
                $tipoMensaje  = 'success';
                $usuarioInput = '';
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
    <title>Registro — Sistema Seguro</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="lock-icon">🔐</div>
        <h2>Crear Cuenta</h2>
        <p class="subtitle">Complete los campos para registrarse</p>

        <?php if ($mensaje): ?>
            <div class="alert alert-<?= $tipoMensaje === 'success' ? 'success' : 'error' ?>">
                <?= htmlspecialchars($mensaje, ENT_QUOTES, 'UTF-8') ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="registro.php" autocomplete="off" novalidate>
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8') ?>">

            <div class="form-group">
                <label for="usuario">Nombre de Usuario</label>
                <input
                    type="text"
                    id="usuario"
                    name="usuario"
                    value="<?= htmlspecialchars($usuarioInput, ENT_QUOTES, 'UTF-8') ?>"
                    placeholder="Ej: usuario_123"
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
                    placeholder="Mínimo 8 caracteres"
                    maxlength="64"
                    required
                >
                <div class="strength-bar" id="strengthBar"></div>
                <p class="password-requirements">
                    Debe contener: mayúscula, minúscula, número y carácter especial.
                </p>
            </div>

            <div class="form-group">
                <label for="confirmar_contrasena">Confirmar Contraseña</label>
                <input
                    type="password"
                    id="confirmar_contrasena"
                    name="confirmar_contrasena"
                    placeholder="Repita su contraseña"
                    maxlength="64"
                    required
                >
            </div>

            <button type="submit" class="btn btn-primary">Registrarse</button>
        </form>

        <p class="link-text">
            ¿Ya tiene cuenta? <a href="login.php">Iniciar Sesión</a>
        </p>
    </div>

    <script>
        // Indicador visual de fuerza de contraseña (lado cliente)
        const passInput   = document.getElementById('contrasena');
        const strengthBar = document.getElementById('strengthBar');

        passInput.addEventListener('input', function () {
            const val   = this.value;
            let score   = 0;

            if (val.length >= 8)                          score++;
            if (/[A-Z]/.test(val) && /[a-z]/.test(val))  score++;
            if (/[0-9]/.test(val))                        score++;
            if (/[^A-Za-z0-9]/.test(val))                 score++;

            strengthBar.className = 'strength-bar';
            if (val.length === 0) {
                strengthBar.className = 'strength-bar';
            } else if (score <= 1) {
                strengthBar.classList.add('strength-weak');
            } else if (score <= 3) {
                strengthBar.classList.add('strength-medium');
            } else {
                strengthBar.classList.add('strength-strong');
            }
        });

        // Validación de coincidencia de contraseñas (lado cliente)
        const confirmInput = document.getElementById('confirmar_contrasena');
        confirmInput.addEventListener('input', function () {
            if (this.value !== passInput.value && this.value.length > 0) {
                this.classList.add('input-error');
            } else {
                this.classList.remove('input-error');
            }
        });
    </script>
</body>
</html>
