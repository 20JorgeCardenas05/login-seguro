<?php
/**
 * Página de Bienvenida (área protegida)
 * Sistema de Registro y Autenticación Segura
 */

session_start();

// Verificar que el usuario esté autenticado
if (!isset($_SESSION['usuario_autenticado']) || $_SESSION['usuario_autenticado'] !== true) {
    header('Location: login.php');
    exit;
}

$nombreUsuario = htmlspecialchars($_SESSION['nombre_usuario'] ?? '', ENT_QUOTES, 'UTF-8');
$horaLogin     = $_SESSION['hora_login'] ?? '';
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Bienvenido — Sistema Seguro</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container welcome-container">
        <div class="lock-icon">✅</div>
        <h2>¡Bienvenido!</h2>

        <div class="user-badge">
            <?= $nombreUsuario ?>
        </div>

        <p>Ha iniciado sesión exitosamente.</p>
        <p style="font-size: 0.82rem; color: #999; margin-bottom: 24px;">
            Sesión iniciada: <?= htmlspecialchars($horaLogin, ENT_QUOTES, 'UTF-8') ?>
        </p>

        <div class="alert alert-success">
            Su autenticación fue verificada mediante hash SHA-256 con sal única.
            Sus credenciales nunca se almacenan en texto plano.
        </div>

        <a href="logout.php" class="btn btn-logout">Cerrar Sesión</a>
    </div>
</body>
</html>
