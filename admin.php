<?php
/**
 * Panel de Administración — Registro de Usuarios
 * Sistema de Registro y Autenticación Segura
 */

require_once __DIR__ . '/includes/seguridad.php';
iniciarSesionSegura();

// Verificar que el usuario esté autenticado
if (!isset($_SESSION['usuario_autenticado']) || $_SESSION['usuario_autenticado'] !== true) {
    header('Location: login.php');
    exit;
}

// Verificar que el usuario sea administrador
if (!esAdministrador()) {
    header('Location: bienvenida.php');
    exit;
}

$nombreUsuario = htmlspecialchars($_SESSION['nombre_usuario'] ?? '', ENT_QUOTES, 'UTF-8');
$totalUsuarios = contarUsuarios();
$usuarios      = obtenerTodosLosUsuarios();

// Generar iniciales para avatar
function obtenerIniciales(string $nombre): string
{
    $partes = explode(' ', $nombre);
    $iniciales = '';
    foreach ($partes as $parte) {
        $iniciales .= mb_strtoupper(mb_substr($parte, 0, 1));
    }
    return mb_substr($iniciales, 0, 2);
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Panel de Administración — Sistema Seguro</title>
    <link rel="stylesheet" href="css/styles.css">
    <link rel="stylesheet" href="css/admin.css">
</head>
<body class="admin-body">

    <!-- ═══ NAVBAR ═══ -->
    <nav class="admin-navbar">
        <div class="navbar-left">
            <span class="navbar-logo">🔒</span>
            <span class="navbar-brand">SecureUni <span class="brand-highlight">Dev</span></span>
            <span class="navbar-role-badge">👑 ADMINISTRADOR</span>
        </div>
        <div class="navbar-right">
            <span class="navbar-avatar"><?= obtenerIniciales($nombreUsuario) ?></span>
            <span class="navbar-username"><?= $nombreUsuario ?></span>
            <a href="logout.php" class="navbar-logout">↪ Salir</a>
        </div>
    </nav>

    <!-- ═══ CONTENIDO PRINCIPAL ═══ -->
    <main class="admin-main">

        <!-- Encabezado -->
        <div class="admin-header-card">
            <div class="admin-header-content">
                <span class="admin-session-badge">● Sesión iniciada como ADMINISTRADOR</span>
                <h1 class="admin-title">Panel de Control <span class="title-accent">Administrativo</span></h1>
                <p class="admin-welcome">Bienvenido, <strong><?= $nombreUsuario ?></strong>. Tienes acceso completo al sistema.</p>
            </div>
            <div class="admin-header-icon">🛡️</div>
        </div>

        <!-- Tarjetas de estadísticas -->
        <div class="stats-grid">
            <div class="stat-card">
                <span class="stat-label">TOTAL USUARIOS</span>
                <span class="stat-value"><?= $totalUsuarios ?></span>
            </div>
            <div class="stat-card">
                <span class="stat-label">ALGORITMO</span>
                <span class="stat-value">SHA-256</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">MÉTODO</span>
                <span class="stat-value">Salt + Hash</span>
            </div>
        </div>

        <!-- Tabla de usuarios -->
        <div class="admin-card">
            <div class="card-header-row">
                <h3 class="card-title">👥 Registro de Usuarios</h3>
                <a href="admin.php" class="btn-refresh">🔄 Actualizar</a>
            </div>

            <?php if (empty($usuarios)): ?>
                <div class="alert alert-warning">
                    No se encontraron usuarios registrados.
                </div>
            <?php else: ?>
                <div class="table-wrapper">
                    <table class="admin-table">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>👤 USUARIO</th>
                                <th># CONTRASEÑA (HASH SHA-256)</th>
                                <th>ROL</th>
                                <th>REGISTRADO</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($usuarios as $i => $usr): ?>
                                <?php
                                    $hashTruncado = substr($usr['hash_contrasena'], 0, 20) . '...' . substr($usr['hash_contrasena'], -4);
                                    $iniciales    = obtenerIniciales($usr['nombre_usuario']);
                                    $esAdmin      = $usr['rol'] === 'admin';
                                    $fechaFormato = date('d/m/Y, h:i a', strtotime($usr['fecha_creacion']));
                                ?>
                                <tr>
                                    <td><?= $i + 1 ?></td>
                                    <td>
                                        <div class="user-cell">
                                            <span class="user-avatar <?= $esAdmin ? 'avatar-admin' : 'avatar-user' ?>"><?= htmlspecialchars($iniciales, ENT_QUOTES, 'UTF-8') ?></span>
                                            <span><?= htmlspecialchars($usr['nombre_usuario'], ENT_QUOTES, 'UTF-8') ?></span>
                                        </div>
                                    </td>
                                    <td>
                                        <span class="hash-cell">
                                            <span class="hash-lock">🔒</span>
                                            <code><?= htmlspecialchars($hashTruncado, ENT_QUOTES, 'UTF-8') ?></code>
                                        </span>
                                    </td>
                                    <td>
                                        <?php if ($esAdmin): ?>
                                            <span class="role-badge role-admin">⭐ Admin</span>
                                        <?php else: ?>
                                            <span class="role-badge role-user">👤 Usuario</span>
                                        <?php endif; ?>
                                    </td>
                                    <td><?= htmlspecialchars($fechaFormato, ENT_QUOTES, 'UTF-8') ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>

            <div class="security-note">
                <span class="note-icon">ℹ️</span>
                <span>
                    <strong>Nota de seguridad:</strong> Las contraseñas nunca se almacenan en texto plano.
                    Lo que ves son hashes SHA-256 de 256 bits (64 caracteres hexadecimales).
                    Cada usuario tiene una sal única, por eso hashes de contraseñas iguales son diferentes.
                </span>
            </div>
        </div>

    </main>

</body>
</html>
