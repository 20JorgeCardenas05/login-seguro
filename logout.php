<?php
/**
 * Cierre de Sesión (Logout)
 * Sistema de Registro y Autenticación Segura
 */

require_once __DIR__ . '/includes/seguridad.php';
iniciarSesionSegura();

// Destruir todas las variables de sesión
$_SESSION = [];

// Destruir la cookie de sesión con los mismos flags seguros
$params = session_get_cookie_params();
setcookie(
    session_name(),
    '',
    time() - 42000,
    $params['path'],
    $params['domain'],
    $params['secure'],
    $params['httponly']
);

// Destruir la sesión
session_destroy();

// Redirigir al login
header('Location: login.php');
exit;
