<?php
/**
 * Página principal — redirige al login
 */
require_once __DIR__ . '/includes/seguridad.php';
iniciarSesionSegura();

header('Location: login.php');
exit;
