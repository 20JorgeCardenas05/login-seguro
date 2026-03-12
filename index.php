<?php
/**
 * Página principal — redirige al login
 */
require_once __DIR__ . '/includes/seguridad.php';
// Aunque solo redirige, se conserva la inicializacion de seguridad para mantener
// un punto de entrada consistente con el resto del proyecto.
iniciarSesionSegura();

header('Location: login.php');
exit;
