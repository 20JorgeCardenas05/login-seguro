<?php
/**
 * Configuración de conexión a la base de datos MySQL (XAMPP)
 * Sistema de Registro y Autenticación Segura
 */

define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');           // XAMPP por defecto no tiene contraseña
define('DB_NAME', 'login_seguro');
define('DB_CHARSET', 'utf8mb4');

/**
 * Obtener conexión PDO a la base de datos
 * Usa PDO con prepared statements para prevenir inyección SQL
 */
function obtenerConexion(): PDO
{
    static $conexion = null;

    if ($conexion === null) {
        try {
            $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
            $opciones = [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ];
            $conexion = new PDO($dsn, DB_USER, DB_PASS, $opciones);
        } catch (PDOException $e) {
            // Mensaje genérico para no revelar detalles internos
            error_log("Error de conexión a BD: " . $e->getMessage());
            die("Error interno del servidor. Intente más tarde.");
        }
    }

    return $conexion;
}
