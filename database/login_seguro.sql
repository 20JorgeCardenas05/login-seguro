-- ============================================
-- Script SQL para crear la base de datos
-- Sistema de Registro y Autenticación Segura
-- ============================================

CREATE DATABASE IF NOT EXISTS login_seguro
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE login_seguro;

-- Tabla de usuarios
CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre_usuario VARCHAR(50) NOT NULL UNIQUE,
    salt VARCHAR(64) NOT NULL,
    hash_contrasena VARCHAR(64) NOT NULL,
    rol ENUM('usuario', 'admin') NOT NULL DEFAULT 'usuario',
    fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
    activo TINYINT(1) DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla para registro de intentos fallidos (protección contra fuerza bruta)
CREATE TABLE IF NOT EXISTS intentos_fallidos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre_usuario VARCHAR(50) NOT NULL,
    direccion_ip VARCHAR(45) NOT NULL,
    fecha_intento DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_usuario_ip (nombre_usuario, direccion_ip),
    INDEX idx_fecha (fecha_intento)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla para registro de sesiones (historial de inicios de sesión)
CREATE TABLE IF NOT EXISTS registro_sesiones (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre_usuario VARCHAR(50) NOT NULL,
    direccion_ip VARCHAR(45) NOT NULL,
    fecha_login DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_usuario (nombre_usuario),
    INDEX idx_fecha_login (fecha_login)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Crear usuario administrador por defecto (contraseña: Admin123!)
-- La sal y el hash deben generarse desde la aplicación.
-- Puede ejecutar manualmente:
--   INSERT INTO usuarios (nombre_usuario, salt, hash_contrasena, rol)
--   VALUES ('admin', '<sal_generada>', '<hash_generado>', 'admin');
