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
