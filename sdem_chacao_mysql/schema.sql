CREATE DATABASE IF NOT EXISTS sdem_chacao
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE sdem_chacao;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    level INT NOT NULL,
    failed_attempts INT DEFAULT 0,
    locked TINYINT(1) DEFAULT 0,
    INDEX idx_username (username)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS analysis_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url TEXT NOT NULL,
    status VARCHAR(20) NOT NULL,
    score INT NOT NULL,
    findings TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    INDEX idx_analysis_status (status),
    INDEX idx_analysis_timestamp (timestamp)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    user VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    detail TEXT NOT NULL,
    INDEX idx_audit_timestamp (timestamp),
    INDEX idx_audit_user (user)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS companies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    lat DOUBLE NOT NULL,
    lon DOUBLE NOT NULL
) ENGINE=InnoDB;
