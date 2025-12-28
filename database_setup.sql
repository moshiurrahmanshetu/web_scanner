-- Database Setup Script for Mini Web Vulnerability Scanner
-- Run this script in MySQL (phpMyAdmin or MySQL command line)

-- Create database
CREATE DATABASE IF NOT EXISTS web_scanner_db;

-- Use the database
USE web_scanner_db;

-- Create scans table
CREATE TABLE IF NOT EXISTS scans (
    scan_id INT AUTO_INCREMENT PRIMARY KEY,
    target_url VARCHAR(500) NOT NULL,
    scan_time DATETIME NOT NULL
);

-- Create vulnerabilities table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    vuln_id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    vuln_type VARCHAR(50) NOT NULL,
    parameter VARCHAR(200),
    severity VARCHAR(20) NOT NULL,
    payload TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

-- Verify tables were created
SHOW TABLES;

