"""
Database Configuration Module
Handles MySQL database connection and initialization
"""

import mysql.connector
from mysql.connector import Error
from datetime import datetime


class DatabaseManager:
    """Manages MySQL database connections and operations"""
    
    def __init__(self, host='localhost', user='root', password='', database='web_scanner_db'):
        """
        Initialize database connection parameters
        
        Args:
            host: MySQL host (default: localhost)
            user: MySQL username (default: root)
            password: MySQL password (default: empty for XAMPP)
            database: Database name (default: web_scanner_db)
        """
        self.host = host
        self.user = user
        self.password = password
        self.database = database
        self.connection = None
        self.cursor = None
    
    def connect(self):
        """Establish connection to MySQL database"""
        try:
            self.connection = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.database
            )
            if self.connection.is_connected():
                self.cursor = self.connection.cursor()
                return True
        except Error as e:
            # Error will be handled by calling code
            return False
    
    def disconnect(self):
        """Close database connection"""
        if self.connection and self.connection.is_connected():
            if self.cursor:
                self.cursor.close()
            self.connection.close()
    
    def create_database(self):
        """Create the database if it doesn't exist"""
        try:
            # Connect without specifying database
            temp_conn = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password
            )
            temp_cursor = temp_conn.cursor()
            temp_cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.database}")
            temp_cursor.close()
            temp_conn.close()
            return True
        except Error as e:
            # Error will be handled by calling code
            return False
    
    def create_tables(self):
        """Create required tables if they don't exist"""
        try:
            # Create scans table
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id INT AUTO_INCREMENT PRIMARY KEY,
                    target_url VARCHAR(500) NOT NULL,
                    scan_time DATETIME NOT NULL
                )
            """)
            
            # Create vulnerabilities table
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    vuln_id INT AUTO_INCREMENT PRIMARY KEY,
                    scan_id INT NOT NULL,
                    vuln_type VARCHAR(50) NOT NULL,
                    parameter VARCHAR(200),
                    severity VARCHAR(20) NOT NULL,
                    payload TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                )
            """)
            
            self.connection.commit()
            return True
        except Error as e:
            # Error will be handled by calling code
            return False
    
    def save_scan(self, target_url):
        """
        Save a new scan record
        
        Args:
            target_url: The URL that was scanned
            
        Returns:
            scan_id: The ID of the created scan record
        """
        try:
            # Ensure connection is active
            if not self.connection or not self.connection.is_connected():
                if not self.connect():
                    return None
            
            # Ensure cursor exists
            if not self.cursor:
                self.cursor = self.connection.cursor()
            
            query = "INSERT INTO scans (target_url, scan_time) VALUES (%s, %s)"
            scan_time = datetime.now()
            self.cursor.execute(query, (target_url, scan_time))
            self.connection.commit()
            return self.cursor.lastrowid
        except Error as e:
            # Error will be handled by calling code
            return None
        except Exception as e:
            # Error will be handled by calling code
            return None
    
    def save_vulnerability(self, scan_id, vuln_type, parameter, severity, payload):
        """
        Save a detected vulnerability
        
        Args:
            scan_id: ID of the associated scan
            vuln_type: Type of vulnerability (e.g., 'SQL Injection', 'XSS')
            parameter: The parameter where vulnerability was found
            severity: Severity level (HIGH, MEDIUM, LOW)
            payload: The payload that triggered the vulnerability
        """
        try:
            query = """
                INSERT INTO vulnerabilities (scan_id, vuln_type, parameter, severity, payload)
                VALUES (%s, %s, %s, %s, %s)
            """
            self.cursor.execute(query, (scan_id, vuln_type, parameter, severity, payload))
            self.connection.commit()
        except Error as e:
            # Error will be handled by calling code
            pass
    
    def get_scan_history(self, limit=10):
        """
        Retrieve recent scan history
        
        Args:
            limit: Number of recent scans to retrieve
            
        Returns:
            List of scan records
        """
        try:
            query = """
                SELECT scan_id, target_url, scan_time 
                FROM scans 
                ORDER BY scan_time DESC 
                LIMIT %s
            """
            self.cursor.execute(query, (limit,))
            return self.cursor.fetchall()
        except Error as e:
            # Error will be handled by calling code
            return []

