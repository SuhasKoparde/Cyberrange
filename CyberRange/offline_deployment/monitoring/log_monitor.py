#!/usr/bin/env python3
"""
Cyber Range Monitoring System
Monitors system logs, network traffic, and security events
"""

import os
import json
import time
import logging
import sqlite3
from datetime import datetime
from threading import Thread
import psutil
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cyber_range_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SecurityEventHandler(FileSystemEventHandler):
    """Monitor file system events for security analysis"""
    
    def __init__(self, db_path):
        self.db_path = db_path
        
    def on_modified(self, event):
        if not event.is_directory:
            self.log_event('file_modified', event.src_path)
    
    def on_created(self, event):
        if not event.is_directory:
            self.log_event('file_created', event.src_path)
    
    def on_deleted(self, event):
        if not event.is_directory:
            self.log_event('file_deleted', event.src_path)
    
    def log_event(self, event_type, file_path):
        """Log security events to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO security_events (timestamp, event_type, details, source)
                VALUES (?, ?, ?, ?)
            ''', (datetime.now(), event_type, file_path, 'filesystem'))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Security event logged: {event_type} - {file_path}")
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")

class NetworkMonitor:
    """Monitor network connections and traffic"""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.running = False
    
    def start_monitoring(self):
        """Start network monitoring in background thread"""
        self.running = True
        thread = Thread(target=self._monitor_loop)
        thread.daemon = True
        thread.start()
        logger.info("Network monitoring started")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.running = False
        logger.info("Network monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Monitor network connections
                connections = psutil.net_connections(kind='inet')
                self._analyze_connections(connections)
                
                # Monitor network statistics
                net_stats = psutil.net_io_counters()
                self._log_network_stats(net_stats)
                
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                logger.error(f"Network monitoring error: {e}")
                time.sleep(60)
    
    def _analyze_connections(self, connections):
        """Analyze network connections for suspicious activity"""
        suspicious_ports = [4444, 4445, 1234, 31337, 8080]
        
        for conn in connections:
            if conn.laddr and conn.laddr.port in suspicious_ports:
                self._log_security_event(
                    'suspicious_port',
                    f"Connection on suspicious port {conn.laddr.port}",
                    'network'
                )
            
            # Check for unusual connection patterns
            if conn.status == 'ESTABLISHED' and conn.raddr:
                # Log external connections
                if not conn.raddr.ip.startswith('192.168.'):
                    self._log_security_event(
                        'external_connection',
                        f"External connection to {conn.raddr.ip}:{conn.raddr.port}",
                        'network'
                    )
    
    def _log_network_stats(self, stats):
        """Log network statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO network_stats (timestamp, bytes_sent, bytes_recv, 
                                         packets_sent, packets_recv)
                VALUES (?, ?, ?, ?, ?)
            ''', (datetime.now(), stats.bytes_sent, stats.bytes_recv,
                  stats.packets_sent, stats.packets_recv))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to log network stats: {e}")
    
    def _log_security_event(self, event_type, details, source):
        """Log security events"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO security_events (timestamp, event_type, details, source)
                VALUES (?, ?, ?, ?)
            ''', (datetime.now(), event_type, details, source))
            
            conn.commit()
            conn.close()
            
            logger.warning(f"Security event: {event_type} - {details}")
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")

class SystemMonitor:
    """Monitor system resources and processes"""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.running = False
    
    def start_monitoring(self):
        """Start system monitoring"""
        self.running = True
        thread = Thread(target=self._monitor_loop)
        thread.daemon = True
        thread.start()
        logger.info("System monitoring started")
    
    def stop_monitoring(self):
        """Stop system monitoring"""
        self.running = False
        logger.info("System monitoring stopped")
    
    def _monitor_loop(self):
        """Main system monitoring loop"""
        while self.running:
            try:
                # Monitor system resources
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                self._log_system_stats(cpu_percent, memory, disk)
                
                # Monitor processes
                self._monitor_processes()
                
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"System monitoring error: {e}")
                time.sleep(60)
    
    def _log_system_stats(self, cpu_percent, memory, disk):
        """Log system statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO system_stats (timestamp, cpu_percent, memory_percent,
                                        memory_used, memory_total, disk_percent,
                                        disk_used, disk_total)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (datetime.now(), cpu_percent, memory.percent,
                  memory.used, memory.total, disk.percent,
                  disk.used, disk.total))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to log system stats: {e}")
    
    def _monitor_processes(self):
        """Monitor running processes for suspicious activity"""
        suspicious_processes = ['nc', 'netcat', 'ncat', 'socat', 'python -c', 'perl -e']
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['cmdline']:
                    cmdline = ' '.join(proc.info['cmdline'])
                    
                    for suspicious in suspicious_processes:
                        if suspicious in cmdline.lower():
                            self._log_security_event(
                                'suspicious_process',
                                f"Suspicious process: {cmdline}",
                                'system'
                            )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    def _log_security_event(self, event_type, details, source):
        """Log security events"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO security_events (timestamp, event_type, details, source)
                VALUES (?, ?, ?, ?)
            ''', (datetime.now(), event_type, details, source))
            
            conn.commit()
            conn.close()
            
            logger.warning(f"Security event: {event_type} - {details}")
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")

class CyberRangeMonitor:
    """Main monitoring system coordinator"""
    
    def __init__(self, db_path='monitoring.db'):
        self.db_path = db_path
        self.network_monitor = NetworkMonitor(db_path)
        self.system_monitor = SystemMonitor(db_path)
        self.file_observer = Observer()
        self.setup_database()
    
    def setup_database(self):
        """Initialize monitoring database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Security events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    event_type TEXT,
                    details TEXT,
                    source TEXT,
                    severity TEXT DEFAULT 'medium'
                )
            ''')
            
            # Network statistics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    bytes_sent INTEGER,
                    bytes_recv INTEGER,
                    packets_sent INTEGER,
                    packets_recv INTEGER
                )
            ''')
            
            # System statistics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    cpu_percent REAL,
                    memory_percent REAL,
                    memory_used INTEGER,
                    memory_total INTEGER,
                    disk_percent REAL,
                    disk_used INTEGER,
                    disk_total INTEGER
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Monitoring database initialized")
        except Exception as e:
            logger.error(f"Failed to setup database: {e}")
    
    def start_monitoring(self):
        """Start all monitoring components"""
        try:
            # Start network monitoring
            self.network_monitor.start_monitoring()
            
            # Start system monitoring
            self.system_monitor.start_monitoring()
            
            # Start file system monitoring
            event_handler = SecurityEventHandler(self.db_path)
            self.file_observer.schedule(event_handler, '/tmp', recursive=True)
            self.file_observer.schedule(event_handler, '/var/log', recursive=True)
            self.file_observer.start()
            
            logger.info("Cyber Range monitoring system started")
            
            # Keep the main thread alive
            try:
                while True:
                    time.sleep(60)
                    self._generate_alerts()
            except KeyboardInterrupt:
                self.stop_monitoring()
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
    
    def stop_monitoring(self):
        """Stop all monitoring components"""
        self.network_monitor.stop_monitoring()
        self.system_monitor.stop_monitoring()
        self.file_observer.stop()
        self.file_observer.join()
        logger.info("Cyber Range monitoring system stopped")
    
    def _generate_alerts(self):
        """Generate alerts based on monitoring data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check for recent security events
            cursor.execute('''
                SELECT COUNT(*) FROM security_events 
                WHERE timestamp > datetime('now', '-5 minutes')
            ''')
            
            recent_events = cursor.fetchone()[0]
            if recent_events > 10:
                logger.warning(f"High security activity detected: {recent_events} events in last 5 minutes")
            
            conn.close()
        except Exception as e:
            logger.error(f"Failed to generate alerts: {e}")
    
    def get_dashboard_data(self):
        """Get monitoring data for dashboard"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get recent security events
            cursor.execute('''
                SELECT event_type, COUNT(*) as count 
                FROM security_events 
                WHERE timestamp > datetime('now', '-1 hour')
                GROUP BY event_type
            ''')
            security_events = cursor.fetchall()
            
            # Get latest system stats
            cursor.execute('''
                SELECT cpu_percent, memory_percent, disk_percent 
                FROM system_stats 
                ORDER BY timestamp DESC LIMIT 1
            ''')
            system_stats = cursor.fetchone()
            
            conn.close()
            
            return {
                'security_events': security_events,
                'system_stats': system_stats
            }
        except Exception as e:
            logger.error(f"Failed to get dashboard data: {e}")
            return None

if __name__ == '__main__':
    monitor = CyberRangeMonitor()
    monitor.start_monitoring()
