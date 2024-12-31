import os
import time
import hashlib
import psutil
import logging
from logging.handlers import TimedRotatingFileHandler
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import socket
from datetime import datetime

class ComprehensiveFileChangeMonitor:
    def __init__(self, log_directory='/var/log/file_monitor', monitoring_interval=60):
        self.log_directory = log_directory
        self.monitoring_interval = monitoring_interval
        self.suspicious_threshold = 5  # Number of changes in timeframe to trigger suspicion
        self.file_change_count = {}
        
        #make logging folder
        os.makedirs(log_directory, exist_ok=True)
        
        # Configure rotating log handler
        self.log_handler = TimedRotatingFileHandler(
            os.path.join(log_directory, 'file_changes.log'), 
            when='M', 
            interval=1, 
            backupCount=10
        )

        #------------------- 
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        self.log_handler.setFormatter(formatter)
        self.logger = logging.getLogger('FileChangeLogger')
        self.logger.addHandler(self.log_handler)
        self.logger.setLevel(logging.INFO)
        
        # Suspicious file log
        self.suspicious_log = logging.getLogger('suspicious_files')
        suspicious_handler = TimedRotatingFileHandler(
            os.path.join(log_directory, 'sus_changes.log'),
            when='M',
            interval=1,
            backupCount=10
        )
        suspicious_handler.setFormatter(formatter)
        self.suspicious_log.addHandler(suspicious_handler)
        self.suspicious_log.setLevel(logging.WARNING)

    def get_file_metadata(self, filepath):
        """Capture comprehensive file metadata."""
        try:
            stat = os.stat(filepath)
            return {
                'size': stat.st_size,
                'modified_time': datetime.fromtimestamp(stat.st_mtime),
                'created_time': datetime.fromtimestamp(stat.st_ctime),
                'hash': self._calculate_file_hash(filepath)
            }
        except Exception as e:
            return {'error': str(e)}

    def _calculate_file_hash(self, filepath, hash_algorithm='sha256', chunk_size=8192):
        """Calculate file hash for integrity checking."""
        try:
            hasher = hashlib.new(hash_algorithm)
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(chunk_size), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None

    def log_file_change(self, event_type, filepath):
        """Log file changes with comprehensive details."""
        metadata = self.get_file_metadata(filepath)
        
        # Track file change frequency
        self.file_change_count[filepath] = self.file_change_count.get(filepath, 0) + 1
        
        # Log change
        log_entry = (f"Event: {event_type}, "
                     f"File: {filepath}, "
                     f"Metadata: {metadata}")
        self.logger.info(log_entry)
        
        # Check for suspicious activity
        if (self.file_change_count[filepath] +1)%(self.suspicious_threshold+1) >= self.suspicious_threshold:
            self.log_suspicious_file(filepath, event_type, metadata)

    def log_suspicious_file(self, filepath, event_type, metadata):
        """Handle and log suspicious file activity."""
        suspicious_entry = (f"SUSPICIOUS ACTIVITY DETECTED\n"
                            f"File: {filepath}\n"
                            f"Event: {event_type}\n"
                            f"Metadata: {metadata}\n"
                            f"Hostname: {socket.gethostname()}")
        self.suspicious_log.warning(suspicious_entry)

class FileWatcher(FileSystemEventHandler):
    def __init__(self, monitor):
        self.monitor = monitor
        self.log_directory = os.path.realpath(self.monitor.log_directory)

    def should_exclude(self, path):
        """Exclude events from the logging directory."""
        # Resolve absolute paths to avoid mismatches
        absolute_path = os.path.realpath(path)
        return absolute_path.startswith(self.log_directory)

    def on_created(self, event):
        if not event.is_directory and not self.should_exclude(event.src_path):
            self.monitor.log_file_change("CREATED", event.src_path)

    def on_modified(self, event):
        if not event.is_directory and not self.should_exclude(event.src_path):
            self.monitor.log_file_change("MODIFIED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory and not self.should_exclude(event.src_path):
            self.monitor.log_file_change("DELETED", event.src_path)

    def on_moved(self, event):
        if not event.is_directory and not self.should_exclude(event.dest_path):
            self.monitor.log_file_change("RENAMED", event.dest_path)

def monitor_root_filesystem():
    """
    Monitor entire root filesystem
    """
    monitor = ComprehensiveFileChangeMonitor()
    event_handler = FileWatcher(monitor)
    observer = Observer()
    
    #root directory and all subdirectories => recursively backtrack
    observer.schedule(event_handler, path='/', recursive=True,)
    
    try:
        observer.start()
        print("File monitoring started. Press Ctrl+C to stop.")
        observer.join()
    except KeyboardInterrupt:
        observer.stop()
    finally:
        observer.join()

if __name__ == "__main__":
    monitor_root_filesystem()
