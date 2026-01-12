"""
Core port scanner engine with TCP/UDP scanning capabilities.
"""

import socket
import threading
import time
from datetime import datetime
from typing import List, Callable, Optional
from queue import Queue

from config import (
    DEFAULT_TIMEOUT, DEFAULT_MAX_THREADS, DEFAULT_RETRIES,
    PORT_STATE_OPEN, PORT_STATE_CLOSED, PORT_STATE_FILTERED,
    PORT_STATE_TIMEOUT, PORT_STATE_RESET
)
from models.scan_result import ScanResult
from utils.logger import scanner_logger


class PortScanner:
    """
    Multi-threaded port scanner with TCP and UDP support.
    """
    
    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        max_threads: int = DEFAULT_MAX_THREADS,
        retries: int = DEFAULT_RETRIES,
        progress_callback: Optional[Callable] = None
    ):
        """
        Initialize port scanner.
        
        Args:
            timeout: Connection timeout in seconds
            max_threads: Maximum concurrent threads
            retries: Number of retries per port
            progress_callback: Callback function for progress updates
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.retries = retries
        self.progress_callback = progress_callback
        self.stop_flag = threading.Event()
        self.pause_flag = threading.Event()
        self.results = []
        self.results_lock = threading.Lock()
        self.scanned_count = 0
        self.total_count = 0
    
    def scan(
        self,
        hosts: List[str],
        ports: List[int],
        protocol: str = "TCP"
    ) -> List[ScanResult]:
        """
        Perform port scan on targets.
        
        Args:
            hosts: List of target IP addresses
            ports: List of port numbers to scan
            protocol: TCP or UDP
            
        Returns:
            List of scan results
        """
        self.results = []
        self.scanned_count = 0
        self.stop_flag.clear()
        self.pause_flag.clear()
        
        # Calculate total scans
        self.total_count = len(hosts) * len(ports)
        
        scanner_logger.info(
            f"Starting scan: {len(hosts)} hosts, {len(ports)} ports, protocol: {protocol}"
        )
        
        # Create work queue
        work_queue = Queue()
        for host in hosts:
            for port in ports:
                work_queue.put((host, port))
        
        # Start worker threads
        threads = []
        for _ in range(min(self.max_threads, work_queue.qsize())):
            if protocol.upper() == "TCP":
                thread = threading.Thread(
                    target=self._tcp_worker,
                    args=(work_queue,)
                )
            else:
                thread = threading.Thread(
                    target=self._udp_worker,
                    args=(work_queue,)
                )
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        scanner_logger.info(f"Scan completed: {len(self.results)} results")
        return self.results
    
    def _tcp_worker(self, work_queue: Queue) -> None:
        """Worker thread for TCP scanning."""
        while not work_queue.empty() and not self.stop_flag.is_set():
            # Check for pause
            while self.pause_flag.is_set() and not self.stop_flag.is_set():
                time.sleep(0.1)
            
            if self.stop_flag.is_set():
                break
            
            try:
                host, port = work_queue.get_nowait()
            except:
                break
            
            result = self._tcp_connect_scan(host, port)
            
            with self.results_lock:
                self.results.append(result)
                self.scanned_count += 1
                
                # Progress callback
                if self.progress_callback:
                    progress = (self.scanned_count / self.total_count) * 100
                    self.progress_callback(progress, self.scanned_count, self.total_count)
            
            work_queue.task_done()
    
    def _udp_worker(self, work_queue: Queue) -> None:
        """Worker thread for UDP scanning."""
        while not work_queue.empty() and not self.stop_flag.is_set():
            # Check for pause
            while self.pause_flag.is_set() and not self.stop_flag.is_set():
                time.sleep(0.1)
            
            if self.stop_flag.is_set():
                break
            
            try:
                host, port = work_queue.get_nowait()
            except:
                break
            
            result = self._udp_probe_scan(host, port)
            
            with self.results_lock:
                self.results.append(result)
                self.scanned_count += 1
                
                if self.progress_callback:
                    progress = (self.scanned_count / self.total_count) * 100
                    self.progress_callback(progress, self.scanned_count, self.total_count)
            
            work_queue.task_done()
    
    def _tcp_connect_scan(self, host: str, port: int) -> ScanResult:
        """
        Perform TCP connect scan on a single port.
        
        Args:
            host: Target IP address
            port: Port number
            
        Returns:
            Scan result
        """
        start_time = time.time()
        state = PORT_STATE_CLOSED
        
        for attempt in range(self.retries + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                result = sock.connect_ex((host, port))
                
                if result == 0:
                    state = PORT_STATE_OPEN
                    sock.close()
                    break
                elif result == 111:  # Connection refused
                    state = PORT_STATE_CLOSED
                else:
                    state = PORT_STATE_FILTERED
                
                sock.close()
                
            except socket.timeout:
                state = PORT_STATE_TIMEOUT
            except (socket.error, OSError, ConnectionError) as e:
                if "reset" in str(e).lower():
                    state = PORT_STATE_RESET
                else:
                    state = PORT_STATE_FILTERED
            except Exception as e:
                scanner_logger.error(f"Unexpected error scanning {host}:{port} - {type(e).__name__}: {e}")
                state = PORT_STATE_FILTERED
        
        response_time = time.time() - start_time
        
        return ScanResult(
            host=host,
            port=port,
            state=state,
            protocol="TCP",
            response_time=response_time,
            timestamp=datetime.now()
        )
    
    def _udp_probe_scan(self, host: str, port: int) -> ScanResult:
        """
        Perform UDP probe scan on a single port.
        
        Args:
            host: Target IP address
            port: Port number
            
        Returns:
            Scan result
        """
        start_time = time.time()
        state = PORT_STATE_FILTERED  # UDP default is filtered/open
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send empty datagram
            sock.sendto(b'', (host, port))
            
            try:
                # Try to receive response
                data, addr = sock.recvfrom(1024)
                state = PORT_STATE_OPEN  # Got response
            except socket.timeout:
                state = PORT_STATE_FILTERED  # No response (open or filtered)
            
            sock.close()
            
        except socket.error as e:
            # ICMP port unreachable = closed
            if "icmp" in str(e).lower() or "unreachable" in str(e).lower():
                state = PORT_STATE_CLOSED
            else:
                state = PORT_STATE_FILTERED
        except Exception as e:
            scanner_logger.error(f"Error UDP scanning {host}:{port} - {e}")
            state = PORT_STATE_FILTERED
        
        response_time = time.time() - start_time
        
        return ScanResult(
            host=host,
            port=port,
            state=state,
            protocol="UDP",
            response_time=response_time,
            timestamp=datetime.now()
        )
    
    def stop(self) -> None:
        """Stop the scan."""
        scanner_logger.info("Stopping scan...")
        self.stop_flag.set()
    
    def pause(self) -> None:
        """Pause the scan."""
        scanner_logger.info("Pausing scan...")
        self.pause_flag.set()
    
    def resume(self) -> None:
        """Resume the scan."""
        scanner_logger.info("Resuming scan...")
        self.pause_flag.clear()
    
    def is_running(self) -> bool:
        """Check if scan is running."""
        return not self.stop_flag.is_set()
    
    def is_paused(self) -> bool:
        """Check if scan is paused."""
        return self.pause_flag.is_set()
