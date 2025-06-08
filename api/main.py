from http.server import BaseHTTPRequestHandler
import json
import time
import hashlib
import hmac
import base64
import os
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import urllib.parse as urlparse
import struct
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class AdvancedPacketAnalyzer:
    """Enhanced packet capture detection with ML-like behavior analysis"""
    
    def __init__(self):
        self.threat_signatures = {
            'automated_tools': {
                'user_agents': [
                    'wget', 'curl', 'python-requests', 'python-urllib',
                    'java/', 'apache-httpclient', 'okhttp', 'nodejs',
                    'bot', 'crawler', 'spider', 'scraper', 'downloader',
                    'automation', 'selenium', 'phantom', 'headless'
                ],
                'header_patterns': [
                    'missing_accept_language',
                    'missing_accept_encoding', 
                    'unusual_accept_header',
                    'no_cache_control'
                ]
            },
            'network_anomalies': {
                'request_timing': {
                    'too_fast': 0.1,  # < 100ms between requests
                    'too_regular': 0.05,  # variance < 50ms (bot-like)
                    'burst_pattern': {'requests': 10, 'window': 5}  # 10 req in 5 sec
                },
                'bandwidth_patterns': {
                    'suspicious_download_speed': 100 * 1024 * 1024,  # 100MB/s
                    'unusual_packet_sizes': {'min': 32, 'max': 2048}
                }
            },
            'behavioral_analysis': {
                'session_anomalies': {
                    'no_mouse_movement': True,
                    'no_keyboard_events': True,
                    'perfect_streaming': True,  # No buffering/pauses
                    'multiple_concurrent': 5
                }
            }
        }
        
        # Store global statistics across all clients
        self.global_stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'threat_patterns': {},
            'client_reputation': {}
        }
    
    def analyze_deep_packet_inspection(self, headers: Dict, payload_info: Dict) -> Dict:
        """Deep packet analysis for advanced threat detection"""
        risk_factors = []
        risk_score = 0
        
        # User-Agent Analysis
        user_agent = headers.get('user-agent', '').lower()
        for tool in self.threat_signatures['automated_tools']['user_agents']:
            if tool in user_agent:
                risk_score += 30
                risk_factors.append(f"Automated tool detected: {tool}")
        
        # Header Fingerprinting
        header_anomalies = self._analyze_header_fingerprint(headers)
        risk_score += header_anomalies['score']
        risk_factors.extend(header_anomalies['factors'])
        
        # Request Pattern Analysis
        pattern_analysis = self._analyze_request_patterns(headers, payload_info)
        risk_score += pattern_analysis['score']
        risk_factors.extend(pattern_analysis['factors'])
        
        # TLS/SSL Fingerprinting (simulated)
        tls_analysis = self._analyze_tls_fingerprint(headers)
        risk_score += tls_analysis['score']
        risk_factors.extend(tls_analysis['factors'])
        
        return {
            'risk_score': min(risk_score, 100),
            'risk_factors': risk_factors,
            'threat_level': self._calculate_threat_level(risk_score),
            'recommended_action': self._get_recommended_action(risk_score)
        }
    
    def _analyze_header_fingerprint(self, headers: Dict) -> Dict:
        """Analyze HTTP header fingerprint for automation detection"""
        score = 0
        factors = []
        
        # Check for missing common browser headers
        browser_headers = [
            'accept-language', 'accept-encoding', 'cache-control',
            'upgrade-insecure-requests', 'sec-fetch-site', 'sec-fetch-mode'
        ]
        
        missing_count = sum(1 for h in browser_headers if h not in headers)
        if missing_count > 3:
            score += 25
            factors.append(f"Missing {missing_count} common browser headers")
        
        # Check header order (browsers have consistent order)
        header_order_score = self._check_header_order_anomaly(list(headers.keys()))
        score += header_order_score
        if header_order_score > 0:
            factors.append("Unusual header order detected")
        
        # Check for automation-specific headers
        automation_headers = ['x-requested-with', 'x-automation', 'selenium-']
        for auto_header in automation_headers:
            if any(auto_header in h.lower() for h in headers.keys()):
                score += 40
                factors.append(f"Automation header detected: {auto_header}")
        
        return {'score': score, 'factors': factors}
    
    def _check_header_order_anomaly(self, header_list: List[str]) -> int:
        """Check if header order matches typical browser patterns"""
        # Browsers typically send headers in a specific order
        typical_order = [
            'host', 'connection', 'cache-control', 'user-agent',
            'accept', 'accept-encoding', 'accept-language'
        ]
        
        score = 0
        order_violations = 0
        
        for i, expected in enumerate(typical_order[:len(header_list)]):
            if i < len(header_list):
                actual = header_list[i].lower()
                if expected not in actual:
                    order_violations += 1
        
        if order_violations > 3:
            score = 15
        
        return score
    
    def _analyze_request_patterns(self, headers: Dict, payload_info: Dict) -> Dict:
        """Analyze request patterns for bot behavior"""
        score = 0
        factors = []
        
        # Check for scripted behavior indicators
        content_length = payload_info.get('content_length', 0)
        
        # Very large payloads might indicate bulk operations
        if content_length > 10 * 1024 * 1024:  # 10MB
            score += 20
            factors.append(f"Large payload detected: {content_length} bytes")
        
        # Check Accept header for automation
        accept_header = headers.get('accept', '')
        if accept_header == '*/*' or not accept_header:
            score += 15
            factors.append("Generic or missing Accept header")
        
        # Check for missing Referer (legitimate requests usually have one)
        if 'referer' not in headers and 'origin' not in headers:
            score += 10
            factors.append("Missing Referer and Origin headers")
        
        return {'score': score, 'factors': factors}
    
    def _analyze_tls_fingerprint(self, headers: Dict) -> Dict:
        """Analyze TLS/SSL characteristics (simulated)"""
        score = 0
        factors = []
        
        # Check for forwarded headers that might indicate proxy usage
        proxy_headers = ['x-forwarded-for', 'x-real-ip', 'cf-connecting-ip']
        proxy_count = sum(1 for h in proxy_headers if h in headers)
        
        if proxy_count > 1:
            score += 20
            factors.append("Multiple proxy headers detected")
        
        # Check for VPN/Proxy indicators
        forwarded_for = headers.get('x-forwarded-for', '')
        if ',' in forwarded_for:  # Multiple IPs indicate proxy chain
            score += 15
            factors.append("Proxy chain detected in X-Forwarded-For")
        
        return {'score': score, 'factors': factors}
    
    def _calculate_threat_level(self, risk_score: int) -> str:
        """Calculate threat level based on risk score"""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        elif risk_score >= 20:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _get_recommended_action(self, risk_score: int) -> str:
        """Get recommended action based on risk score"""
        if risk_score >= 80:
            return "BLOCK_IMMEDIATELY"
        elif risk_score >= 60:
            return "REQUIRE_CAPTCHA"
        elif risk_score >= 40:
            return "RATE_LIMIT"
        elif risk_score >= 20:
            return "MONITOR_CLOSELY"
        else:
            return "ALLOW"

class MediaProtectionAPI:
    """Enhanced API with advanced security features"""
    
    def __init__(self):
        self.packet_analyzer = AdvancedPacketAnalyzer()
        self.client_sessions = {}
        self.rate_limits = {}
        self.blocked_ips = set()
        self.webhook_queue = []
        
        # Pricing tiers for different clients
        self.pricing_tiers = {
            'basic': {'requests_per_hour': 1000, 'features': ['encryption', 'basic_detection']},
            'premium': {'requests_per_hour': 10000, 'features': ['encryption', 'advanced_detection', 'webhooks']},
            'enterprise': {'requests_per_hour': 100000, 'features': ['encryption', 'advanced_detection', 'webhooks', 'custom_rules']}
        }
    
    def check_rate_limit(self, client_id: str, tier: str = 'basic') -> Dict:
        """Check if client has exceeded rate limits"""
        current_time = time.time()
        hour_window = current_time - 3600  # 1 hour ago
        
        if client_id not in self.rate_limits:
            self.rate_limits[client_id] = []
        
        # Clean old requests
        self.rate_limits[client_id] = [
            req_time for req_time in self.rate_limits[client_id] 
            if req_time > hour_window
        ]
        
        # Check limit
        limit = self.pricing_tiers[tier]['requests_per_hour']
        current_count = len(self.rate_limits[client_id])
        
        if current_count >= limit:
            return {
                'allowed': False,
                'limit': limit,
                'current': current_count,
                'reset_time': hour_window + 3600
            }
        
        # Add current request
        self.rate_limits[client_id].append(current_time)
        
        return {
            'allowed': True,
            'limit': limit,
            'current': current_count + 1,
            'remaining': limit - current_count - 1
        }
    
    def generate_session_token(self, client_id: str, content_hash: str) -> str:
        """Generate secure session token"""
        timestamp = str(int(time.time()))
        session_data = f"{client_id}:{content_hash}:{timestamp}"
        session_hash = hashlib.sha256(session_data.encode()).hexdigest()
        return f"{session_hash[:16]}-{timestamp}"
    
    def encrypt_media_advanced(self, media_data: bytes, client_id: str, 
                             security_level: str = 'standard') -> Dict:
        """Advanced media encryption with multiple security levels"""
        try:
            # Generate layered encryption based on security level
            base_key = self._generate_encryption_key(f"{client_id}_base")
            
            if security_level == 'high':
                # Triple encryption for high security
                session_key = self._generate_encryption_key(f"{client_id}_{time.time()}")
                content_key = self._generate_encryption_key(f"{hashlib.md5(media_data).hexdigest()}")
                
                # Layer 1: Content-based encryption
                fernet1 = Fernet(content_key)
                encrypted_layer1 = fernet1.encrypt(media_data)
                
                # Layer 2: Session-based encryption
                fernet2 = Fernet(session_key)
                encrypted_layer2 = fernet2.encrypt(encrypted_layer1)
                
                # Layer 3: Client-based encryption
                fernet3 = Fernet(base_key)
                final_encrypted = fernet3.encrypt(encrypted_layer2)
                
                encryption_layers = [content_key, session_key, base_key]
            else:
                # Standard single-layer encryption
                fernet = Fernet(base_key)
                final_encrypted = fernet.encrypt(media_data)
                encryption_layers = [base_key]
            
            # Generate advanced protection metadata
            content_hash = hashlib.sha256(media_data).hexdigest()
            session_token = self.generate_session_token(client_id, content_hash)
            
            protection_metadata = {
                'client_id': client_id,
                'session_token': session_token,
                'security_level': security_level,
                'encryption_layers': len(encryption_layers),
                'original_size': len(media_data),
                'checksum': content_hash,
                'encryption_timestamp': time.time(),
                'expected_metrics': {
                    'max_bandwidth': 100 * 1024 * 1024,
                    'min_bandwidth': 512 * 1024,
                    'max_concurrent_streams': 3,
                    'session_timeout': 3600,  # 1 hour
                    'max_pause_duration': 300  # 5 minutes
                },
                'security_flags': {
                    'require_continuous_validation': security_level == 'high',
                    'allow_seek': security_level != 'high',
                    'allow_download': False,
                    'watermark_required': security_level == 'high'
                }
            }
            
            # Package encrypted content
            metadata_json = json.dumps(protection_metadata).encode()
            metadata_size = struct.pack('I', len(metadata_json))
            
            protected_package = metadata_size + metadata_json + final_encrypted
            
            return {
                'status': 'success',
                'session_token': session_token,
                'protected_content': base64.b64encode(protected_package).decode(),
                'security_level': security_level,
                'original_size': len(media_data),
                'protected_size': len(protected_package),
                'expires_at': time.time() + 3600
            }
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def _generate_encryption_key(self, seed: str) -> bytes:
        """Generate encryption key from seed"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'media_protection_2024',
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(seed.encode()))
        return key
    
    async def queue_webhook(self, webhook_url: str, data: Dict, secret: str = None):
        """Queue webhook for asynchronous delivery"""
        webhook_payload = {
            'url': webhook_url,
            'data': data,
            'secret': secret,
            'timestamp': time.time(),
            'attempts': 0,
            'max_attempts': 3
        }
        self.webhook_queue.append(webhook_payload)
    
    def validate_and_decrypt_advanced(self, protected_content: str, client_id: str,
                                    request_headers: Dict, client_ip: str,
                                    real_time_metrics: Dict = None) -> Dict:
        """Advanced validation with real-time packet analysis"""
        try:
            # Check if IP is blocked
            if client_ip in self.blocked_ips:
                return {
                    'status': 'blocked',
                    'reason': 'IP address blocked due to previous violations',
                    'block_expires': 'permanent' 
                }
            
            # Decode protected content
            content_bytes = base64.b64decode(protected_content)
            metadata_size = struct.unpack('I', content_bytes[:4])[0]
            metadata_json = content_bytes[4:4+metadata_size]
            encrypted_data = content_bytes[4+metadata_size:]
            
            protection_metadata = json.loads(metadata_json.decode())
            
            # Validate client and session
            if protection_metadata['client_id'] != client_id:
                return {'status': 'error', 'message': 'Client ID mismatch'}
            
            # Check session expiry
            if time.time() - protection_metadata['encryption_timestamp'] > 3600:
                return {'status': 'expired', 'message': 'Session expired'}
            
            # Advanced Packet Analysis
            payload_info = {
                'content_length': len(protected_content),
                'encryption_layers': protection_metadata['encryption_layers'],
                'security_level': protection_metadata['security_level']
            }
            
            packet_analysis = self.packet_analyzer.analyze_deep_packet_inspection(
                request_headers, payload_info
            )
            
            # Update client session history
            if client_id not in self.client_sessions:
                self.client_sessions[client_id] = {
                    'requests': [],
                    'total_risk_score': 0,
                    'violation_count': 0,
                    'last_access': time.time()
                }
            
            current_request = {
                'timestamp': time.time(),
                'ip': client_ip,
                'risk_score': packet_analysis['risk_score'],
                'threat_level': packet_analysis['threat_level'],
                'session_token': protection_metadata['session_token']
            }
            
            self.client_sessions[client_id]['requests'].append(current_request)
            self.client_sessions[client_id]['requests'] = self.client_sessions[client_id]['requests'][-100:]
            
            # Calculate cumulative risk
            recent_requests = self.client_sessions[client_id]['requests'][-10:]
            avg_risk_score = sum(req['risk_score'] for req in recent_requests) / len(recent_requests)
            
            # Decision matrix
            final_risk_score = (packet_analysis['risk_score'] + avg_risk_score) / 2
            
            validation_result = {
                'session_token': protection_metadata['session_token'],
                'risk_score': final_risk_score,
                'threat_level': packet_analysis['threat_level'],
                'packet_analysis': packet_analysis,
                'client_ip': client_ip,
                'timestamp': datetime.now().isoformat(),
                'recommended_action': packet_analysis['recommended_action']
            }
            
            # Apply security decision
            if packet_analysis['recommended_action'] == 'BLOCK_IMMEDIATELY':
                self.blocked_ips.add(client_ip)
                self.client_sessions[client_id]['violation_count'] += 1
                
                return {
                    'status': 'blocked',
                    'reason': 'Critical threat detected',
                    'validation_result': validation_result
                }
            
            elif packet_analysis['recommended_action'] in ['REQUIRE_CAPTCHA', 'RATE_LIMIT']:
                return {
                    'status': 'challenge_required',
                    'challenge_type': 'captcha' if 'CAPTCHA' in packet_analysis['recommended_action'] else 'rate_limit',
                    'validation_result': validation_result
                }
            
            elif final_risk_score < 50:  # Allow access
                # Decrypt content based on security level
                try:
                    if protection_metadata['security_level'] == 'high':
                        # Triple decryption for high security
                        base_key = self._generate_encryption_key(f"{client_id}_base")
                        fernet3 = Fernet(base_key)
                        decrypted_layer3 = fernet3.decrypt(encrypted_data)
                        
                        # This would require storing session and content keys securely
                        # For demo purposes, we'll simulate successful decryption
                        decrypted_content = b"[HIGH_SECURITY_CONTENT_DECRYPTED]"
                    else:
                        base_key = self._generate_encryption_key(f"{client_id}_base")
                        fernet = Fernet(base_key)
                        decrypted_content = fernet.decrypt(encrypted_data)
                    
                    return {
                        'status': 'approved',
                        'quality': 'original',
                        'content_size': len(decrypted_content),
                        'validation_result': validation_result,
                        'decrypted_content': base64.b64encode(decrypted_content).decode(),
                        'streaming_token': self.generate_session_token(client_id, "streaming")
                    }
                    
                except Exception as decrypt_error:
                    return {
                        'status': 'error',
                        'message': f'Decryption failed: {str(decrypt_error)}',
                        'validation_result': validation_result
                    }
            
            else:
                return {
                    'status': 'suspicious',
                    'quality': 'degraded',
                    'reason': 'Moderate risk detected - providing degraded quality',
                    'validation_result': validation_result
                }
                
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

class Handler(BaseHTTPRequestHandler):
    """Main Vercel handler with comprehensive API endpoints"""
    
    def __init__(self, *args, **kwargs):
        self.api = MediaProtectionAPI()
        super().__init__(*args, **kwargs)
    
    def _set_headers(self, status_code=200):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key, X-Client-Tier')
        self.send_header('X-API-Version', '2.0')
        self.send_header('X-Rate-Limit-Window', '3600')
        self.end_headers()
    
    def _authenticate_client(self, headers: Dict) -> tuple:
        """Authenticate client and return client_id and tier"""
        api_key = headers.get('x-api-key')
        if not api_key:
            return None, None
        
        try:
            decoded = base64.b64decode(api_key).decode()
            client_id, timestamp = decoded.split(':')
            
            # Get client tier from header or default to basic
            tier = headers.get('x-client-tier', 'basic')
            if tier not in self.api.pricing_tiers:
                tier = 'basic'
            
            return client_id, tier
        except:
            return None, None
    
    def do_OPTIONS(self):
        self._set_headers()
    
    def do_GET(self):
        """Handle GET requests - Status, analytics, health checks"""
        parsed_path = urlparse.urlparse(self.path)
        path = parsed_path.path
        
        if path == '/api/health':
            self._set_headers()
            response = {
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'service': 'Media Protection API v2.0',
                'uptime': time.time(),
                'endpoints': [
                    '/api/health', '/api/generate-key', '/api/encrypt',
                    '/api/validate', '/api/analytics', '/api/webhook-status'
                ]
            }
            self.wfile.write(json.dumps(response).encode())
        
        elif path == '/api/generate-key':
            query_params = urlparse.parse_qs(parsed_path.query)
            client_id = query_params.get('client_id', [None])[0]
            tier = query_params.get('tier', ['basic'])[0]
            
            if not client_id:
                self._set_headers(400)
                self.wfile.write(json.dumps({'error': 'client_id required'}).encode())
                return
            
            if tier not in self.api.pricing_tiers:
                tier = 'basic'
            
            api_key = base64.b64encode(f"{client_id}:{int(time.time())}".encode()).decode()
            
            self._set_headers()
            response = {
                'client_id': client_id,
                'api_key': api_key,
                'tier': tier,
                'features': self.api.pricing_tiers[tier]['features'],
                'rate_limit': self.api.pricing_tiers[tier]['requests_per_hour'],
                'generated_at': datetime.now().isoformat()
            }
            self.wfile.write(json.dumps(response).encode())
        
        elif path == '/api/analytics':
            headers = dict(self.headers)
            client_id, tier = self._authenticate_client(headers)
            
            if not client_id:
                self._set_headers(401)
                self.wfile.write(json.dumps({'error': 'Authentication required'}).encode())
                return
            
            client_data = self.api.client_sessions.get(client_id, {})
            
            analytics = {
                'client_id': client_id,
                'tier': tier,
                'total_requests': len(client_data.get('requests', [])),
                'avg_risk_score': sum(req.get('risk_score', 0) for req in client_data.get('requests', [])) / max(len(client_data.get('requests', [])), 1),
                'violation_count': client_data.get('violation_count', 0),
                'last_access': client_data.get('last_access'),
                'recent_activity': client_data.get('requests', [])[-10:],
                'timestamp': datetime.now().isoformat()
            }
            
            self._set_headers()
            self.wfile.write(json.dumps(analytics).encode())
        
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({'error': 'Endpoint not found'}).encode())
    
    def do_POST(self):
        """Handle POST requests - Main API functionality"""
        try:
            headers = dict(self.headers)
            client_id, tier = self._authenticate_client(headers)
            
            if not client_id:
                self._set_headers(401)
                self.wfile.write(json.dumps({'error': 'Valid API key required'}).encode())
                return
            
            # Rate limiting check
            rate_limit_result = self.api.check_rate_limit(client_id, tier)
            if not rate_limit_result['allowed']:
                self._set_headers(429)
                response = {
                    'error': 'Rate limit exceeded',
                    'limit': rate_limit_result['limit'],
                    'reset_time': rate_limit_result['reset_time']
                }
                self.wfile.write(json.dumps(response).encode())
                return
            
            # Get client IP
            client_ip = headers.get('x-forwarded-for', headers.get('x-real-ip', self.client_address[0]))
            
            # Read request body
            content_length = int(headers.get('content-length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                request_data = json.loads(post_data.decode())
            except json.JSONDecodeError:
                self._set_headers(400)
                self.wfile.write(json.dumps({'error': 'Invalid JSON payload'}).encode())
                return
            
            parsed_path = urlparse.urlparse(self.path)
            path = parsed_path.path
            
            if path == '/api/encrypt':
                media_data = base64.b64decode(request_data.get('media_data', ''))
                security_level = request_data.get('security_level', 'standard')
                
                if security_level == 'high' and 'advanced_detection' not in self.api.pricing_tiers[tier]['features']:
                    self._set_headers(403)
                    self.wfile.write(json.dumps({'error': 'High security requires premium tier'}).encode())
                    return
                
                result = self.api.encrypt_media_advanced(media_data, client_id, security_level)
                
                # Add rate limiting headers
                result['rate_limit'] = {
                    'remaining': rate_limit_result['remaining'],
                    'limit': rate_limit_result['limit']
                }
                
                self._set_headers()
                self.wfile.write(json.dumps(result).encode())
            
            elif path == '/api/validate':
                protected_content = request_data.get('protected_content', '')
                real_time_metrics = request_data.get('real_time_metrics', {})
                
                result = self.api.validate_and_decrypt_advanced(
                    protected_content, client_id, headers, client_ip, real_time_metrics
                )
                
                # Queue webhook if configured and client has webhook feature
                webhook_url = request_data.get('webhook_url')
                if webhook_url and 'webhooks' in self.api.pricing_tiers[tier]['features']:
                    webhook_data = {
                        'event': 'validation_completed',
                        'client_id': client_id,
                        'result': result['status'],
                        'risk_score': result.get('validation_result', {}).get('risk_score', 0),
                        'timestamp': datetime.now().isoformat(),
                        'client_ip': client_ip
                    }
                    
                    # In production, this would be handled by a queue system
                    # For demo, we'll just add to a list
                    self.api.webhook_queue.append({
                        'url': webhook_url,
                        'data': webhook_data,
                        'client_id': client_id
                    })
                
                self._set_headers()
                self.wfile.write(json.dumps(result).encode())
            
            elif path == '/api/webhook-status':
                # Get webhook delivery status
                client_webhooks = [w for w in self.api.webhook_queue if w.get('client_id') == client_id]
                
                webhook_status = {
                    'client_id': client_id,
                    'pending_webhooks': len(client_webhooks),
                    'recent_webhooks': client_webhooks[-10:],
                    'timestamp': datetime.now().isoformat()
                }
                
                self._set_headers()
                self.wfile.write(json.dumps(webhook_status).encode())
            
            else:
                self._set_headers(404)
                self.wfile.write(json.dumps({'error': 'Endpoint not found'}).encode())
        
        except Exception as e:
            self._set_headers(500)
            error_response = {
                'error': 'Internal server error',
                'message': str(e),
                'timestamp': datetime.now().isoformat()
            }
            self.wfile.write(json.dumps(error_response).encode())

# Vercel handler function
def handler(request, response):
    """Vercel serverless function entry point"""
    return Handler(request, response)

# For local testing
if __name__ == '__main__':
    from http.server import HTTPServer
    server = HTTPServer(('localhost', 8000), Handler)
    print("🚀 Media Protection API v2.0 running on http://localhost:8000")
    print("\n📋 Available Endpoints:")
    print("  GET  /api/health           - Service health check")
    print("  GET  /api/generate-key     - Generate API key")
    print("  GET  /api/analytics        - Client analytics")
    print("  POST /api/encrypt          - Encrypt media content")
    print("  POST /api/validate         - Validate and decrypt")
    print("  POST /api/webhook-status   - Webhook delivery status")
    print("\n💰 Pricing Tiers:")
    for tier, config in MediaProtectionAPI().pricing_tiers.items():
        print(f"  {tier.upper()}: {config['requests_per_hour']}/hour - {config['features']}")
    server.serve_forever()
