"""
Vercel-deployable Media Protection API
Multi-tenant streaming platform security service
"""

import json
import time
import hashlib
import hmac
import base64
import os
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import asyncio
import aiohttp
import struct
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Vercel serverless function handler
from http.server import BaseHTTPRequestHandler
import urllib.parse as urlparse

class PacketCaptureDetector:
    """Advanced packet capture and anomaly detection"""
    
    def __init__(self):
        self.suspicious_patterns = {
            'rapid_requests': {'threshold': 10, 'window': 60},  # 10 requests in 60 seconds
            'large_bandwidth': {'threshold': 100 * 1024 * 1024},  # 100MB/min
            'unusual_user_agents': [
                'wget', 'curl', 'python-requests', 'bot', 'crawler',
                'spider', 'scraper', 'downloader', 'automation'
            ],
            'packet_size_anomaly': {'min': 64, 'max': 1500},  # Normal ethernet MTU
            'connection_patterns': {
                'max_concurrent': 5,
                'min_interval': 1.0  # seconds between requests
            }
        }
        
    def analyze_request_headers(self, headers: Dict[str, str]) -> Dict[str, any]:
        """Analyze HTTP headers for suspicious patterns"""
        risk_score = 0
        alerts = []
        
        user_agent = headers.get('user-agent', '').lower()
        for suspicious_ua in self.suspicious_patterns['unusual_user_agents']:
            if suspicious_ua in user_agent:
                risk_score += 25
                alerts.append(f"Suspicious User-Agent detected: {suspicious_ua}")
        
        # Check for missing common headers
        expected_headers = ['accept', 'accept-language', 'accept-encoding']
        missing_headers = [h for h in expected_headers if h not in headers]
        if len(missing_headers) > 1:
            risk_score += 15
            alerts.append(f"Missing common headers: {missing_headers}")
        
        # Check for automation indicators
        if 'x-requested-with' not in headers and 'referer' not in headers:
            risk_score += 10
            alerts.append("Direct API access without browser context")
        
        return {
            'risk_score': min(risk_score, 100),
            'alerts': alerts,
            'classification': 'high' if risk_score > 50 else 'medium' if risk_score > 25 else 'low'
        }
    
    def detect_timing_attacks(self, request_history: List[Dict]) -> Dict[str, any]:
        """Detect timing-based attacks and patterns"""
        if len(request_history) < 2:
            return {'risk_score': 0, 'alerts': []}
        
        # Calculate request intervals
        intervals = []
        for i in range(1, len(request_history)):
            interval = request_history[i]['timestamp'] - request_history[i-1]['timestamp']
            intervals.append(interval)
        
        avg_interval = sum(intervals) / len(intervals)
        risk_score = 0
        alerts = []
        
        # Too rapid requests
        if avg_interval < self.suspicious_patterns['connection_patterns']['min_interval']:
            risk_score += 30
            alerts.append(f"Rapid fire requests detected: {avg_interval:.2f}s average interval")
        
        # Too regular intervals (bot-like behavior)
        if len(set([round(i, 1) for i in intervals])) == 1 and len(intervals) > 5:
            risk_score += 40
            alerts.append("Highly regular request pattern detected (bot-like)")
        
        return {
            'risk_score': min(risk_score, 100),
            'alerts': alerts,
            'avg_interval': avg_interval
        }

class MediaProtectionAPI:
    """Main API class for media protection service"""
    
    def __init__(self):
        self.packet_detector = PacketCaptureDetector()
        self.client_sessions = {}  # Store client session data
        self.rate_limits = {}  # Rate limiting data
        
    def generate_api_key(self, client_id: str) -> str:
        """Generate API key for client"""
        timestamp = str(int(time.time()))
        data = f"{client_id}:{timestamp}"
        return base64.b64encode(data.encode()).decode()
    
    def validate_api_key(self, api_key: str) -> Optional[str]:
        """Validate API key and return client_id"""
        try:
            decoded = base64.b64decode(api_key).decode()
            client_id, timestamp = decoded.split(':')
            # Add expiration logic if needed
            return client_id
        except:
            return None
    
    def generate_encryption_key(self, password: str, salt: bytes = None) -> bytes:
        """Generate encryption key"""
        if salt is None:
            salt = b'streaming_protection_2024'
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    async def send_webhook(self, webhook_url: str, data: Dict, secret: str = None):
        """Send webhook notification"""
        payload = json.dumps(data)
        headers = {'Content-Type': 'application/json'}
        
        if secret:
            signature = hmac.new(
                secret.encode(),
                payload.encode(),
                hashlib.sha256
            ).hexdigest()
            headers['X-Signature-SHA256'] = f"sha256={signature}"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, data=payload, headers=headers, timeout=10) as response:
                    return response.status == 200
        except:
            return False
    
    def encrypt_media(self, media_data: bytes, client_id: str, metadata: Dict = None) -> Dict:
        """Encrypt media with protection metadata"""
        try:
            # Generate client-specific key
            encryption_key = self.generate_encryption_key(f"{client_id}_media_key")
            fernet = Fernet(encryption_key)
            
            # Calculate protection metrics
            original_size = len(media_data)
            checksum = hashlib.sha256(media_data).hexdigest()
            
            protection_metadata = {
                'client_id': client_id,
                'original_size': original_size,
                'checksum': checksum,
                'encryption_timestamp': time.time(),
                'session_id': str(uuid.uuid4()),
                'expected_metrics': {
                    'max_bandwidth': 50 * 1024 * 1024,  # 50MB/s
                    'min_bandwidth': 1024 * 1024,  # 1MB/s
                    'max_concurrent_streams': 3
                },
                'custom_metadata': metadata or {}
            }
            
            # Encrypt data
            encrypted_data = fernet.encrypt(media_data)
            
            # Create protected package
            metadata_json = json.dumps(protection_metadata).encode()
            metadata_size = struct.pack('I', len(metadata_json))
            
            protected_content = metadata_size + metadata_json + encrypted_data
            
            return {
                'status': 'success',
                'session_id': protection_metadata['session_id'],
                'protected_content': base64.b64encode(protected_content).decode(),
                'original_size': original_size,
                'protected_size': len(protected_content)
            }
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def validate_and_decrypt(self, protected_content: str, client_id: str, 
                           request_headers: Dict, client_ip: str) -> Dict:
        """Validate protection requirements and decrypt if passed"""
        try:
            # Decode protected content
            content_bytes = base64.b64decode(protected_content)
            
            # Extract metadata
            metadata_size = struct.unpack('I', content_bytes[:4])[0]
            metadata_json = content_bytes[4:4+metadata_size]
            encrypted_data = content_bytes[4+metadata_size:]
            
            protection_metadata = json.loads(metadata_json.decode())
            
            # Validate client
            if protection_metadata['client_id'] != client_id:
                return {'status': 'error', 'message': 'Client ID mismatch'}
            
            # Security Analysis
            header_analysis = self.packet_detector.analyze_request_headers(request_headers)
            
            # Get request history for this client
            if client_id not in self.client_sessions:
                self.client_sessions[client_id] = []
            
            # Add current request to history
            current_request = {
                'timestamp': time.time(),
                'ip': client_ip,
                'headers': request_headers,
                'session_id': protection_metadata['session_id']
            }
            self.client_sessions[client_id].append(current_request)
            
            # Keep only last 50 requests
            self.client_sessions[client_id] = self.client_sessions[client_id][-50:]
            
            timing_analysis = self.packet_detector.detect_timing_attacks(
                self.client_sessions[client_id]
            )
            
            # Calculate overall risk score
            total_risk_score = (header_analysis['risk_score'] + timing_analysis['risk_score']) / 2
            
            # Decision logic
            validation_result = {
                'session_id': protection_metadata['session_id'],
                'risk_score': total_risk_score,
                'header_analysis': header_analysis,
                'timing_analysis': timing_analysis,
                'client_ip': client_ip,
                'timestamp': datetime.now().isoformat()
            }
            
            # Decrypt if validation passed
            if total_risk_score < 60:  # Threshold for allowing access
                encryption_key = self.generate_encryption_key(f"{client_id}_media_key")
                fernet = Fernet(encryption_key)
                decrypted_data = fernet.decrypt(encrypted_data)
                
                # Verify integrity
                actual_checksum = hashlib.sha256(decrypted_data).hexdigest()
                if actual_checksum != protection_metadata['checksum']:
                    return {
                        'status': 'error',
                        'message': 'Content integrity check failed',
                        'validation_result': validation_result
                    }
                
                return {
                    'status': 'approved',
                    'quality': 'original',
                    'content_size': len(decrypted_data),
                    'validation_result': validation_result,
                    'decrypted_content': base64.b64encode(decrypted_data).decode()
                }
            else:
                return {
                    'status': 'blocked',
                    'quality': 'denied',
                    'reason': 'High risk score detected',
                    'validation_result': validation_result
                }
                
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

# Vercel Handler Class
class handler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.api = MediaProtectionAPI()
        super().__init__(*args, **kwargs)
    
    def _set_headers(self, status_code=200):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key')
        self.end_headers()
    
    def do_OPTIONS(self):
        self._set_headers()
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse.urlparse(self.path)
        path = parsed_path.path
        
        if path == '/health':
            self._set_headers()
            response = {
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'service': 'Media Protection API'
            }
            self.wfile.write(json.dumps(response).encode())
        
        elif path == '/generate-key':
            # Generate API key for new client
            query_params = urlparse.parse_qs(parsed_path.query)
            client_id = query_params.get('client_id', [None])[0]
            
            if not client_id:
                self._set_headers(400)
                self.wfile.write(json.dumps({'error': 'client_id required'}).encode())
                return
            
            api_key = self.api.generate_api_key(client_id)
            self._set_headers()
            response = {
                'client_id': client_id,
                'api_key': api_key,
                'generated_at': datetime.now().isoformat()
            }
            self.wfile.write(json.dumps(response).encode())
        
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({'error': 'Endpoint not found'}).encode())
    
    def do_POST(self):
        """Handle POST requests"""
        try:
            # Get request headers
            headers = dict(self.headers)
            
            # Validate API key
            api_key = headers.get('x-api-key')
            if not api_key:
                self._set_headers(401)
                self.wfile.write(json.dumps({'error': 'API key required'}).encode())
                return
            
            client_id = self.api.validate_api_key(api_key)
            if not client_id:
                self._set_headers(401)
                self.wfile.write(json.dumps({'error': 'Invalid API key'}).encode())
                return
            
            # Get client IP
            client_ip = headers.get('x-forwarded-for', self.client_address[0])
            
            # Read request body
            content_length = int(headers.get('content-length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                request_data = json.loads(post_data.decode())
            except json.JSONDecodeError:
                self._set_headers(400)
                self.wfile.write(json.dumps({'error': 'Invalid JSON'}).encode())
                return
            
            parsed_path = urlparse.urlparse(self.path)
            path = parsed_path.path
            
            if path == '/encrypt':
                # Encrypt media content
                media_data = base64.b64decode(request_data.get('media_data', ''))
                metadata = request_data.get('metadata', {})
                
                result = self.api.encrypt_media(media_data, client_id, metadata)
                self._set_headers()
                self.wfile.write(json.dumps(result).encode())
            
            elif path == '/validate':
                # Validate and potentially decrypt content
                protected_content = request_data.get('protected_content', '')
                
                result = self.api.validate_and_decrypt(
                    protected_content, client_id, headers, client_ip
                )
                
                # Send webhook if configured
                webhook_url = request_data.get('webhook_url')
                if webhook_url and result.get('validation_result'):
                    webhook_data = {
                        'event': 'validation_completed',
                        'client_id': client_id,
                        'result': result['status'],
                        'risk_score': result['validation_result']['risk_score'],
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    # Send webhook asynchronously (in real implementation)
                    # asyncio.create_task(self.api.send_webhook(webhook_url, webhook_data))
                
                self._set_headers()
                self.wfile.write(json.dumps(result).encode())
            
            elif path == '/analytics':
                # Get analytics for client
                analytics_data = {
                    'client_id': client_id,
                    'session_count': len(self.api.client_sessions.get(client_id, [])),
                    'recent_requests': self.api.client_sessions.get(client_id, [])[-10:],
                    'timestamp': datetime.now().isoformat()
                }
                
                self._set_headers()
                self.wfile.write(json.dumps(analytics_data).encode())
            
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

# For local testing
if __name__ == '__main__':
    from http.server import HTTPServer
    
    server = HTTPServer(('localhost', 8000), handler)
    print("Media Protection API running on http://localhost:8000")
    print("Available endpoints:")
    print("  GET  /health - Health check")
    print("  GET  /generate-key?client_id=xxx - Generate API key")
    print("  POST /encrypt - Encrypt media content")
    print("  POST /validate - Validate and decrypt content")
    print("  POST /analytics - Get client analytics")
    server.serve_forever()
