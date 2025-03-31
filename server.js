// server.js - Main entry point for the Node.js web application

const express = require('express');
const http = require('http');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');
const { promisify } = require('util');
const WebSocket = require('ws');
const net = require('net');
const { networkInterfaces } = require('os');
const cors = require('cors');
const bodyParser = require('body-parser');

// Create Express app
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Set up middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configuration
const config = {
  port: process.env.PORT || 3000,
  streamProtectionUrl: process.env.PROTECTION_URL || 'http://localhost:3000/protection',
  streamPort: process.env.STREAM_PORT || 8888,
  debugMode: process.env.DEBUG_MODE === 'true' || false
};

// Store active streams
const activeStreams = new Map();
// Store blocked IPs
const blockedIPs = new Set();
// Store client connections
const clients = new Map();

// Helper to get local IP address
function getLocalIP() {
  const interfaces = networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      // Skip over non-IPv4 and internal (loopback) addresses
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return '127.0.0.1';
}

const serverIP = getLocalIP();

// Logging utility
const logger = {
  info: (message) => {
    console.log(`[INFO] ${new Date().toISOString()}: ${message}`);
  },
  error: (message) => {
    console.error(`[ERROR] ${new Date().toISOString()}: ${message}`);
  },
  warning: (message) => {
    console.warn(`[WARNING] ${new Date().toISOString()}: ${message}`);
  },
  debug: (message) => {
    if (config.debugMode) {
      console.log(`[DEBUG] ${new Date().toISOString()}: ${message}`);
    }
  }
};

// Stream protection module
class StreamProtector {
  constructor() {
    this.isRunning = false;
    this.protectionProcess = null;
    this.networkMap = new Map(); // IP to MAC mapping
    this.lastScanTime = 0;
    this.scanInterval = 60000; // 1 minute between scans
  }

  async start() {
    if (this.isRunning) return;
    
    this.isRunning = true;
    logger.info('Starting stream protection module');

    try {
      // Start monitoring network
      this.monitorNetwork();
      
      // If you have a Python script to run, you can spawn it here
      // this.spawnPythonProtector();
      
      // Start periodic network scans
      this.startNetworkScan();
      
      logger.info('Stream protection module started');
    } catch (error) {
      logger.error(`Failed to start stream protection: ${error.message}`);
      this.isRunning = false;
    }
  }

  spawnPythonProtector() {
    // This would spawn the Python protection script if needed
    try {
      this.protectionProcess = spawn('python3', ['./stream_protector.py', 
        `--url=${config.streamProtectionUrl}`,
        `--port=${config.streamPort}`
      ]);

      this.protectionProcess.stdout.on('data', (data) => {
        logger.debug(`Protection script output: ${data}`);
      });

      this.protectionProcess.stderr.on('data', (data) => {
        logger.error(`Protection script error: ${data}`);
      });

      this.protectionProcess.on('close', (code) => {
        logger.info(`Protection script exited with code ${code}`);
        this.isRunning = false;
      });
    } catch (error) {
      logger.error(`Failed to spawn protection script: ${error.message}`);
    }
  }

  monitorNetwork() {
    wss.on('connection', (ws, req) => {
      const clientIp = req.socket.remoteAddress;
      logger.info(`New WebSocket connection from ${clientIp}`);
      
      // If this IP is blocked, close the connection immediately
      if (blockedIPs.has(clientIp)) {
        logger.warning(`Blocking connection from known bad IP: ${clientIp}`);
        ws.close();
        return;
      }

      // Store the client
      clients.set(ws, {
        ip: clientIp,
        connectTime: Date.now(),
        streamIds: new Set()
      });

      ws.on('message', (message) => {
        try {
          const data = JSON.parse(message);
          
          if (data.type === 'startStream') {
            const streamId = this.registerStream(ws, data.streamUrl);
            ws.send(JSON.stringify({ type: 'streamRegistered', streamId }));
          } else if (data.type === 'stopStream') {
            this.unregisterStream(ws, data.streamId);
          }
        } catch (err) {
          logger.error(`Error processing message: ${err.message}`);
        }
      });

      ws.on('close', () => {
        this.handleClientDisconnect(ws);
      });
    });
  }

  registerStream(ws, streamUrl) {
    const clientInfo = clients.get(ws);
    if (!clientInfo) return null;

    const streamId = crypto.randomUUID();
    
    // Add to active streams
    activeStreams.set(streamId, {
      url: streamUrl,
      clientIp: clientInfo.ip,
      startTime: Date.now(),
      bytesTransferred: 0
    });

    // Add to client's stream list
    clientInfo.streamIds.add(streamId);
    
    logger.info(`Registered stream ${streamId} for client ${clientInfo.ip}`);
    return streamId;
  }

  unregisterStream(ws, streamId) {
    const clientInfo = clients.get(ws);
    if (!clientInfo) return;

    if (activeStreams.has(streamId)) {
      activeStreams.delete(streamId);
      clientInfo.streamIds.delete(streamId);
      logger.info(`Unregistered stream ${streamId} for client ${clientInfo.ip}`);
    }
  }

  handleClientDisconnect(ws) {
    const clientInfo = clients.get(ws);
    if (!clientInfo) return;

    // Clean up client's streams
    for (const streamId of clientInfo.streamIds) {
      if (activeStreams.has(streamId)) {
        activeStreams.delete(streamId);
        logger.info(`Removed stream ${streamId} after client disconnect`);
      }
    }

    // Remove client
    clients.delete(ws);
    logger.info(`Client ${clientInfo.ip} disconnected`);
  }

  startNetworkScan() {
    setInterval(() => this.scanNetwork(), this.scanInterval);
    // Run an initial scan
    this.scanNetwork();
  }

  async scanNetwork() {
    try {
      const now = Date.now();
      
      // Don't scan too frequently
      if (now - this.lastScanTime < this.scanInterval) {
        return;
      }
      
      this.lastScanTime = now;
      logger.debug('Running network scan');

      // On Windows, you might use 'arp -a', on Linux 'ip neigh'
      const command = process.platform === 'win32' ? 'arp -a' : 'ip neigh';
      
      // Execute the command
      const { exec } = require('child_process');
      const execPromise = promisify(exec);
      const { stdout } = await execPromise(command);
      
      // Parse the output
      const previousDevices = new Set(this.networkMap.keys());
      const newDevices = new Set();
      
      if (process.platform === 'win32') {
        // Parse Windows ARP output
        const lines = stdout.split('\n');
        for (const line of lines) {
          const match = line.match(/(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]+)\s/i);
          if (match) {
            const [, ip, mac] = match;
            this.networkMap.set(ip, mac);
            newDevices.add(ip);
          }
        }
      } else {
        // Parse Linux IP neighbor output
        const lines = stdout.split('\n');
        for (const line of lines) {
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 5 && parts[0].includes('.')) {
            const ip = parts[0];
            const mac = parts[4];
            if (mac !== 'FAILED' && mac !== 'INCOMPLETE') {
              this.networkMap.set(ip, mac);
              newDevices.add(ip);
            }
          }
        }
      }
      
      // Check for new devices that weren't present before
      for (const ip of newDevices) {
        if (!previousDevices.has(ip) && ip !== serverIP) {
          const mac = this.networkMap.get(ip);
          logger.warning(`New device detected on network: ${ip} (MAC: ${mac})`);
          
          // Check if this device is connected to any active streams
          for (const [streamId, stream] of activeStreams.entries()) {
            if (stream.clientIp === ip) {
              logger.info(`New device ${ip} is connected to stream ${streamId}`);
            }
          }
        }
      }
      
      // Check for suspicious activity
      this.checkSuspiciousActivity();
      
    } catch (error) {
      logger.error(`Network scan failed: ${error.message}`);
    }
  }

  checkSuspiciousActivity() {
    // Implement suspicious activity detection logic here
    // For example, check for multiple connections from the same IP
    // or unusually high bandwidth usage
    
    const ipStreamCount = new Map();
    
    for (const [streamId, stream] of activeStreams.entries()) {
      const ip = stream.clientIp;
      ipStreamCount.set(ip, (ipStreamCount.get(ip) || 0) + 1);
    }
    
    // Check for IPs with suspiciously high number of streams
    for (const [ip, count] of ipStreamCount.entries()) {
      if (count > 5) { // Threshold can be adjusted
        logger.warning(`Suspicious activity: ${ip} has ${count} active streams`);
        this.terminateClientStreams(ip);
      }
    }
  }

  terminateClientStreams(clientIp) {
    // Terminate all streams for this client
    logger.warning(`Terminating all streams for client ${clientIp}`);
    
    // Block the IP
    blockedIPs.add(clientIp);
    
    // Find all streams for this IP
    const streamsToTerminate = [];
    for (const [streamId, stream] of activeStreams.entries()) {
      if (stream.clientIp === clientIp) {
        streamsToTerminate.push(streamId);
      }
    }
    
    // Terminate identified streams
    for (const streamId of streamsToTerminate) {
      activeStreams.delete(streamId);
    }
    
    // Disconnect WebSocket clients
    for (const [ws, clientInfo] of clients.entries()) {
      if (clientInfo.ip === clientIp) {
        try {
          ws.close();
        } catch (error) {
          logger.error(`Error closing WebSocket: ${error.message}`);
        }
      }
    }
    
    logger.info(`Terminated ${streamsToTerminate.length} streams for ${clientIp}`);
    
    // Broadcast blocked IP to all clients
    this.broadcastBlockedIP(clientIp);
    
    return streamsToTerminate.length;
  }

  broadcastBlockedIP(ip) {
    const message = JSON.stringify({
      type: 'ipBlocked',
      ip: ip,
      timestamp: new Date().toISOString()
    });
    
    for (const ws of clients.keys()) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(message);
      }
    }
  }

  stop() {
    this.isRunning = false;
    
    if (this.protectionProcess) {
      this.protectionProcess.kill();
      this.protectionProcess = null;
    }
    
    logger.info('Stream protection module stopped');
  }
}

// Create and start the stream protector
const streamProtector = new StreamProtector();
streamProtector.start();

// API endpoints
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Protection API endpoint
app.post('/protection', (req, res) => {
  const alert = req.body;
  logger.warning(`Protection alert received: ${JSON.stringify(alert)}`);
  
  if (alert.source) {
    streamProtector.terminateClientStreams(alert.source);
  }
  
  res.json({ status: 'alert received' });
});

// Stream status API endpoint
app.get('/api/streams', (req, res) => {
  const streams = [];
  for (const [id, stream] of activeStreams.entries()) {
    streams.push({
      id,
      clientIp: stream.clientIp,
      startTime: stream.startTime,
      duration: Date.now() - stream.startTime,
      bytesTransferred: stream.bytesTransferred
    });
  }
  
  res.json(streams);
});

// Start the server
server.listen(config.port, () => {
  logger.info(`Server running on port ${config.port}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  logger.info('Shutting down server...');
  streamProtector.stop();
  server.close(() => {
    logger.info('Server shutdown complete');
    process.exit(0);
  });
});
