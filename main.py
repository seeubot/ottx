/**
 * OTT Content Protection System for Node.js
 * Unified solution handling both client and server-side protection
 * 
 * Features:
 * 1. Server-side network monitoring and protection
 * 2. Client-side detection for VPN, packet capture tools
 * 3. Real-time data transfer speed monitoring
 * 4. Automatic stream termination on security threats
 */

const express = require('express');
const http = require('http');
const socketio = require('socket.io');
const pcap = require('pcap');
const ip = require('ip');
const child_process = require('child_process');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const util = require('util');
const winston = require('winston');
const arp = require('node-arp');
const pcapParser = require('pcap-parser');
const exec = util.promisify(child_process.exec);

// Configure logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ level, message, timestamp }) => {
      return `${timestamp} ${level}: ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'ott-protection.log' })
  ]
});

/**
 * OTT Protection Server Class
 * Handles network-level monitoring and protection
 */
class OTTProtectionServer {
  constructor(config = {}) {
    // Default configuration
    this.config = {
      serverPorts: [8080, 8443],
      monitoringInterval: 5000, // ms
      networkScanInterval: 30000, // ms
      maxSpeedVariationThreshold: 0.3,
      vpnCheckEnabled: true,
      packetCaptureCheckEnabled: true,
      blockDuration: 24 * 60 * 60 * 1000, // 24 hours in ms
      ...config
    };

    // Server state
    this.serverIp = this._getLocalIp();
    this.interfaces = this._getNetworkInterfaces();
    this.isRunning = false;
    this.activeStreams = new Map(); // Map of active streams
    this.blockedIps = new Set(); // Set of blocked IP addresses
    this.networkMap = new Map(); // Map of IP to MAC addresses
    this.previousNetworkMap = new Map(); // Previous network state
    this.captureHandles = []; // Store pcap capture handles
    
    logger.info(`OTT Protection Server initialized on ${this.serverIp}`);
    logger.info(`Monitoring interfaces: ${this.interfaces.join(', ')}`);
  }

  /**
   * Get local IP address
   */
  _getLocalIp() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
      for (const iface of interfaces[name]) {
        // Skip internal and non-ipv4 addresses
        if (iface.family === 'IPv4' && !iface.internal) {
          return iface.address;
        }
      }
    }
    return '127.0.0.1';
  }

  /**
   * Get network interfaces
   */
  _getNetworkInterfaces() {
    const interfaces = [];
    const networkInterfaces = os.networkInterfaces();
    
    for (const name of Object.keys(networkInterfaces)) {
      for (const iface of networkInterfaces[name]) {
        if (iface.family === 'IPv4' && !iface.internal) {
          interfaces.push(name);
          break;
        }
      }
    }
    
    return interfaces.length > 0 ? interfaces : ['eth0'];
  }

  /**
   * Start the protection server
   */
  async start() {
    if (this.isRunning) return;
    
    this.isRunning = true;
    logger.info('OTT Protection Server starting...');
    
    // Start network scanning
    this.networkScanInterval = setInterval(() => {
      this._scanNetwork();
    }, this.config.networkScanInterval);
    
    // Start packet capture on all interfaces
    for (const iface of this.interfaces) {
      try {
        this._startPacketCapture(iface);
      } catch (error) {
        logger.error(`Failed to start packet capture on ${iface}: ${error.message}`);
      }
    }
    
    // Start monitoring active streams
    this.monitoringInterval = setInterval(() => {
      this._monitorActiveStreams();
    }, this.config.monitoringInterval);
    
    logger.info('OTT Protection Server started successfully');
  }

  /**
   * Stop the protection server
   */
  stop() {
    if (!this.isRunning) return;
    
    this.isRunning = false;
    logger.info('OTT Protection Server stopping...');
    
    // Clear all intervals
    clearInterval(this.networkScanInterval);
    clearInterval(this.monitoringInterval);
    
    // Stop all packet captures
    for (const handle of this.captureHandles) {
      try {
        handle.close();
      } catch (error) {
        logger.error(`Error closing capture: ${error.message}`);
      }
    }
    
    // Clear firewall rules for blocked IPs
    this._clearFirewallRules();
    
    logger.info('OTT Protection Server stopped');
  }

  /**
   * Start packet capture on interface
   * @param {string} iface - Network interface
   */
  _startPacketCapture(iface) {
    try {
      // Create a filter for our server ports
      const portFilter = this.config.serverPorts.map(port => `port ${port}`).join(' or ');
      const filter = `ip and (${portFilter})`;
      
      // Start packet capture
      logger.info(`Starting packet capture on ${iface} with filter: ${filter}`);
      const pcapSession = pcap.createSession(iface, filter);
      
      // Store the handle
      this.captureHandles.push(pcapSession);
      
      // Handle packets
      pcapSession.on('packet', (rawPacket) => {
        try {
          const packet = pcap.decode.packet(rawPacket);
          this._processPacket(packet);
        } catch (error) {
          logger.error(`Error processing packet: ${error.message}`);
        }
      });
      
    } catch (error) {
      logger.error(`Failed to set up packet capture on ${iface}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Process captured packet
   * @param {object} packet - Parsed packet object
   */
  _processPacket(packet) {
    if (!packet.payload || !packet.payload.payload) return;
    
    const ipPacket = packet.payload;
    const tcpPacket = ipPacket.payload;
    
    if (!tcpPacket || !tcpPacket.dport) return;
    
    const srcIp = ipPacket.saddr.addr.join('.');
    const dstIp = ipPacket.daddr.addr.join('.');
    const srcPort = tcpPacket.sport;
    const dstPort = tcpPacket.dport;
    
    // Check if this is traffic to/from our server ports
    let streamId = null;
    let clientIp = null;
    
    if (dstIp === this.serverIp && this.config.serverPorts.includes(dstPort)) {
      // Inbound traffic to server
      streamId = `${srcIp}:${srcPort}-${dstPort}`;
      clientIp = srcIp;
    } else if (srcIp === this.serverIp && this.config.serverPorts.includes(srcPort)) {
      // Outbound traffic from server
      streamId = `${dstIp}:${dstPort}-${srcPort}`;
      clientIp = dstIp;
    }
    
    if (streamId && clientIp) {
      // Check if client is blocked
      if (this.blockedIps.has(clientIp)) {
        logger.warn(`Detected traffic from blocked IP: ${clientIp}`);
        this._terminateStream(streamId);
        return;
      }
      
      // Update stream information
      if (!this.activeStreams.has(streamId)) {
        this.activeStreams.set(streamId, {
          clientIp,
          startTime: Date.now(),
          lastActivity: Date.now(),
          bytesSent: tcpPacket.data ? tcpPacket.data.length : 0,
          packetCount: 1
        });
        logger.info(`New stream detected: ${streamId}`);
      } else {
        const stream = this.activeStreams.get(streamId);
        stream.bytesSent += tcpPacket.data ? tcpPacket.data.length : 0;
        stream.packetCount += 1;
        stream.lastActivity = Date.now();
      }
    }
  }

  /**
   * Scan network for devices
   */
  async _scanNetwork() {
    try {
      // Store previous network map
      this.previousNetworkMap = new Map(this.networkMap);
      
      // Scan ARP table to find devices
      const { stdout } = await exec('arp -a');
      
      // Parse ARP table output
      this.networkMap.clear();
      
      const lines = stdout.split('\n');
      for (const line of lines) {
        const match = line.match(/\((\d+\.\d+\.\d+\.\d+)\) at ([0-9A-Fa-f:]+)/);
        if (match) {
          const [, deviceIp, macAddress] = match;
          this.networkMap.set(deviceIp, macAddress.toLowerCase());
        }
      }
      
      // Check for new devices
      this._checkNewDevices();
      
      // Check for suspicious network activity
      this._checkSuspiciousActivity();
      
    } catch (error) {
      logger.error(`Error scanning network: ${error.message}`);
    }
  }

  /**
   * Check for new devices on the network
   */
  _checkNewDevices() {
    for (const [ip, mac] of this.networkMap.entries()) {
      if (!this.previousNetworkMap.has(ip) && ip !== this.serverIp) {
        logger.warn(`New device detected on network: ${ip} (MAC: ${mac})`);
        
        // Check if this device is using any active streams
        for (const [streamId, stream] of this.activeStreams.entries()) {
          if (stream.clientIp === ip) {
            logger.info(`New device ${ip} has an active stream: ${streamId}`);
          }
        }
      }
    }
  }

  /**
   * Check for suspicious network activity
   */
  _checkSuspiciousActivity() {
    // Check for duplicate MACs (potential spoofing)
    const macAddresses = new Map();
    
    for (const [ip, mac] of this.networkMap.entries()) {
      if (macAddresses.has(mac)) {
        const existingIp = macAddresses.get(mac);
        logger.warn(`Potential ARP spoofing detected: ${ip} and ${existingIp} have same MAC ${mac}`);
        
        // Block both IPs
        this._blockIp(ip);
        this._blockIp(existingIp);
      } else {
        macAddresses.set(mac, ip);
      }
    }
    
    // Check for incomplete ARP entries
    // (This is OS-specific but would be implemented here)
  }

  /**
   * Monitor active streams for suspicious behavior
   */
  _monitorActiveStreams() {
    const now = Date.now();
    const expiredStreams = [];
    
    for (const [streamId, stream] of this.activeStreams.entries()) {
      // Check for expired streams (inactive for more than 1 hour)
      if (now - stream.lastActivity > 3600000) {
        expiredStreams.push(streamId);
        continue;
      }
      
      // Calculate stream metrics
      const duration = (now - stream.startTime) / 1000; // seconds
      const avgBandwidth = (stream.bytesSent * 8) / (duration * 1000000); // Mbps
      
      // Log suspicious low bandwidth (potential packet capturing)
      if (duration > 10 && avgBandwidth < 0.5) {
        logger.warn(`Suspicious low bandwidth detected for stream ${streamId}: ${avgBandwidth.toFixed(2)} Mbps`);
        
        // Investigate this client further
        this._investigateClient(stream.clientIp);
      }
    }
    
    // Remove expired streams
    for (const streamId of expiredStreams) {
      this.activeStreams.delete(streamId);
      logger.info(`Stream expired: ${streamId}`);
    }
  }

  /**
   * Investigate client for suspicious activity
   * @param {string} clientIp - Client IP address
   */
  async _investigateClient(clientIp) {
    // Count client's active streams
    let streamCount = 0;
    for (const stream of this.activeStreams.values()) {
      if (stream.clientIp === clientIp) {
        streamCount++;
      }
    }
    
    // If client has multiple streams, that's suspicious
    if (streamCount > 3) {
      logger.warn(`Client ${clientIp} has ${streamCount} active streams - blocking`);
      this._blockIp(clientIp);
      return;
    }
    
    // Additional investigation methods would be implemented here
  }

  /**
   * Block an IP address
   * @param {string} clientIp - IP address to block
   */
  async _blockIp(clientIp) {
    if (this.blockedIps.has(clientIp)) return;
    
    logger.warn(`Blocking IP address: ${clientIp}`);
    this.blockedIps.add(clientIp);
    
    // Terminate all streams from this client
    this._terminateClientStreams(clientIp);
    
    // Add firewall rules
    try {
      if (os.platform() === 'linux') {
        await exec(`iptables -A INPUT -s ${clientIp} -j DROP`);
        await exec(`iptables -A OUTPUT -d ${clientIp} -j DROP`);
      } else if (os.platform() === 'win32') {
        // Windows firewall commands would go here
        await exec(`netsh advfirewall firewall add rule name="OTT_BLOCK_${clientIp}" dir=in action=block remoteip=${clientIp}`);
        await exec(`netsh advfirewall firewall add rule name="OTT_BLOCK_${clientIp}" dir=out action=block remoteip=${clientIp}`);
      }
    } catch (error) {
      logger.error(`Failed to add firewall rules for ${clientIp}: ${error.message}`);
    }
  }

  /**
   * Clear firewall rules for all blocked IPs
   */
  async _clearFirewallRules() {
    for (const blockedIp of this.blockedIps) {
      try {
        if (os.platform() === 'linux') {
          await exec(`iptables -D INPUT -s ${blockedIp} -j DROP`);
          await exec(`iptables -D OUTPUT -d ${blockedIp} -j DROP`);
        } else if (os.platform() === 'win32') {
          await exec(`netsh advfirewall firewall delete rule name="OTT_BLOCK_${blockedIp}"`);
        }
      } catch (error) {
        logger.error(`Failed to remove firewall rules for ${blockedIp}: ${error.message}`);
      }
    }
  }

  /**
   * Terminate all streams from a specific client
   * @param {string} clientIp - Client IP address
   */
  _terminateClientStreams(clientIp) {
    let terminatedCount = 0;
    
    for (const [streamId, stream] of this.activeStreams.entries()) {
      if (stream.clientIp === clientIp) {
        this._terminateStream(streamId);
        terminatedCount++;
      }
    }
    
    logger.info(`Terminated ${terminatedCount} streams from client ${clientIp}`);
    return terminatedCount;
  }

  /**
   * Terminate a specific stream
   * @param {string} streamId - Stream identifier
   */
  _terminateStream(streamId) {
    if (!this.activeStreams.has(streamId)) return false;
    
    logger.info(`Terminating stream: ${streamId}`);
    
    const stream = this.activeStreams.get(streamId);
    this.activeStreams.delete(streamId);
    
    // Send reset packet (would be implemented via raw sockets)
    // This is simplified for the demo
    
    return true;
  }

  /**
   * Register a new stream with the system
   * @param {string} clientIp - Client IP address
   * @param {number} clientPort - Client port
   * @param {number} serverPort - Server port
   */
  registerStream(clientIp, clientPort, serverPort) {
    // Check if client is blocked
    if (this.blockedIps.has(clientIp)) {
      logger.warn(`Rejected connection from blocked client: ${clientIp}`);
      return false;
    }
    
    const streamId = `${clientIp}:${clientPort}-${serverPort}`;
    
    this.activeStreams.set(streamId, {
      clientIp,
      startTime: Date.now(),
      lastActivity: Date.now(),
      bytesSent: 0,
      packetCount: 0
    });
    
    logger.info(`Registered stream ${streamId}`);
    return true;
  }
}

/**
 * Client-side protection system (to be sent to the browser)
 */
class ClientProtection {
  constructor(config = {}) {
    this.config = {
      maxSpeedVariationThreshold: 0.3,
      speedCheckInterval: 2000,
      vpnCheckInterval: 5000,
      packetCaptureCheckInterval: 3000,
      ...config
    };
    
    this.lastSpeedMeasurements = [];
    this.isStreaming = false;
    this.speedCheckTimer = null;
    this.vpnCheckTimer = null;
    this.packetCaptureCheckTimer = null;
    this.socket = null;
  }

  /**
   * Connect to the server for security reporting
   * @param {string} serverUrl - Socket.io server URL
   */
  connect(serverUrl) {
    this.socket = io(serverUrl);
    
    this.socket.on('connect', () => {
      console.log('Connected to protection server');
    });
    
    this.socket.on('disconnect', () => {
      console.log('Disconnected from protection server');
    });
  }

  /**
   * Start the client-side protection system
   */
  startProtection() {
    if (this.isStreaming) return;
    
    this.isStreaming = true;
    console.log('Client protection system started');
    
    // Start monitoring speed
    this.speedCheckTimer = setInterval(() => this.checkDataTransferSpeed(), this.config.speedCheckInterval);
    
    // Start checking for VPN
    this.vpnCheckTimer = setInterval(() => this.checkForVPN(), this.config.vpnCheckInterval);
    
    // Start checking for packet capture
    this.packetCaptureCheckTimer = setInterval(() => this.checkForPacketCapture(), this.config.packetCaptureCheckInterval);
  }

  /**
   * Stop the client-side protection system
   */
  stopProtection() {
    this.isStreaming = false;
    
    // Clear all timers
    clearInterval(this.speedCheckTimer);
    clearInterval(this.vpnCheckTimer);
    clearInterval(this.packetCaptureCheckTimer);
    
    console.log('Client protection system stopped');
  }

  /**
   * Measure current data transfer speed
   * @returns {Promise<number>} Speed in Mbps
   */
  async measureCurrentSpeed() {
    return new Promise((resolve) => {
      const startTime = performance.now();
      const testData = new Blob([new ArrayBuffer(1000000)]); // 1MB test data
      const url = URL.createObjectURL(testData);
      
      const image = new Image();
      image.onload = () => {
        const endTime = performance.now();
        const duration = (endTime - startTime) / 1000; // Convert to seconds
        const speedMbps = (1 / duration) * 8; // Convert to Mbps
        
        URL.revokeObjectURL(url);
        resolve(speedMbps);
      };
      
      image.onerror = () => {
        URL.revokeObjectURL(url);
        resolve(0); // Error case
      };
      
      image.src = url;
    });
  }

  /**
   * Check data transfer speed for anomalies
   */
  async checkDataTransferSpeed() {
    if (!this.isStreaming) return;
    
    try {
      const currentSpeed = await this.measureCurrentSpeed();
      console.log(`Current transfer speed: ${currentSpeed.toFixed(2)} Mbps`);
      
      // Report to server
      if (this.socket && this.socket.connected) {
        this.socket.emit('speedMeasurement', { speed: currentSpeed });
      }
      
      // Store last 5 measurements
      this.lastSpeedMeasurements.push(currentSpeed);
      if (this.lastSpeedMeasurements.length > 5) {
        this.lastSpeedMeasurements.shift();
      }
      
      // Only analyze if we have enough measurements
      if (this.lastSpeedMeasurements.length >= 3) {
        if (this.detectSpeedAnomaly()) {
          console.warn('Speed anomaly detected - possible packet capture');
          this.handleSecurityThreat('Unusual speed variation detected. Stream terminated for security reasons.');
        }
      }
    } catch (error) {
      console.error('Error measuring speed:', error);
    }
  }

  /**
   * Detect speed anomalies
   * @returns {boolean} True if anomaly detected
   */
  detectSpeedAnomaly() {
    const avg = this.lastSpeedMeasurements.reduce((sum, speed) => sum + speed, 0) / this.lastSpeedMeasurements.length;
    
    // Check for sudden drops in speed which might indicate packet capture
    const hasAnomaly = this.lastSpeedMeasurements.some(speed => {
      const variation = Math.abs(speed - avg) / avg;
      return variation > this.config.maxSpeedVariationThreshold;
    });
    
    return hasAnomaly;
  }

  /**
   * Check for VPN usage
   */
  async checkForVPN() {
    if (!this.isStreaming) return;
    
    try {
      // Check for common VPN indicators
      const vpnDetected = await this.detectVPN();
      
      if (vpnDetected) {
        console.warn('VPN usage detected');
        this.handleSecurityThreat('VPN detected. Streaming is not allowed through VPN connections.');
      }
    } catch (error) {
      console.error('Error checking for VPN:', error);
    }
  }

  /**
   * Detect VPN usage
   * @returns {Promise<boolean>} True if VPN detected
   */
  async detectVPN() {
    // Method 1: WebRTC leak detection
    const hasWebRTCLeak = await this.checkWebRTCLeak();
    
    // Method 2: Check timezone inconsistency
    const hasTimezoneInconsistency = this.checkTimezoneInconsistency();
    
    // Method 3: IP geolocation anomaly
    const hasIPGeoAnomaly = await this.checkIPGeolocationAnomaly();
    
    // Report to server
    if (this.socket && this.socket.connected) {
      this.socket.emit('vpnCheck', {
        webrtcLeak: hasWebRTCLeak,
        timezoneInconsistency: hasTimezoneInconsistency,
        ipGeoAnomaly: hasIPGeoAnomaly
      });
    }
    
    return hasWebRTCLeak || hasTimezoneInconsistency || hasIPGeoAnomaly;
  }

  /**
   * Check for WebRTC leaks
   * @returns {Promise<boolean>}
   */
  async checkWebRTCLeak() {
    return new Promise((resolve) => {
      try {
        const pc = new RTCPeerConnection({
          iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
        });
        
        let localIPs = new Set();
        let publicIP;
        
        pc.onicecandidate = (event) => {
          if (!event.candidate) {
            pc.close();
            
            // Compare IPs for inconsistencies indicating VPN
            if (localIPs.size > 0 && publicIP) {
              // Check if public and local IPs are from different subnets/regions
              resolve(true); // For demo purposes - would need actual comparison logic
            } else {
              resolve(false);
            }
            return;
          }
          
          const ipRegex = /([0-9]{1,3}(\.[0-9]{1,3}){3})/;
          const match = ipRegex.exec(event.candidate.candidate);
          if (match) {
            const ip = match[1];
            if (ip.match(/^(192\.168\.|169\.254\.|10\.|172\.(1[6-9]|2\d|3[01]))/)) {
              localIPs.add(ip);
            } else {
              publicIP = ip;
            }
          }
        };
        
        pc.createDataChannel('');
        pc.createOffer()
          .then(offer => pc.setLocalDescription(offer))
          .catch(() => resolve(false));
          
        // Timeout after 1 second
        setTimeout(() => {
          pc.close();
          resolve(false);
        }, 1000);
      } catch (err) {
        console.error('WebRTC check error:', err);
        resolve(false);
      }
    });
  }

  /**
   * Check for timezone inconsistencies
   * @returns {boolean}
   */
  checkTimezoneInconsistency() {
    try {
      // Get browser's reported timezone
      const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
      
      // In a real implementation, you would compare this with IP geolocation timezone
      // For demo purposes, we'll just return false
      return false;
    } catch (err) {
      console.error('Timezone check error:', err);
      return false;
    }
  }

  /**
   * Check for IP geolocation anomalies
   * @returns {Promise<boolean>}
   */
  async checkIPGeolocationAnomaly() {
    try {
      // In a real implementation, this would make a server-side request
      // to check IP geolocation vs browser language/timezone
      return false;
    } catch (err) {
      console.error('IP geolocation check error:', err);
      return false;
    }
  }

  /**
   * Check for packet capture tools
   */
  async checkForPacketCapture() {
    if (!this.isStreaming) return;
    
    try {
      // Check for packet capture indicators
      const packetCaptureDetected = await this.detectPacketCapture();
      
      if (packetCaptureDetected) {
        console.warn('Packet capture detected');
        this.handleSecurityThreat('Network traffic monitoring detected. Stream terminated for security reasons.');
      }
    } catch (error) {
      console.error('Error checking for packet capture:', error);
    }
  }

  /**
   * Detect packet capture tools
   * @returns {Promise<boolean>} True if packet capture detected
   */
  async detectPacketCapture() {
    // Method 1: Timing analysis for processing overhead
    const hasProcessingOverhead = await this.checkProcessingOverhead();
    
    // Method 2: Browser performance analysis
    const hasPerformanceAnomaly = this.checkPerformanceAnomaly();
    
    // Method 3: Network timing analysis
    const hasNetworkTimingAnomaly = await this.checkNetworkTimingAnomaly();
    
    // Report to server
    if (this.socket && this.socket.connected) {
      this.socket.emit('packetCaptureCheck', {
        processingOverhead: hasProcessingOverhead,
        performanceAnomaly: hasPerformanceAnomaly,
        networkTimingAnomaly: hasNetworkTimingAnomaly
      });
    }
    
    return hasProcessingOverhead || hasPerformanceAnomaly || hasNetworkTimingAnomaly;
  }

  /**
   * Check for processing overhead
   * @returns {Promise<boolean>}
   */
  async checkProcessingOverhead() {
    return new Promise((resolve) => {
      const samples = 20;
      const results = [];
      
      const measure = (iteration) => {
        if (iteration >= samples) {
          // Analyze results
          const avg = results.reduce((sum, time) => sum + time, 0) / results.length;
          const threshold = 5; // 5ms threshold (would need calibration in production)
          
          resolve(avg > threshold);
          return;
        }
        
        const start = performance.now();
        
        // Create a small network request
        fetch('/api/healthcheck?_=' + Math.random(), { method: 'HEAD' })
          .then(() => {
            const end = performance.now();
            results.push(end - start);
            measure(iteration + 1);
          })
          .catch(() => {
            // Continue even if request fails
            measure(iteration + 1);
          });
      };
      
      measure(0);
    });
  }

  /**
   * Check for performance anomalies
   * @returns {boolean}
   */
  checkPerformanceAnomaly() {
    try {
      // Check if performance entry buffer size is unusually large
      if (performance && performance.getEntries) {
        const entries = performance.getEntries();
        return entries.length > 1000;
      }
      return false;
    } catch (err) {
      console.error('Performance check error:', err);
      return false;
    }
  }

  /**
   * Check for network timing anomalies
   * @returns {Promise<boolean>}
   */
  async checkNetworkTimingAnomaly() {
    return new Promise((resolve) => {
      try {
        // Create a resource timing entry by loading a tiny resource
        const img = new Image();
        const random = Math.random();
        const start = performance.now();
        
        img.onload = () => {
          const end = performance.now();
          const loadTime = end - start;
          
          // Get the actual resource timing entry
          setTimeout(() => {
            if (performance && performance.getEntriesByName) {
              const entries = performance.getEntriesByName(img.src);
              if (entries.length > 0) {
                const entry = entries[0];
                
                // Check if there are unusual gaps in the timing
                const connectTime = entry.connectEnd - entry.connectStart;
                const requestTime = entry.responseStart - entry.
