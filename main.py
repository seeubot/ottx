/**
 * OTT Content Protection System
 * 
 * Features:
 * 1. Monitors data transfer speed between server and client
 * 2. Detects VPN usage and packet capture tools
 * 3. Automatically stops stream if security threats are detected
 */

class OTTProtectionSystem {
  constructor(config = {}) {
    // Default configuration
    this.config = {
      maxSpeedVariationThreshold: 0.3, // 30% variation threshold for speed anomalies
      speedCheckInterval: 2000,        // Check speed every 2 seconds
      vpnCheckInterval: 5000,          // Check for VPN every 5 seconds
      packetCaptureCheckInterval: 3000, // Check for packet capture every 3 seconds
      ...config
    };
    
    this.lastSpeedMeasurements = [];
    this.isStreaming = false;
    this.speedCheckTimer = null;
    this.vpnCheckTimer = null;
    this.packetCaptureCheckTimer = null;
  }

  /**
   * Start the protection system and monitoring
   */
  startProtection() {
    if (this.isStreaming) return;
    
    this.isStreaming = true;
    console.log("Protection system started");
    
    // Start monitoring speed
    this.speedCheckTimer = setInterval(() => this.checkDataTransferSpeed(), this.config.speedCheckInterval);
    
    // Start checking for VPN
    this.vpnCheckTimer = setInterval(() => this.checkForVPN(), this.config.vpnCheckInterval);
    
    // Start checking for packet capture
    this.packetCaptureCheckTimer = setInterval(() => this.checkForPacketCapture(), this.config.packetCaptureCheckInterval);
  }

  /**
   * Stop the protection system and all monitoring
   */
  stopProtection() {
    this.isStreaming = false;
    
    // Clear all timers
    clearInterval(this.speedCheckTimer);
    clearInterval(this.vpnCheckTimer);
    clearInterval(this.packetCaptureCheckTimer);
    
    console.log("Protection system stopped");
  }

  /**
   * Measures current data transfer speed
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
   * Checks if current data transfer speed indicates potential packet capture
   */
  async checkDataTransferSpeed() {
    if (!this.isStreaming) return;
    
    try {
      const currentSpeed = await this.measureCurrentSpeed();
      console.log(`Current transfer speed: ${currentSpeed.toFixed(2)} Mbps`);
      
      // Store last 5 measurements
      this.lastSpeedMeasurements.push(currentSpeed);
      if (this.lastSpeedMeasurements.length > 5) {
        this.lastSpeedMeasurements.shift();
      }
      
      // Only analyze if we have enough measurements
      if (this.lastSpeedMeasurements.length >= 3) {
        if (this.detectSpeedAnomaly()) {
          console.warn("Speed anomaly detected - possible packet capture");
          this.handleSecurityThreat("Unusual speed variation detected. Stream terminated for security reasons.");
        }
      }
    } catch (error) {
      console.error("Error measuring speed:", error);
    }
  }

  /**
   * Analyzes speed measurements to detect anomalies
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
   * Checks for VPN usage
   */
  async checkForVPN() {
    if (!this.isStreaming) return;
    
    try {
      // Check for common VPN indicators
      const vpnDetected = await this.detectVPN();
      
      if (vpnDetected) {
        console.warn("VPN usage detected");
        this.handleSecurityThreat("VPN detected. Streaming is not allowed through VPN connections.");
      }
    } catch (error) {
      console.error("Error checking for VPN:", error);
    }
  }

  /**
   * Detects if user is using a VPN
   * @returns {Promise<boolean>} True if VPN detected
   */
  async detectVPN() {
    // Method 1: WebRTC leak detection
    const hasWebRTCLeak = await this.checkWebRTCLeak();
    
    // Method 2: Check timezone inconsistency
    const hasTimezoneInconsistency = this.checkTimezoneInconsistency();
    
    // Method 3: IP geolocation anomaly
    const hasIPGeoAnomaly = await this.checkIPGeolocationAnomaly();
    
    return hasWebRTCLeak || hasTimezoneInconsistency || hasIPGeoAnomaly;
  }

  /**
   * Check for WebRTC leaks that might reveal VPN usage
   * @returns {Promise<boolean>}
   */
  async checkWebRTCLeak() {
    return new Promise((resolve) => {
      try {
        // This is a simplified implementation
        // In production, you would implement a full WebRTC leak test
        
        const pc = new RTCPeerConnection({
          iceServers: [{ urls: "stun:stun.l.google.com:19302" }]
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
        
        pc.createDataChannel("");
        pc.createOffer()
          .then(offer => pc.setLocalDescription(offer))
          .catch(() => resolve(false));
          
        // Timeout after 1 second
        setTimeout(() => {
          pc.close();
          resolve(false);
        }, 1000);
      } catch (err) {
        console.error("WebRTC check error:", err);
        resolve(false);
      }
    });
  }

  /**
   * Check for timezone inconsistencies that might indicate VPN
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
      console.error("Timezone check error:", err);
      return false;
    }
  }

  /**
   * Check for IP geolocation anomalies that might indicate VPN
   * @returns {Promise<boolean>}
   */
  async checkIPGeolocationAnomaly() {
    try {
      // In a real implementation, you would make a server call to check IP geolocation
      // For demo purposes, we'll simulate an API call
      return new Promise((resolve) => {
        // Simulate API call delay
        setTimeout(() => {
          // For demo purposes - would need actual IP check logic via server
          resolve(false);
        }, 500);
      });
    } catch (err) {
      console.error("IP geolocation check error:", err);
      return false;
    }
  }

  /**
   * Checks for packet capture tools
   */
  async checkForPacketCapture() {
    if (!this.isStreaming) return;
    
    try {
      // Check for packet capture indicators
      const packetCaptureDetected = await this.detectPacketCapture();
      
      if (packetCaptureDetected) {
        console.warn("Packet capture detected");
        this.handleSecurityThreat("Network traffic monitoring detected. Stream terminated for security reasons.");
      }
    } catch (error) {
      console.error("Error checking for packet capture:", error);
    }
  }

  /**
   * Detects if packet capture tools are being used
   * @returns {Promise<boolean>} True if packet capture detected
   */
  async detectPacketCapture() {
    // Method 1: Timing analysis for processing overhead
    const hasProcessingOverhead = await this.checkProcessingOverhead();
    
    // Method 2: Browser performance analysis
    const hasPerformanceAnomaly = this.checkPerformanceAnomaly();
    
    // Method 3: Network timing analysis
    const hasNetworkTimingAnomaly = await this.checkNetworkTimingAnomaly();
    
    return hasProcessingOverhead || hasPerformanceAnomaly || hasNetworkTimingAnomaly;
  }

  /**
   * Check for processing overhead that might indicate packet capture
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
   * Check for performance anomalies that might indicate packet capture
   * @returns {boolean}
   */
  checkPerformanceAnomaly() {
    try {
      // Check if performance entry buffer size is unusually large
      // (some packet capture tools hook into performance monitoring)
      if (performance && performance.getEntries) {
        const entries = performance.getEntries();
        // Threshold would need calibration in production
        return entries.length > 1000;
      }
      return false;
    } catch (err) {
      console.error("Performance check error:", err);
      return false;
    }
  }

  /**
   * Check for network timing anomalies that might indicate packet capture
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
                const requestTime = entry.responseStart - entry.requestStart;
                
                // Look for anomalies that might indicate packet interception
                // These thresholds would need calibration in production
                const hasAnomaly = 
                  connectTime > 100 || // Unusually high connect time
                  requestTime > 500 || // Unusually high request time
                  Math.abs(loadTime - entry.duration) > 50; // Timing discrepancy
                
                resolve(hasAnomaly);
              } else {
                resolve(false);
              }
            } else {
              resolve(false);
            }
          }, 100);
        };
        
        img.onerror = () => resolve(false);
        
        // Load a tiny image to measure network timing
        img.src = `/api/pixel.gif?_=${random}`;
      } catch (err) {
        console.error("Network timing check error:", err);
        resolve(false);
      }
    });
  }

  /**
   * Handle detected security threat
   * @param {string} reason Reason for stopping the stream
   */
  handleSecurityThreat(reason) {
    // Stop the stream immediately
    this.stopStream(reason);
    
    // Log the security incident
    this.logSecurityIncident(reason);
    
    // Stop protection system
    this.stopProtection();
  }
  
  /**
   * Stop the video stream
   * @param {string} reason Reason for stopping
   */
  stopStream(reason) {
    // Implementation depends on streaming technology used
    // This is a placeholder for actual implementation
    console.log(`Stream stopped: ${reason}`);
    
    // Example: Using HTML5 video element
    const videoElements = document.querySelectorAll('video');
    videoElements.forEach(video => {
      video.pause();
      if (video.srcObject) {
        const tracks = video.srcObject.getTracks();
        tracks.forEach(track => track.stop());
      }
      video.srcObject = null;
      video.src = "";
      video.removeAttribute('src');
    });
    
    // Display error message to user
    this.displayErrorMessage(reason);
  }
  
  /**
   * Display error message to the user
   * @param {string} message Error message
   */
  displayErrorMessage(message) {
    // Create error overlay
    const overlay = document.createElement('div');
    overlay.style.position = 'fixed';
    overlay.style.top = '0';
    overlay.style.left = '0';
    overlay.style.width = '100%';
    overlay.style.height = '100%';
    overlay.style.backgroundColor = 'rgba(0, 0, 0, 0.8)';
    overlay.style.color = 'white';
    overlay.style.display = 'flex';
    overlay.style.justifyContent = 'center';
    overlay.style.alignItems = 'center';
    overlay.style.zIndex = '9999';
    overlay.style.textAlign = 'center';
    overlay.style.padding = '20px';
    
    const messageElement = document.createElement('div');
    messageElement.innerHTML = `
      <h2>Streaming Error</h2>
      <p>${message}</p>
      <p>Please contact support if you believe this is an error.</p>
    `;
    
    overlay.appendChild(messageElement);
    document.body.appendChild(overlay);
  }
  
  /**
   * Log security incident for later analysis
   * @param {string} reason Security incident details
   */
  logSecurityIncident(reason) {
    // In production, send this to your server
    const incidentData = {
      timestamp: new Date().toISOString(),
      reason: reason,
      userAgent: navigator.userAgent,
      screenResolution: `${screen.width}x${screen.height}`,
      // Don't collect sensitive data
    };
    
    console.log("Security incident logged:", incidentData);
    
    // In production, you would send this data to your server
    // Example: 
    // fetch('/api/security-incidents', {
    //   method: 'POST',
    //   headers: { 'Content-Type': 'application/json' },
    //   body: JSON.stringify(incidentData)
    // });
  }
}

// Server-side configuration component
class ServerConfig {
  /**
   * Creates server configuration
   * @param {Object} config Server configuration
   */
  static createServer(config = {}) {
    // This would be implemented on your server
    // Here's a sample of what the configuration might look like
    return {
      // Monitor client speeds and detect anomalies
      speedMonitoring: {
        enabled: true,
        minRequiredSpeed: 1.5, // Mbps
        anomalyDetectionSensitivity: 0.3, // 30% variation
        allowedSpeedDrops: 2 // Number of consecutive drops allowed
      },
      
      // Security validations
      security: {
        checkVPN: true,
        checkPacketCapture: true,
        maxFailedChecks: 3,
        banDuration: 24 // hours
      },
      
      // Content delivery rules
      contentDelivery: {
        chunkSize: 5, // seconds
        encryptionEnabled: true,
        dynamicKeyRotation: true,
        keyRotationInterval: 30 // seconds
      }
    };
  }
}

// Example usage
const startProtection = () => {
  // Create protection system
  const protectionSystem = new OTTProtectionSystem({
    maxSpeedVariationThreshold: 0.25, // More sensitive
    speedCheckInterval: 3000, // Check more frequently
    vpnCheckInterval: 10000,
    packetCaptureCheckInterval: 5000
  });

  // Start monitoring
  protectionSystem.startProtection();
  
  return protectionSystem;
};

// This would be called when your video player initializes
// const protection = startProtection();

// To stop the protection manually:
// protection.stopProtection();
