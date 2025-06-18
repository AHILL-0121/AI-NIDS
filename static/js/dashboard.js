// NIDS Dashboard JavaScript
class NIDSDashboard {
    constructor() {
        this.updateInterval = null;
        this.charts = {};
        this.currentStatus = 'stopped';
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadConfiguration();
        this.startUpdates();
        this.initializeCharts();
    }

    bindEvents() {
        // Control buttons
        document.getElementById('start-btn').addEventListener('click', () => this.startNIDS());
        document.getElementById('stop-btn').addEventListener('click', () => this.stopNIDS());
        document.getElementById('train-btn').addEventListener('click', () => this.showTrainingModal());
        document.getElementById('clear-alerts-btn').addEventListener('click', () => this.clearAlerts());

        // Training modal
        document.getElementById('start-training-btn').addEventListener('click', () => this.startTraining());
        document.getElementById('training-type').addEventListener('change', (e) => this.toggleTrainingOptions(e.target.value));

        // Configuration form
        document.getElementById('config-form').addEventListener('submit', (e) => this.saveConfiguration(e));

        // Tab changes
        document.querySelectorAll('[data-bs-toggle="tab"]').forEach(tab => {
            tab.addEventListener('shown.bs.tab', (e) => this.onTabChange(e));
        });
    }

    async startNIDS() {
        try {
            const modelType = document.getElementById('model-type').value;
            const netInterface = document.getElementById('network-interface').value;

            const response = await fetch('/api/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model_type: modelType,
                    interface: netInterface
                })
            });

            const result = await response.json();
            
            if (result.success) {
                this.showNotification('NIDS started successfully', 'success');
                this.updateStatus('running');
            } else {
                this.showNotification(result.message, 'error');
            }
        } catch (error) {
            this.showNotification('Error starting NIDS: ' + error.message, 'error');
        }
    }

    async stopNIDS() {
        try {
            const response = await fetch('/api/stop', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            const result = await response.json();
            
            if (result.success) {
                this.showNotification('NIDS stopped successfully', 'success');
                this.updateStatus('stopped');
                if (result.report) {
                    const pdfName = result.report.split('/').pop();
                    const reportUrl = `/reports/${pdfName}`;
                    this.showNotification(
                        `Session report generated: <a href='${reportUrl}' download target='_blank'>Download PDF Report</a>`,
                        'info'
                    );
                }
            } else {
                this.showNotification(result.message, 'error');
            }
        } catch (error) {
            this.showNotification('Error stopping NIDS: ' + error.message, 'error');
        }
    }

    async startTraining() {
        try {
            const trainingType = document.getElementById('training-type').value;
            const trainingData = {
                type: trainingType
            };

            if (trainingType === 'synthetic') {
                trainingData.n_samples = parseInt(document.getElementById('n-samples').value);
                trainingData.anomaly_ratio = parseFloat(document.getElementById('anomaly-ratio').value);
            } else if (trainingType === 'pcap') {
                trainingData.pcap_file = document.getElementById('pcap-file').value;
                trainingData.max_packets = parseInt(document.getElementById('max-packets').value);
            }

            const response = await fetch('/api/train', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(trainingData)
            });

            const result = await response.json();
            
            if (result.success) {
                this.showNotification('Model training completed successfully', 'success');
                bootstrap.Modal.getInstance(document.getElementById('trainingModal')).hide();
            } else {
                this.showNotification(result.message, 'error');
            }
        } catch (error) {
            this.showNotification('Error training model: ' + error.message, 'error');
        }
    }

    async clearAlerts() {
        try {
            const response = await fetch('/api/clear-alerts', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            const result = await response.json();
            
            if (result.success) {
                this.showNotification('Alerts cleared successfully', 'success');
                this.updateAlerts([]);
            } else {
                this.showNotification(result.message, 'error');
            }
        } catch (error) {
            this.showNotification('Error clearing alerts: ' + error.message, 'error');
        }
    }

    async saveConfiguration(event) {
        event.preventDefault();
        
        try {
            const config = {
                network_interface: document.getElementById('network-interface').value,
                anomaly_threshold: parseFloat(document.getElementById('anomaly-threshold').value),
                feature_window_size: parseInt(document.getElementById('feature-window-size').value),
                alert_cooldown: parseInt(document.getElementById('alert-cooldown').value),
                web_port: parseInt(document.getElementById('web-port').value)
            };

            const response = await fetch('/api/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(config)
            });

            const result = await response.json();
            
            if (result.success) {
                this.showNotification('Configuration saved successfully', 'success');
            } else {
                this.showNotification(result.message, 'error');
            }
        } catch (error) {
            this.showNotification('Error saving configuration: ' + error.message, 'error');
        }
    }

    async loadConfiguration() {
        try {
            const response = await fetch('/api/config');
            const config = await response.json();
            
            document.getElementById('network-interface').value = config.network_interface || 'Ethernet';
            document.getElementById('anomaly-threshold').value = config.anomaly_threshold || 0.7;
            document.getElementById('feature-window-size').value = config.feature_window_size || 100;
            document.getElementById('alert-cooldown').value = config.alert_cooldown || 60;
            document.getElementById('web-port').value = config.web_port || 5000;
            document.getElementById('model-type').value = config.model_type || 'ensemble';
        } catch (error) {
            console.error('Error loading configuration:', error);
        }
    }

    showTrainingModal() {
        const modal = new bootstrap.Modal(document.getElementById('trainingModal'));
        modal.show();
    }

    toggleTrainingOptions(trainingType) {
        const syntheticOptions = document.querySelectorAll('#synthetic-options');
        const pcapOptions = document.querySelectorAll('#pcap-options');
        
        if (trainingType === 'synthetic') {
            syntheticOptions.forEach(el => el.style.display = 'block');
            pcapOptions.forEach(el => el.style.display = 'none');
        } else if (trainingType === 'pcap') {
            syntheticOptions.forEach(el => el.style.display = 'none');
            pcapOptions.forEach(el => el.style.display = 'block');
        }
    }

    startUpdates() {
        this.updateStatus();
        this.updateMetrics();
        
        this.updateInterval = setInterval(() => {
            this.updateStatus();
            this.updateMetrics();
        }, 2000);
    }

    async updateStatus() {
        try {
            const response = await fetch('/api/status');
            const data = await response.json();
            
            this.currentStatus = data.status;
            this.updateStatusIndicator(data.status);
            this.updateControlButtons(data.status);
            
            if (data.status === 'running') {
                this.updateMetrics(data.stats);
                this.updateAlerts(data.recent_alerts);
            } else if (data.status === 'stopped') {
                // Clear metrics and charts when stopped
                this.clearMetricsAndCharts();
                this.updateAlerts([]);
            }
        } catch (error) {
            console.error('Error updating status:', error);
            this.updateStatusIndicator('error');
        }
    }

    updateStatusIndicator(status) {
        const indicator = document.getElementById('status-indicator');
        const text = document.getElementById('status-text');
        
        indicator.className = 'status-indicator';
        
        switch (status) {
            case 'running':
                indicator.classList.add('status-running');
                text.textContent = 'Running';
                break;
            case 'stopped':
                indicator.classList.add('status-stopped');
                text.textContent = 'Stopped';
                break;
            case 'error':
                indicator.classList.add('status-error');
                text.textContent = 'Error';
                break;
            default:
                indicator.classList.add('status-stopped');
                text.textContent = 'Unknown';
        }
    }

    updateControlButtons(status) {
        const startBtn = document.getElementById('start-btn');
        const stopBtn = document.getElementById('stop-btn');
        
        if (status === 'running') {
            startBtn.disabled = true;
            stopBtn.disabled = false;
        } else {
            startBtn.disabled = false;
            stopBtn.disabled = true;
        }
    }

    updateMetrics(stats = null) {
        if (!stats) {
            // Clear metrics if no stats provided (e.g., stopped)
            document.getElementById('packets-processed').textContent = 0;
            document.getElementById('anomalies-detected').textContent = 0;
            document.getElementById('packet-rate').textContent = '0.0';
            document.getElementById('uptime').textContent = this.formatUptime(0);
            // Also clear charts
            this.clearCharts();
            return;
        }
        
        document.getElementById('packets-processed').textContent = stats.total_packets_processed || 0;
        document.getElementById('anomalies-detected').textContent = stats.anomalies_detected || 0;
        document.getElementById('packet-rate').textContent = (stats.capture_stats?.packets_per_second || 0).toFixed(1);
        
        const uptime = stats.uptime || 0;
        document.getElementById('uptime').textContent = this.formatUptime(uptime);
        
        // Update charts if they exist
        this.updateCharts(stats);
    }

    updateAlerts(alerts = []) {
        const container = document.getElementById('alerts-container');
        const count = document.getElementById('alert-count');
        
        count.textContent = alerts.length;
        
        if (alerts.length === 0) {
            container.innerHTML = '<p class="text-muted">No alerts to display</p>';
            return;
        }
        
        const alertsHtml = alerts.map(alert => this.createAlertHtml(alert)).join('');
        container.innerHTML = alertsHtml;
    }

    createAlertHtml(alert) {
        const details = this.formatAlertDetails(alert.details);
        const explanation = alert.explanation ? `<div class='alert-explanation'><i class='fas fa-info-circle'></i> ${alert.explanation}</div>` : '';
        return `
            <div class="alert-item ${this.getAlertClass(alert.type)}">
                <div><strong>Type:</strong> ${alert.type}</div>
                <div><strong>Time:</strong> ${alert.datetime}</div>
                <div><strong>Details:</strong> ${details}</div>
                ${explanation}
            </div>
        `;
    }

    getAlertClass(alertType) {
        switch (alertType) {
            case 'ml_anomaly':
                return 'alert-warning';
            case 'port_scan':
            case 'ddos_indicator':
                return '';
            default:
                return 'alert-normal';
        }
    }

    formatAlertDetails(details) {
        if (!details) return 'No details available';
        
        const parts = [];
        
        if (details.src_ip) parts.push(`Source: ${details.src_ip}`);
        if (details.dst_ip) parts.push(`Destination: ${details.dst_ip}`);
        if (details.packet_count) parts.push(`Packets: ${details.packet_count}`);
        if (details.protocol) parts.push(`Protocol: ${details.protocol}`);
        
        return parts.join(' | ');
    }

    formatUptime(seconds) {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = Math.floor(seconds % 60);
        
        if (hours > 0) {
            return `${hours}h ${minutes}m ${secs}s`;
        } else if (minutes > 0) {
            return `${minutes}m ${secs}s`;
        } else {
            return `${secs}s`;
        }
    }

    initializeCharts() {
        // Real-time traffic chart
        this.trafficChartData = {
            x: [],
            y: [],
            type: 'scatter',
            mode: 'lines+markers',
            name: 'Packets/sec',
            line: { color: '#667eea' }
        };
        Plotly.newPlot('traffic-chart', [this.trafficChartData], {
            title: 'Packets Processed Over Time',
            xaxis: { title: 'Time (s)' },
            yaxis: { title: 'Packets/sec' },
            margin: { t: 40 }
        });

        // Protocol distribution chart
        this.protocolChartData = {
            labels: ['TCP', 'UDP', 'ICMP', 'Other'],
            values: [0, 0, 0, 0],
            type: 'pie',
            marker: { colors: ['#28a745', '#20c997', '#ffc107', '#6c757d'] }
        };
        Plotly.newPlot('protocol-chart', [this.protocolChartData], {
            title: 'Protocol Distribution',
            margin: { t: 40 }
        });
    }

    updateCharts(stats) {
        // Update traffic chart
        if (stats && stats.traffic_history) {
            this.trafficChartData.x = stats.traffic_history.map(item => item[0]);
            this.trafficChartData.y = stats.traffic_history.map(item => item[1]);
            Plotly.update('traffic-chart', {
                x: [this.trafficChartData.x],
                y: [this.trafficChartData.y]
            });
        } else if (stats && stats.capture_stats) {
            // fallback for legacy or missing traffic_history
            const now = new Date();
            if (!this.trafficChartData.x) this.trafficChartData.x = [];
            if (!this.trafficChartData.y) this.trafficChartData.y = [];
            this.trafficChartData.x.push(now.toLocaleTimeString());
            this.trafficChartData.y.push(stats.capture_stats.packet_rate || 0);
            if (this.trafficChartData.x.length > 30) {
                this.trafficChartData.x.shift();
                this.trafficChartData.y.shift();
            }
            Plotly.update('traffic-chart', {
                x: [this.trafficChartData.x],
                y: [this.trafficChartData.y]
            });
        }
        // Update protocol chart
        if (stats && stats.capture_stats) {
            const tcp = stats.capture_stats.tcp_packets || 0;
            const udp = stats.capture_stats.udp_packets || 0;
            const icmp = stats.capture_stats.icmp_packets || 0;
            const other = stats.capture_stats.other_packets || 0;
            Plotly.update('protocol-chart', {
                values: [[tcp, udp, icmp, other]]
            });
        }
    }

    async updateLogs() {
        try {
            const response = await fetch('/api/logs');
            const data = await response.json();
            
            const container = document.getElementById('logs-container');
            
            if (data.logs.length === 0) {
                container.innerHTML = '<p class="text-muted">No logs available</p>';
                return;
            }
            
            const logsHtml = data.logs.map(log => this.createLogHtml(log)).join('');
            container.innerHTML = logsHtml;
            container.scrollTop = container.scrollHeight;
        } catch (error) {
            console.error('Error updating logs:', error);
        }
    }

    createLogHtml(log) {
        const logClass = this.getLogClass(log);
        return `<div class="log-entry ${logClass}">${log}</div>`;
    }

    getLogClass(log) {
        if (log.includes('ERROR')) return 'log-error';
        if (log.includes('WARNING')) return 'log-warning';
        if (log.includes('INFO')) return 'log-info';
        return '';
    }

    onTabChange(event) {
        const targetId = event.target.getAttribute('data-bs-target');
        
        if (targetId === '#logs') {
            this.updateLogs();
        }
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show position-fixed`;
        notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
        notification.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 5000);
    }

    clearMetricsAndCharts() {
        this.updateMetrics(null);
        this.clearCharts();
    }

    clearCharts() {
        // Clear traffic chart
        if (this.trafficChartData) {
            this.trafficChartData.x = [];
            this.trafficChartData.y = [];
            Plotly.update('traffic-chart', { x: [[]], y: [[]] });
        }
        // Clear protocol chart
        if (this.protocolChartData) {
            this.protocolChartData.values = [0, 0, 0, 0];
            Plotly.update('protocol-chart', { values: [[0, 0, 0, 0]] });
        }
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.nidsDashboard = new NIDSDashboard();
}); 