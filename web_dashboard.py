from flask import Flask, render_template, jsonify, request, redirect, url_for, send_from_directory
from flask_cors import CORS
import json
import time
from datetime import datetime, timedelta
import threading
from typing import Dict, List, Any

from anomaly_detector import NIDSAnomalyDetector
from utils import logger, config

app = Flask(__name__)
CORS(app)

# Global NIDS instance
nids_instance = None
nids_thread = None

def create_directories():
    """Create necessary directories"""
    import os
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('models', exist_ok=True)

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/status')
def get_status():
    """Get NIDS system status"""
    global nids_instance
    
    if nids_instance is None:
        return jsonify({
            'status': 'stopped',
            'message': 'NIDS system not initialized'
        })
    
    try:
        stats = nids_instance.get_stats()
        alerts = nids_instance.get_recent_alerts(10)
        alert_stats = nids_instance.get_alert_stats()
        
        return jsonify({
            'status': 'running' if nids_instance.is_running else 'stopped',
            'stats': stats,
            'recent_alerts': alerts,
            'alert_stats': alert_stats,
            'model_type': nids_instance.model_type,
            'interface': nids_instance.interface
        })
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.route('/api/start', methods=['POST'])
def start_nids():
    """Start the NIDS system"""
    global nids_instance, nids_thread
    
    try:
        if nids_instance is None:
            # Initialize NIDS
            model_type = request.json.get('model_type', 'ensemble')
            interface = request.json.get('interface', config.get('network_interface', 'Ethernet'))
            
            nids_instance = NIDSAnomalyDetector(model_type=model_type, interface=interface)
            
            # Try to load existing model
            try:
                nids_instance.load_model()
            except:
                logger.warning("No trained model found. Please train a model first.")
                return jsonify({
                    'success': False,
                    'message': 'No trained model found. Please train a model first.'
                })
        
        if not nids_instance.is_running:
            nids_instance.start()
            
            return jsonify({
                'success': True,
                'message': 'NIDS system started successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'NIDS system is already running'
            })
            
    except Exception as e:
        logger.error(f"Error starting NIDS: {e}")
        return jsonify({
            'success': False,
            'message': f'Error starting NIDS: {str(e)}'
        })

@app.route('/api/stop', methods=['POST'])
def stop_nids():
    """Stop the NIDS system"""
    global nids_instance
    
    try:
        if nids_instance and nids_instance.is_running:
            nids_instance.stop()
            import os
            from datetime import datetime
            from fpdf import FPDF
            import matplotlib.pyplot as plt
            import tempfile
            import numpy as np
            os.makedirs('reports', exist_ok=True)
            stats = nids_instance.get_stats() if hasattr(nids_instance, 'get_stats') else {}
            alerts = nids_instance.get_recent_alerts(100) if hasattr(nids_instance, 'get_recent_alerts') else []
            # For infographics: get traffic history and anomaly history if available
            traffic_history = stats.get('traffic_history', [])  # list of (timestamp, packets/sec)
            anomaly_history = stats.get('anomaly_history', [])  # list of (timestamp, anomaly_count)
            proto_stats = stats.get('capture_stats', {})
            report = {
                'start_time': stats.get('start_time'),
                'stop_time': datetime.now().isoformat(),
                'packets_processed': stats.get('total_packets_processed', 0),
                'anomalies_detected': stats.get('anomalies_detected', 0),
                'packet_rate': proto_stats.get('packet_rate', 0),
                'uptime': stats.get('uptime', 0),
                'protocol_stats': proto_stats,
                'alerts': alerts
            }
            # Save JSON report for reference
            report_json_filename = f"reports/nids_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_json_filename, 'w') as f:
                import json
                json.dump(report, f, indent=2)
            # --- Generate infographics ---
            temp_imgs = []
            # Traffic Over Time
            if traffic_history and len(traffic_history) > 1:
                times, rates = zip(*traffic_history)
                plt.figure(figsize=(5,2.5))
                plt.plot(times, rates, marker='o', color='#667eea')
                plt.title('Traffic Over Time')
                plt.xlabel('Time (s)')
                plt.ylabel('Packets/sec')
                plt.tight_layout()
                traffic_img = tempfile.mktemp(suffix='.png')
                plt.savefig(traffic_img)
                plt.close()
                temp_imgs.append(traffic_img)
            else:
                traffic_img = None
            # Protocol Distribution
            proto_labels = ['TCP', 'UDP', 'ICMP', 'Other']
            proto_values = [proto_stats.get('tcp_packets', 0), proto_stats.get('udp_packets', 0), proto_stats.get('icmp_packets', 0), proto_stats.get('other_packets', 0)]
            if sum(proto_values) > 0:
                plt.figure(figsize=(3,3))
                plt.pie(proto_values, labels=proto_labels, autopct='%1.1f%%', colors=['#28a745', '#20c997', '#ffc107', '#6c757d'])
                plt.title('Protocol Distribution')
                plt.tight_layout()
                proto_img = tempfile.mktemp(suffix='.png')
                plt.savefig(proto_img)
                plt.close()
                temp_imgs.append(proto_img)
            else:
                proto_img = None
            # Anomalies Over Time
            if anomaly_history and len(anomaly_history) > 1:
                atimes, acounts = zip(*anomaly_history)
                plt.figure(figsize=(5,2.5))
                plt.plot(atimes, acounts, marker='o', color='#dc3545')
                plt.title('Anomalies Over Time')
                plt.xlabel('Time (s)')
                plt.ylabel('Anomalies Detected')
                plt.tight_layout()
                anomaly_img = tempfile.mktemp(suffix='.png')
                plt.savefig(anomaly_img)
                plt.close()
                temp_imgs.append(anomaly_img)
            else:
                anomaly_img = None
            # --- Generate beautified PDF report ---
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font('Arial', 'B', 18)
            pdf.cell(0, 12, 'NIDS Session Report', ln=1, align='C')
            pdf.set_font('Arial', '', 12)
            pdf.cell(0, 8, 'AI-Based Network Intrusion Detection System', ln=1, align='C')
            pdf.ln(6)
            # Friendly intro
            pdf.set_font('Arial', 'B', 13)
            pdf.set_text_color(34, 139, 34)
            pdf.multi_cell(0, 8, "This report summarizes your network activity and any suspicious events detected. It's designed to be easy to understand, even if you're not a network expert.")
            pdf.set_text_color(0, 0, 0)
            pdf.ln(2)
            # How to Read This Report
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 8, 'How to Read This Report', ln=1)
            pdf.set_font('Arial', '', 11)
            pdf.multi_cell(0, 7, "- Packets: Each piece of data sent over your network.\n- Anomaly: Something unusual or unexpected in the network traffic.\n- Alert: A warning about a specific suspicious activity.")
            pdf.ln(2)
            # Insert infographics
            if traffic_img:
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(0, 8, 'Traffic Over Time', ln=1)
                pdf.image(traffic_img, w=pdf.w-40)
                pdf.ln(4)
            if proto_img:
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(0, 8, 'Protocol Distribution', ln=1)
                pdf.image(proto_img, w=pdf.w/2)
                pdf.ln(4)
            if anomaly_img:
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(0, 8, 'Anomalies Over Time', ln=1)
                pdf.image(anomaly_img, w=pdf.w-40)
                pdf.ln(4)
            # Session Summary
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'Session Summary', ln=1)
            pdf.set_font('Arial', '', 12)
            pdf.cell(80, 8, 'Start Time:', 0, 0)
            pdf.cell(0, 8, str(report['start_time']), ln=1)
            pdf.cell(80, 8, 'Stop Time:', 0, 0)
            pdf.cell(0, 8, str(report['stop_time']), ln=1)
            pdf.cell(80, 8, 'Uptime:', 0, 0)
            pdf.cell(0, 8, f"{int(report['uptime'])} seconds", ln=1)
            pdf.cell(80, 8, 'Packets Processed:', 0, 0)
            pdf.cell(0, 8, str(report['packets_processed']), ln=1)
            pdf.cell(80, 8, 'Anomalies Detected:', 0, 0)
            pdf.cell(0, 8, str(report['anomalies_detected']), ln=1)
            # Fix: Use packets_per_second from proto_stats
            packet_rate = proto_stats.get('packets_per_second', 0)
            pdf.cell(80, 8, 'Packet Rate:', 0, 0)
            pdf.cell(0, 8, f"{packet_rate:.2f} packets/sec", ln=1)
            pdf.ln(4)
            # Protocol Statistics
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'Protocol Statistics', ln=1)
            pdf.set_font('Arial', '', 12)
            for proto in ['tcp_packets', 'udp_packets', 'icmp_packets', 'other_packets']:
                label = proto.replace('_', ' ').upper()
                value = proto_stats.get(proto, 0)
                pdf.cell(80, 8, f'{label}:', 0, 0)
                pdf.cell(0, 8, str(value), ln=1)
            pdf.ln(4)
            # Alerts Section (user-friendly)
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, f"Security Alerts ({len(report['alerts'])})", ln=1)
            pdf.set_font('Arial', '', 11)
            if report['alerts']:
                for alert in report['alerts'][:20]:
                    pdf.set_font('Arial', 'B', 11)
                    pdf.cell(0, 8, f"Type: {alert.get('type', '').replace('_', ' ').title()} | Time: {alert.get('datetime', '')}", ln=1)
                    pdf.set_font('Arial', '', 10)
                    # Friendly explanations for each alert type
                    alert_type = alert.get('type', '').lower()
                    explanation = alert.get('explanation')
                    if alert_type == 'ml_anomaly':
                        explanation = "The AI detected network activity that looks very different from normal. This could mean someone is trying something unusual or potentially harmful on your network."
                    elif alert_type == 'port_scan':
                        explanation = "A device tried to quickly check many different ports on another device. Hackers often do this to find weak spots before launching an attack."
                    elif alert_type == 'ddos_indicator':
                        explanation = "A large number of packets were sent to a single device, possibly overwhelming it. This is a common sign of a Distributed Denial of Service (DDoS) attack, which can take down services."
                    elif alert_type == 'unusual_protocol':
                        explanation = "An unusual network protocol was detected. This could indicate suspicious or unauthorized network activity."
                    pdf.multi_cell(0, 7, f"Details: {alert.get('details', '')}")
                    pdf.set_text_color(100, 100, 100)
                    pdf.multi_cell(0, 7, f"Explanation: {explanation}")
                    pdf.set_text_color(0, 0, 0)
                    pdf.ln(1)
                if len(report['alerts']) > 20:
                    pdf.set_font('Arial', 'I', 10)
                    pdf.cell(0, 8, f"...and {len(report['alerts'])-20} more alerts.", ln=1)
            else:
                pdf.cell(0, 8, "No alerts were raised during this session.", ln=1)
            pdf.ln(6)
            # What Should I Do section
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'What Should I Do?', ln=1)
            pdf.set_font('Arial', '', 11)
            pdf.multi_cell(0, 7, "- If you see many alerts: Consider checking your devices for unusual activity or malware.\n- If you see DDoS or Port Scan alerts: Make sure your firewall is active and up-to-date.\n- If unsure: Share this report with your IT support or a cybersecurity professional.")
            pdf.ln(4)
            # Glossary/Legend Section
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'Glossary of Terms', ln=1)
            pdf.set_font('Arial', '', 10)
            glossary = [
                ("Packets Processed", "Total number of network packets analyzed by the NIDS during this session."),
                ("Anomalies Detected", "Number of network events flagged as suspicious or abnormal by the NIDS."),
                ("Packet Rate", "Current rate at which packets are being processed."),
                ("Uptime", "How long the NIDS was running."),
                ("TCP/UDP/ICMP/Other", "Number of packets for each protocol."),
                ("Port Scan", "A port scan was detected. This means a host is rapidly probing multiple ports on a target, which is often a precursor to an attack."),
                ("DDoS Indicator", "Possible Distributed Denial of Service (DDoS) activity detected. This means a large number of packets are being sent to a target, which may overwhelm the system."),
                ("Unusual Protocol", "Unusual network protocol detected. This could indicate suspicious or unauthorized network activity."),
                ("ML Anomaly", "The machine learning model detected traffic that is statistically unusual compared to normal patterns.")
            ]
            for term, desc in glossary:
                pdf.set_font('Arial', 'B', 10)
                pdf.cell(50, 7, f'{term}:', 0, 0)
                pdf.set_font('Arial', '', 10)
                pdf.multi_cell(0, 7, desc)
            pdf_filename = f"reports/nids_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            pdf.output(pdf_filename)
            # Clean up temp images
            for img in temp_imgs:
                try:
                    os.remove(img)
                except Exception:
                    pass
            return jsonify({
                'success': True,
                'message': 'NIDS system stopped successfully',
                'report': pdf_filename
            })
        else:
            return jsonify({
                'success': False,
                'message': 'NIDS system is not running'
            })
            
    except Exception as e:
        logger.error(f"Error stopping NIDS: {e}")
        return jsonify({
            'success': False,
            'message': f'Error stopping NIDS: {str(e)}'
        })

@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts"""
    global nids_instance
    
    try:
        limit = request.args.get('limit', 50, type=int)
        alerts = nids_instance.get_recent_alerts(limit) if nids_instance else []
        
        return jsonify({
            'alerts': alerts,
            'count': len(alerts)
        })
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({
            'alerts': [],
            'count': 0,
            'error': str(e)
        })

@app.route('/api/alerts/stats')
def get_alert_stats():
    """Get alert statistics"""
    global nids_instance
    
    try:
        stats = nids_instance.get_alert_stats() if nids_instance else {}
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting alert stats: {e}")
        return jsonify({})

@app.route('/api/train', methods=['POST'])
def train_model():
    """Train the ML model"""
    global nids_instance
    
    try:
        data = request.json
        training_type = data.get('type', 'synthetic')
        
        if nids_instance is None:
            nids_instance = NIDSAnomalyDetector()
        
        if training_type == 'synthetic':
            # Generate synthetic training data
            from anomaly_detector import NIDSTrainer
            trainer = NIDSTrainer()
            
            n_samples = data.get('n_samples', 1000)
            anomaly_ratio = data.get('anomaly_ratio', 0.1)
            
            # Generate data
            features_list = trainer.generate_synthetic_data(n_samples)
            labels = trainer.create_labels_for_synthetic_data(features_list, anomaly_ratio)
            
            # Train model
            training_stats = nids_instance.train_model(features_list, labels)
            
            return jsonify({
                'success': True,
                'message': 'Model trained successfully with synthetic data',
                'training_stats': training_stats
            })
            
        elif training_type == 'pcap':
            # Train with PCAP file
            pcap_file = data.get('pcap_file')
            if not pcap_file:
                return jsonify({
                    'success': False,
                    'message': 'PCAP file path is required'
                })
            
            from anomaly_detector import NIDSTrainer
            trainer = NIDSTrainer()
            
            max_packets = data.get('max_packets', 10000)
            features_list = trainer.generate_training_data(pcap_file, max_packets)
            
            # For PCAP data, we assume it's mostly normal traffic
            labels = [0] * len(features_list)
            
            # Train model
            training_stats = nids_instance.train_model(features_list, labels)
            
            return jsonify({
                'success': True,
                'message': 'Model trained successfully with PCAP data',
                'training_stats': training_stats
            })
            
        else:
            return jsonify({
                'success': False,
                'message': 'Invalid training type'
            })
            
    except Exception as e:
        logger.error(f"Error training model: {e}")
        return jsonify({
            'success': False,
            'message': f'Error training model: {str(e)}'
        })

@app.route('/api/config')
def get_config():
    """Get current configuration"""
    return jsonify(config.config)

@app.route('/api/config', methods=['POST'])
def update_config():
    """Update configuration"""
    try:
        data = request.json
        for key, value in data.items():
            config.set(key, value)
        
        return jsonify({
            'success': True,
            'message': 'Configuration updated successfully'
        })
    except Exception as e:
        logger.error(f"Error updating config: {e}")
        return jsonify({
            'success': False,
            'message': f'Error updating config: {str(e)}'
        })

@app.route('/api/logs')
def get_logs():
    """Get recent logs"""
    try:
        import os
        log_file = 'logs/nids.log'
        
        if not os.path.exists(log_file):
            return jsonify({'logs': []})
        
        # Read last 100 lines
        with open(log_file, 'r') as f:
            lines = f.readlines()
            recent_logs = lines[-100:] if len(lines) > 100 else lines
        
        return jsonify({
            'logs': recent_logs
        })
    except Exception as e:
        logger.error(f"Error reading logs: {e}")
        return jsonify({'logs': [], 'error': str(e)})

@app.route('/api/clear-alerts', methods=['POST'])
def clear_alerts():
    """Clear all alerts"""
    global nids_instance
    
    try:
        if nids_instance:
            nids_instance.clear_alerts()
        
        return jsonify({
            'success': True,
            'message': 'Alerts cleared successfully'
        })
    except Exception as e:
        logger.error(f"Error clearing alerts: {e}")
        return jsonify({
            'success': False,
            'message': f'Error clearing alerts: {str(e)}'
        })

@app.route('/reports/<path:filename>')
def download_report(filename):
    import os
    return send_from_directory(os.path.abspath('reports'), filename, as_attachment=True)

def create_app():
    """Create and configure the Flask application"""
    create_directories()
    return app

if __name__ == '__main__':
    create_directories()
    
    # Load configuration from environment
    config.load_from_env()
    
    port = config.get('web_port', 5000)
    debug = config.get('log_level', 'INFO') == 'DEBUG'
    
    logger.info(f"Starting web dashboard on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug) 