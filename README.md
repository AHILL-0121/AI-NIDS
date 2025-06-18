# AI-Based Network Intrusion Detection System (NIDS)

A real-time network intrusion detection system that uses machine learning to detect anomalies in network traffic.

## 🎯 Features

- **Real-time Packet Capture**: Live network traffic monitoring using Scapy
- **ML-based Anomaly Detection**: Unsupervised learning models (Isolation Forest, Autoencoder)
- **Feature Extraction**: Protocol-based features from network packets
- **Real-time Alerting**: Terminal and web-based alerts for suspicious activity
- **Web Dashboard**: Interactive UI for monitoring and analysis
- **Model Training**: Support for CIC-IDS2017 and NSL-KDD datasets

## 🛠 Tech Stack

- **Packet Capture**: Python + Scapy
- **Machine Learning**: scikit-learn, TensorFlow
- **Backend**: Flask
- **Frontend**: HTML + JavaScript + Plotly
- **Data Processing**: Pandas, NumPy

## 📋 Prerequisites

- Python 3.8+
- Administrator/root privileges (for packet capture)
- Network interface access

## 🚀 Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd NIDS
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

## 🏃‍♂️ Quick Start

### 1. Train the Model (First Time)
```bash
python train_model.py
```

### 2. Start the NIDS System
```bash
python main.py
```

### 3. Access Web Dashboard
Open your browser and navigate to: `http://localhost:5000`

## 📁 Project Structure

```
NIDS/
├── main.py                 # Main application entry point
├── packet_capture.py       # Packet capture and processing
├── feature_extraction.py   # Feature extraction from packets
├── ml_models.py           # ML model implementations
├── anomaly_detector.py    # Anomaly detection logic
├── web_dashboard.py       # Flask web application
├── train_model.py         # Model training script
├── utils.py              # Utility functions
├── data/                 # Dataset storage
├── models/               # Trained model storage
├── static/               # Web assets
├── templates/            # HTML templates
└── logs/                 # System logs
```

## 🔧 Configuration

Edit the `.env` file to configure:
- Network interface for packet capture
- Model parameters
- Alert thresholds
- Web server settings

## 📊 Model Performance

The system achieves >80% accuracy on test datasets:
- CIC-IDS2017: ~85% accuracy
- NSL-KDD: ~82% accuracy

## 🚨 Alert Types

- **Port Scanning**: Multiple connection attempts to different ports
- **DDoS Attacks**: High packet frequency from single source
- **Protocol Anomalies**: Unusual protocol usage patterns
- **Payload Anomalies**: Suspicious packet payload characteristics

## 📈 Monitoring

The web dashboard provides:
- Real-time traffic visualization
- Alert history and details
- Model performance metrics
- Network statistics

## 🔒 Security Notes

- Run with administrator privileges for packet capture
- Monitor system resources during operation
- Regularly update the ML model with new data
- Review and validate alerts before taking action

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details. 