
https://github.com/user-attachments/assets/625acbd5-bfe7-43f6-b88e-db69d9c421b5
# Solana Malicious Validator Detector

A comprehensive tool for monitoring and detecting potentially malicious validators on the Solana network. This application helps identify validators engaging in harmful activities such as double-signing, transaction censorship, network attacks, and suspicious downtime patterns.



Uploading Solana Malicious Validator Detector.mp4…



## Features

### Security Monitoring
- **Double-signing Detection**: Identifies validators signing multiple blocks at the same height
- **Transaction Censorship Analysis**: Detects validators selectively excluding transactions
- **Network Attack Monitoring**: Identifies validators attempting to disrupt network operations
- **Downtime Pattern Analysis**: Detects validators with suspicious availability patterns

### Performance Scoring
The tool evaluates validators based on multiple performance metrics:
- Root block distance
- Vote distance
- Skipped slot percentage
- Vote latency
- Published information
- Software version
- Stake concentration
- Data center concentration
- Authorized withdrawer risk
- Consensus modifications

### Risk Assessment
- Comprehensive risk scoring system (0-100)
- Detailed breakdown of risk factors
- Performance scoring (0-13)
- Actionable recommendations based on risk level

## Installation

### Prerequisites
- Python 3.8+
- Flask
- Internet connection to access Solana network data

### Setup
1. Clone the repository:
```bash
git clone https://github.com/harpal88/malicious-validator-detector.git
cd malicious-validator-detector
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Access the web interface at `http://localhost:5000`

## Usage

### Checking Individual Validators
1. Enter a validator's public key in the search box on the homepage
2. Click "Check Validator" to analyze the validator
3. View the risk assessment, performance score, and detailed breakdown
4. Access the full report for comprehensive analysis

### Monitoring Top Validators
1. Navigate to the Dashboard page
2. View the list of top validators on the network
3. Use the "Quick Check" feature for rapid assessment
4. Access detailed reports for validators of interest

### Understanding Risk Scores
- **0-30**: Low risk - Validator appears to be operating normally
- **31-70**: Medium risk - Some concerning patterns, monitor closely
- **71-100**: High risk - Significant signs of malicious behavior, immediate action recommended

### Performance Score Interpretation
- **0-5**: Poor performance - Validator may be experiencing technical issues
- **6-9**: Average performance - Room for improvement
- **10-13**: Excellent performance - Validator is operating optimally

## Technical Details

### Architecture
- **Frontend**: HTML, CSS, JavaScript, Bootstrap 5
- **Backend**: Python, Flask
- **Data Processing**: Custom validator analysis algorithms

### Data Sources
- Solana RPC API
- Validator gossip network
- Historical performance data
- Network statistics

### Security Considerations
- This tool is for monitoring purposes only
- Always verify findings with additional sources
- False positives may occur in certain network conditions

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Solana Foundation for network documentation
- Open-source community for various libraries and tools
- All contributors who have helped improve this project
