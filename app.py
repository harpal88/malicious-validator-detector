#!/usr/bin/env python3
"""
Solana Malicious Validator Detector - Web UI

A Flask-based web interface for the Solana Validator Detector tool.
"""

from flask import Flask, render_template, request, jsonify
from detector import ValidatorDetector

app = Flask(__name__)
detector = ValidatorDetector()

@app.route('/')
def index():
    """Render the main page"""
    network_stats = detector.network_stats
    return render_template('index.html', network_stats=network_stats)

@app.route('/check_validator', methods=['POST'])
def check_validator():
    """API endpoint to check a single validator"""
    validator_pubkey = request.form.get('validator_pubkey', '')
    if not validator_pubkey:
        return jsonify({'error': 'No validator public key provided'}), 400

    try:
        # Get the full analysis
        analysis = detector.check_validator(validator_pubkey)

        # Format the report for the UI
        report = {
            'validator': validator_pubkey,
            'risk_score': analysis['risk_score'],
            'risk_factors': analysis['risk_factors'],
            'details': analysis['details'],
            'checks': analysis['checks'],
            'performance_score': analysis['performance_score']
        }

        return jsonify(report)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/top_validators', methods=['GET'])
def top_validators():
    """Get a list of top validators"""
    try:
        limit = int(request.args.get('limit', 10))
        if limit < 1 or limit > 50:
            limit = 10

        validators = detector.get_top_validators(limit)
        return jsonify(validators)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/network_stats', methods=['GET'])
def network_stats():
    """Get current network statistics"""
    try:
        stats = detector.network_stats
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/validator_report/<validator_pubkey>')
def validator_report(validator_pubkey):
    """Render a detailed report page for a specific validator"""
    try:
        analysis = detector.check_validator(validator_pubkey)
        return render_template('report.html', analysis=analysis)
    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/dashboard')
def dashboard():
    """Render the dashboard page with multiple validators"""
    try:
        limit = int(request.args.get('limit', 10))
        if limit < 1 or limit > 50:
            limit = 10

        validators = detector.get_top_validators(limit)
        return render_template('dashboard.html', validators=validators)
    except Exception as e:
        return render_template('error.html', error=str(e))

if __name__ == '__main__':
    print("Starting Solana Validator Detector Web UI...")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
