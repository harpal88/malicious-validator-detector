#!/usr/bin/env python3
"""
Test script for the Flask app
"""

from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello, World!"

if __name__ == '__main__':
    print("Starting test Flask app...")
    app.run(debug=True, host='0.0.0.0', port=5001)
