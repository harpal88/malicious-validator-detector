#!/usr/bin/env python3
"""
Test script for the detector module
"""

try:
    print("Attempting to import ValidatorDetector...")
    from detector import ValidatorDetector
    print("Import successful!")
    
    print("Creating ValidatorDetector instance...")
    detector = ValidatorDetector()
    print("Instance created successfully!")
    
    print("Network stats:", detector.network_stats)
except Exception as e:
    print(f"Error: {str(e)}")
    import traceback
    traceback.print_exc()
