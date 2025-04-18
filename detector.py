#!/usr/bin/env python3
"""
Solana Malicious Validator Detector

Objective:
Identify and address malicious validators on the Solana network who engage in:
- Double-signing
- Transaction censorship
- Network attacks
- Unusual downtime
- Other harmful activities
"""

import requests
import json
from typing import Dict, Any, List
from datetime import datetime
from termcolor import colored
import sys

# Configuration
RPC_URL = "https://api.mainnet-beta.solana.com"
VALIDATORS_API_URL = "https://www.validators.app/api/v1/validators/mainnet"
API_TOKEN = "FCG4W3TEGMnPMD75pKDRSfko"

class ValidatorDetector:
    def __init__(self):
        self.session = requests.Session()
        self.network_stats = self._get_network_stats()

    def _get_network_stats(self) -> Dict[str, Any]:
        """Get network averages for comparison"""
        try:
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getVoteAccounts",
                "params": []
            }
            response = self.session.post(RPC_URL, json=payload)
            data = response.json()

            credits = []
            for account in data.get("result", {}).get("current", []):
                if account.get("epochCredits"):
                    credits.append(account["epochCredits"][-1][0])

            # Get current slot for other calculations
            slot_payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getSlot",
                "params": []
            }
            slot_response = self.session.post(RPC_URL, json=slot_payload)
            slot_data = slot_response.json()
            current_slot = slot_data.get("result", 0)

            return {
                "avg_epoch_credits": sum(credits)/len(credits) if credits else 0,
                "total_validators": len(data.get("result", {}).get("current", [])),
                "current_slot": current_slot,
                "current_epoch": current_slot // 432000 if current_slot else 0,  # Solana epoch is ~432,000 slots
                "avg_skipped_slots": 5.0,  # Default average skipped slots percentage
                "total_stake": 1000000000  # Default total stake for calculations
            }
        except Exception as e:
            print(f"Error getting network stats: {str(e)}")
            return {
                "avg_epoch_credits": 50000,
                "total_validators": 1000,
                "current_slot": 0,
                "current_epoch": 0,
                "avg_skipped_slots": 5.0,
                "total_stake": 1000000000
            }  # Fallback values

    def get_rpc_data(self, method: str, params: list) -> Dict[str, Any]:
        """Generic Solana RPC call"""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        }
        try:
            response = self.session.post(RPC_URL, json=payload, timeout=10)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def get_top_validators(self, limit: int) -> List[Dict[str, Any]]:
        """Get top validators from Validators.app API"""
        try:
            headers = {"Token": API_TOKEN}
            params = {
                "order": "score",
                "limit": limit,
                "active_only": "true"
            }
            response = requests.get(
                f"{VALIDATORS_API_URL}.json",
                headers=headers,
                params=params,
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"Error fetching top validators: {str(e)}")
        return []

    def _check_censorship(self, validator_pubkey: str) -> Dict[str, Any]:
        """Check for transaction censorship patterns"""
        # Fetch recent performance data
        try:
            headers = {"Token": API_TOKEN}
            response = requests.get(
                f"{VALIDATORS_API_URL}/{validator_pubkey}.json",
                headers=headers,
                timeout=5
            )
            if response.status_code == 200:
                perf_data = response.json()
                skipped_pct = perf_data.get("skipped_slot_percent", 0)
                suspicious = False
                reasons = []
                # Flag high skipped slots (possible censorship or downtime)
                if skipped_pct and float(skipped_pct) > 10:
                    suspicious = True
                    reasons.append(f"High skipped slots: {skipped_pct}% (possible censorship or downtime)")
                # Flag if MEV or known censorship fields exist (example placeholder)
                if perf_data.get("mev_commission"):
                    suspicious = True
                    reasons.append(f"Possible MEV extraction: MEV commission {perf_data['mev_commission']}")
                return {
                    "suspicious": suspicious,
                    "reasons": reasons,
                    "skipped_slot_percent": skipped_pct,
                    "mev_commission": perf_data.get("mev_commission")
                }
        except Exception as e:
            return {"error": str(e)}
        return {"suspicious": False, "reasons": ["No evidence of censorship found"]}

    def check_validator(self, validator_pubkey: str) -> Dict[str, Any]:
        """Comprehensive validator analysis"""
        result = {
            "validator": validator_pubkey,
            "checks": {
                "voting": {},
                "double_sign": {},
                "censorship": {
                    "basic_check": {},
                    "skipped_slots": {},
                    "tx_patterns": {},
                    "mev": {}
                },
                "performance": {},
                "network_attacks": {
                    "voting_anomalies": {},
                    "stake_concentration": {}
                }
            },
            "slashing_logs": {},
            "warnings": [],
            "risk_factors": [],
            "risk_score": 0,
            "performance_score": {
                "total": 0,
                "root_block_distance": 0,
                "vote_distance": 0,
                "skipped_slot": 0,
                "vote_latency": 0,
                "skipped_after": 0,
                "published_info": 0,
                "software_version": 0,
                "bonus_point": 0,
                "stake_concentration": 0,
                "data_center_concentration": 0,
                "authorized_withdrawer": 0,
                "consensus_mods": 0
            },
            "details": []
        }

        # 1. Voting Activity Check
        vote_accounts = self.get_rpc_data("getVoteAccounts", [{"votePubkey": validator_pubkey}])
        if "result" in vote_accounts:
            for account in vote_accounts["result"].get("current", []) + vote_accounts["result"].get("delinquent", []):
                if account["votePubkey"] == validator_pubkey:
                    result["checks"]["voting"] = {
                        "commission": account["commission"],
                        "epoch_credits": account["epochCredits"][-1][0] if account.get("epochCredits") else 0,
                        "last_vote": account["lastVote"],
                        "root_slot": account["rootSlot"],
                        "delinquent": account in vote_accounts["result"].get("delinquent", [])
                    }
                    break

        # 2. Double-Signing Check
        result["checks"]["double_sign"] = self.check_double_signing(validator_pubkey)

        # 3. Performance Check
        try:
            headers = {"Token": API_TOKEN}
            response = requests.get(
                f"{VALIDATORS_API_URL}/{validator_pubkey}.json",
                headers=headers,
                timeout=5
            )
            if response.status_code == 200:
                perf_data = response.json()
                result["checks"]["performance"] = {
                    "skipped_slots": perf_data.get("skipped_slot_percent", 0),
                    "uptime": 100 - float(perf_data.get("skipped_slot_percent", 0)),
                    "software": perf_data.get("software_version", "unknown")
                }
        except Exception as e:
            result["checks"]["performance"] = {
                "error": str(e),
                "skipped_slots": 0,
                "uptime": 0,
                "software": "unknown"
            }

        # 4. Censorship Check
        result["checks"]["censorship"]["basic_check"] = self._check_censorship(validator_pubkey)
        result["checks"]["censorship"]["skipped_slots"] = self.check_skipped_slots(validator_pubkey)
        result["checks"]["censorship"]["tx_patterns"] = self.check_tx_censorship(validator_pubkey)
        result["checks"]["censorship"]["mev"] = self.detect_mev(validator_pubkey)

        # 5. Additional Checks
        result["slashing_logs"] = self.check_slashing_logs(validator_pubkey)
        result["checks"]["network_attacks"]["voting_anomalies"] = self.check_voting_anomalies(validator_pubkey)
        result["checks"]["network_attacks"]["stake_concentration"] = self.check_stake_concentration(validator_pubkey)

        # 6. Risk Assessment
        self._assess_risks(result)

        return result

    def _assess_risks(self, result: Dict[str, Any]):
        """Calculate risk factors and performance scores"""
        # ===== RISK ASSESSMENT =====
        # Voting Activity Risks
        if not result["checks"]["voting"]:
            result["risk_factors"].append(("No voting activity detected", 40))
            result["details"].append("Validator appears completely inactive")
        else:
            credits = result["checks"]["voting"].get("epoch_credits", 0)
            if credits < (self.network_stats["avg_epoch_credits"] * 0.1):  # <10% of network average
                result["risk_factors"].append(
                    (f"Extremely low voting participation ({credits} vs network avg {self.network_stats['avg_epoch_credits']})", 30)
                )

            if result["checks"]["voting"].get("delinquent"):
                result["risk_factors"].append(("Validator is delinquent", 50))

        # Double-Signing Risks
        suspicious_slots = result["checks"]["double_sign"].get("suspicious_slots", [])
        if len(suspicious_slots) > 0:
            severity = min(20 + (len(suspicious_slots) * 10), 50)
            result["risk_factors"].append(
                (f"Possible double-signing in {len(suspicious_slots)} slots", severity)
            )
            result["details"].append(f"Most suspicious slot: {max(suspicious_slots) if suspicious_slots else 'N/A'}")

        # Performance Risks
        try:
            skipped_slots = float(result["checks"]["performance"].get("skipped_slots", 0))
            if skipped_slots > 10:
                result["risk_factors"].append(
                    (f"High skipped slots ({skipped_slots:.1f}%)", 30)
                )
        except (ValueError, TypeError):
            # Handle case where skipped_slots is not a valid number
            pass

        # Censorship Risks
        if result["checks"]["censorship"]["basic_check"].get("suspicious"):
            severity = 50
            result["risk_factors"].append(
                (f"Possible censorship detected: {', '.join(result['checks']['censorship']['basic_check']['reasons'])}", severity)
            )

        # Calculate total risk score
        result["risk_score"] = min(
            sum(score for (_, score) in result["risk_factors"]),
            100  # Cap at 100
        )

        # ===== PERFORMANCE SCORING =====
        # Initialize performance score
        perf_score = result["performance_score"]

        # 1. Root Block Distance
        if result["checks"]["voting"] and "root_slot" in result["checks"]["voting"]:
            root_slot = result["checks"]["voting"]["root_slot"]
            current_slot = self.network_stats["current_slot"]
            block_distance = current_slot - root_slot if current_slot > root_slot else 0

            # Compare to network median/average (placeholder logic)
            network_median_distance = 10  # Placeholder value
            network_avg_distance = 20     # Placeholder value

            if block_distance <= network_median_distance:
                perf_score["root_block_distance"] = 2
            elif block_distance <= network_avg_distance:
                perf_score["root_block_distance"] = 1
            else:
                perf_score["root_block_distance"] = 0

        # 2. Vote Distance (similar to root block distance)
        if result["checks"]["voting"] and "last_vote" in result["checks"]["voting"]:
            last_vote = result["checks"]["voting"]["last_vote"]
            current_slot = self.network_stats["current_slot"]
            vote_distance = current_slot - last_vote if current_slot > last_vote else 0

            # Compare to network median/average (placeholder logic)
            network_median_vote_distance = 5  # Placeholder value
            network_avg_vote_distance = 10     # Placeholder value

            if vote_distance <= network_median_vote_distance:
                perf_score["vote_distance"] = 2
            elif vote_distance <= network_avg_vote_distance:
                perf_score["vote_distance"] = 1
            else:
                perf_score["vote_distance"] = 0

        # 3. Skipped Slot %
        try:
            skipped_slots = float(result["checks"]["performance"].get("skipped_slots", 0))
            network_median_skipped = 3.0  # Placeholder value
            network_avg_skipped = 5.0     # Placeholder value

            if skipped_slots <= network_median_skipped:
                perf_score["skipped_slot"] = 2
            elif skipped_slots <= network_avg_skipped:
                perf_score["skipped_slot"] = 1
            else:
                perf_score["skipped_slot"] = 0
        except (ValueError, TypeError):
            perf_score["skipped_slot"] = 0

        # 4. Vote Latency (placeholder implementation)
        # In a real implementation, you would get this data from an API
        vote_latency = 2.5  # Placeholder value in slots

        if vote_latency < 2.0:
            perf_score["vote_latency"] = 2
        elif vote_latency < 3.0:
            perf_score["vote_latency"] = 1
        else:
            perf_score["vote_latency"] = 0

        # 5. Software Version
        software_version = result["checks"]["performance"].get("software", "unknown")
        if software_version != "unknown":
            try:
                # Parse version string (assuming format like "1.14.15")
                version_parts = software_version.split('.')
                if len(version_parts) >= 3:
                    # Compare with latest version (placeholder values)
                    latest_major, latest_minor, latest_patch = 1, 14, 18
                    major, minor, patch = map(int, version_parts[:3])

                    if major == latest_major and minor == latest_minor and patch == latest_patch:
                        perf_score["software_version"] = 2
                    elif major == latest_major and minor == latest_minor:
                        perf_score["software_version"] = 1
                    else:
                        perf_score["software_version"] = 0
            except (ValueError, IndexError):
                perf_score["software_version"] = 0

        # 6. Published Information (placeholder implementation)
        # In a real implementation, you would check validator info on-chain
        published_info_count = 0  # Placeholder value

        if published_info_count == 4:  # All info published
            perf_score["published_info"] = 2
        elif published_info_count >= 2:  # 2-3 pieces of info
            perf_score["published_info"] = 1
        else:  # 0-1 pieces of info
            perf_score["published_info"] = 0

        # 7. Stake Concentration
        stake_concentration = result["checks"]["network_attacks"]["stake_concentration"]
        if stake_concentration.get("risk") == "CRITICAL":
            perf_score["stake_concentration"] = -2  # Deduction for high stake concentration

        # 8. Data Center Concentration (placeholder implementation)
        # In a real implementation, you would get this from an API
        data_center_concentration_high = False  # Placeholder value
        if data_center_concentration_high:
            perf_score["data_center_concentration"] = -2

        # 9. Authorized Withdrawer (placeholder implementation)
        # In a real implementation, you would check if identity matches withdrawer
        identity_is_withdrawer = False  # Placeholder value
        if identity_is_withdrawer:
            perf_score["authorized_withdrawer"] = -2

        # 10. Consensus Mods (placeholder implementation)
        # In a real implementation, you would check for modified software
        uses_consensus_mods = False  # Placeholder value
        if uses_consensus_mods:
            perf_score["consensus_mods"] = -2
            perf_score["bonus_point"] = 0  # No bonus point for validators with mods

        # Calculate total performance score (max 13 points)
        perf_score["total"] = (
            perf_score["root_block_distance"] +
            perf_score["vote_distance"] +
            perf_score["skipped_slot"] +
            perf_score["vote_latency"] +
            perf_score["published_info"] +
            perf_score["software_version"] +
            perf_score["bonus_point"] +
            perf_score["stake_concentration"] +
            perf_score["data_center_concentration"] +
            perf_score["authorized_withdrawer"] +
            perf_score["consensus_mods"]
        )

        # Ensure score is within valid range (0-13)
        perf_score["total"] = max(0, min(perf_score["total"], 13))
    def check_double_signing(self, validator_pubkey: str) -> Dict[str, Any]:
        """Check for duplicate votes in the same slot (potential double-signing)"""
        result = {
            "suspicious_slots": [],
            "total_duplicates": 0,
            "last_checked_slot": None,
            "total_txs": 0  # Add this field to match what's used in generate_report
        }

        try:
            # Fetch recent votes (limit 1000 for thoroughness)
            votes = self.get_rpc_data("getConfirmedSignaturesForAddress2", [
                validator_pubkey,
                {"limit": 1000}
            ])

            if "result" in votes and isinstance(votes["result"], list):
                result["total_txs"] = len(votes["result"])  # Set the total transactions count

                slot_counts = {}
                for tx in votes["result"]:
                    if isinstance(tx, dict) and "slot" in tx:
                        slot = tx["slot"]
                        slot_counts[slot] = slot_counts.get(slot, 0) + 1

                # Flag slots with >1 vote
                result["suspicious_slots"] = [slot for slot, count in slot_counts.items() if count > 1]
                result["total_duplicates"] = len(result["suspicious_slots"])
                result["last_checked_slot"] = max(slot_counts.keys()) if slot_counts else None
        except Exception as e:
            print(f"Error checking double signing: {str(e)}")
            # Continue with default values in result

        return result

    def check_slashing_logs(self, validator_pubkey: str) -> bool:
        """Check third-party explorers for slashing history (Solana Beach/Explorers)"""
        try:
            response = requests.get(
                f"https://api.solanabeach.io/v1/validator/{validator_pubkey}/slashing",
                timeout=5
            )
            if response.status_code == 200:
                return response.json().get("slashed", False)
        except:
            pass
        return False

    def check_skipped_slots(self, validator_pubkey: str) -> Dict[str, float]:
        """Compare validator's skipped slots % vs network average"""
        validator_data = self._get_validator_performance(validator_pubkey)
        network_avg = self.network_stats.get("avg_skipped_slots", 5.0)  # Default 5%

        return {
            "validator_skipped": validator_data.get("skipped_slots", 0),
            "network_avg": network_avg,
            "deviation_pct": abs(validator_data.get("skipped_slots", 0) - network_avg)
        }
    def check_tx_censorship(self, validator_pubkey: str) -> Dict[str, Any]:
        """Analyze if validator ignores certain transactions"""
        try:
            # Get recent proposed blocks
            blocks = self.get_rpc_data("getConfirmedBlocks", [
                self.network_stats["current_slot"] - 100,  # Last 100 slots
                self.network_stats["current_slot"]
            ])

            suspicious_txs = []
            if "result" in blocks and isinstance(blocks["result"], list):
                for slot in blocks["result"][:10]:  # Limit to 10 blocks to avoid too many API calls
                    try:
                        block = self.get_rpc_data("getConfirmedBlock", [slot])
                        if "result" in block and isinstance(block["result"], dict):
                            if validator_pubkey in block["result"].get("leader", ""):
                                # Check if block excludes high-fee txs (potential censorship)
                                txs_in_mempool = self._get_mempool_txs(slot)
                                if txs_in_mempool and "transactions" in block["result"]:
                                    if len(block["result"]["transactions"]) < len(txs_in_mempool) * 0.5:
                                        suspicious_txs.append({
                                            "slot": slot,
                                            "included": len(block["result"]["transactions"]),
                                            "mempool": len(txs_in_mempool)
                                        })
                    except Exception as e:
                        print(f"Error checking block {slot}: {str(e)}")
                        continue

            return {"suspicious_blocks": suspicious_txs}
        except Exception as e:
            print(f"Error in check_tx_censorship: {str(e)}")
            return {"suspicious_blocks": [], "error": str(e)}

    def _get_mempool_txs(self, slot: int) -> List[Dict[str, Any]]:
        """Get transactions in mempool around a specific slot"""
        try:
            # This is a placeholder implementation since Solana doesn't have a direct mempool API
            # In a real implementation, you would use a more sophisticated approach to get mempool txs for a specific slot
            # For now, we're just estimating based on recent network activity
            print(f"Checking mempool for slot {slot}")

            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getRecentPerformanceSamples",
                "params": [1]
            }
            response = self.session.post(RPC_URL, json=payload, timeout=5)
            data = response.json()

            # Estimate mempool size based on recent transactions per second
            if "result" in data and data["result"]:
                tps = data["result"][0].get("numTransactions", 0) / data["result"][0].get("samplePeriodSecs", 1)
                # Return a placeholder list with estimated size
                return [{"placeholder": True, "slot": slot} for _ in range(int(tps * 2))]
            return []
        except Exception as e:
            print(f"Error getting mempool transactions: {str(e)}")
            return []

    def _is_sandwich_attack(self, txs: List) -> bool:
        """Actual MEV detection logic"""
        if len(txs) < 3:
            return False
        # Check for: tx1 (victim), tx2 (attacker), tx3 (victim) with matching token pairs
        return (txs[0]["input"] == txs[2]["input"] and
                txs[1]["gasPrice"] > txs[0]["gasPrice"] * 1.5)

    def detect_mev(self, validator_pubkey: str) -> List[Dict[str, Any]]:
        """Identify frontrunning/backrunning patterns"""
        mev_indicators = []
        try:
            recent_blocks = self.get_rpc_data("getConfirmedBlocks", [
                self.network_stats["current_slot"] - 32,  # Last epoch
                self.network_stats["current_slot"]
            ])

            if "result" in recent_blocks and isinstance(recent_blocks["result"], list):
                for slot in recent_blocks["result"][:10]:  # Check last 10 blocks
                    try:
                        block = self.get_rpc_data("getConfirmedBlock", [slot])
                        if "result" in block and isinstance(block["result"], dict):
                            if block["result"].get("leader") == validator_pubkey and "transactions" in block["result"]:
                                # Safely extract transactions
                                txs = []
                                for tx_data in block["result"]["transactions"]:
                                    if isinstance(tx_data, dict) and "transaction" in tx_data:
                                        txs.append(tx_data["transaction"])

                                # Detect sandwich attacks
                                if self._is_sandwich_attack(txs):
                                    mev_indicators.append({
                                        "slot": slot,
                                        "type": "sandwich",
                                        "evidence": txs[:3] if len(txs) >= 3 else txs  # Sample of suspicious txs
                                    })
                    except Exception as e:
                        print(f"Error checking MEV for block {slot}: {str(e)}")
                        continue
        except Exception as e:
            print(f"Error in detect_mev: {str(e)}")

        return mev_indicators
    def check_voting_anomalies(self, validator_pubkey: str) -> Dict[str, Any]:
        """Detect sudden changes in voting patterns"""
        votes = self.get_rpc_data("getVoteAccounts", [{"votePubkey": validator_pubkey}])
        # Get current epoch for context (will be used in future implementations)
        current_epoch = self.network_stats["current_epoch"]
        print(f"Checking voting anomalies for epoch {current_epoch}")

        try:
            if ("result" in votes and
                "current" in votes["result"] and
                len(votes["result"]["current"]) > 0 and
                "epochCredits" in votes["result"]["current"][0]):

                history = votes["result"]["current"][0]["epochCredits"]
                last_3_epochs = history[-3:] if len(history) >= 3 else history

                # Calculate voting rate change
                if len(last_3_epochs) >= 2:
                    change = (last_3_epochs[-1][0] - last_3_epochs[-2][0]) / last_3_epochs[-2][0]
                    return {
                        "voting_change_pct": change * 100,
                        "is_anomaly": abs(change) > 0.5  # >50% change
                    }
        except Exception as e:
            print(f"Error checking voting anomalies: {str(e)}")
            # Continue with default return

        return {"voting_change_pct": 0, "is_anomaly": False}


    def _get_validator_performance(self, validator_pubkey: str) -> Dict[str, Any]:
        """Get validator performance data from Validators.app API"""
        try:
            headers = {"Token": API_TOKEN}
            response = requests.get(
                f"{VALIDATORS_API_URL}/{validator_pubkey}.json",
                headers=headers,
                timeout=5
            )
            if response.status_code == 200:
                return response.json()
            else:
                return {"skipped_slots": 0, "error": f"API returned status code {response.status_code}"}
        except Exception as e:
            return {"skipped_slots": 0, "error": str(e)}

    def check_stake_concentration(self, validator_pubkey: str) -> Dict[str, Any]:
        """Identify validators with >33% stake from single source"""
        stake_info = self.get_rpc_data("getStakeActivation", [validator_pubkey])
        if "result" in stake_info:
            activation = stake_info["result"]["state"]
            if activation == "active" and stake_info["result"]["active"] > 0.33 * self.network_stats["total_stake"]:
                return {
                    "stake_percentage": stake_info["result"]["active"] / self.network_stats["total_stake"] * 100,
                    "risk": "CRITICAL"
                }

        return {"stake_percentage": 0, "risk": None}

    def generate_report(self, validator_pubkey: str) -> str:
        """Generate comprehensive security report"""
        analysis = self.check_validator(validator_pubkey)
        report = [
            colored("\n=== SOLANA VALIDATOR SECURITY REPORT ===", 'blue', attrs=['bold']),
            f"Validator: {validator_pubkey}",
            colored(f"\nRISK SCORE: {analysis['risk_score']}/100",
                  'red' if analysis['risk_score'] > 70 else
                  'yellow' if analysis['risk_score'] > 30 else 'green',
                  attrs=['bold']),
            colored(f"PERFORMANCE SCORE: {analysis['performance_score']['total']}/13",
                  'green' if analysis['performance_score']['total'] > 9 else
                  'yellow' if analysis['performance_score']['total'] > 5 else 'red',
                  attrs=['bold']),
            "\n=== POTENTIAL ISSUES ==="
        ]

        # Add risk factors with severity indicators
        for factor, score in analysis["risk_factors"]:
            color = 'red' if score > 30 else 'yellow'
            report.append(colored(f"⚠️ [{score} pts] {factor}", color))

        # Add detailed findings
        report.append("\n=== DETAILED FINDINGS ===")
        if analysis["checks"]["voting"]:
            report.extend([
                "\n[VOTING ACTIVITY]",
                f"• Commission: {analysis['checks']['voting']['commission']}%",
                f"• Epoch Credits: {analysis['checks']['voting']['epoch_credits']} (Network avg: {self.network_stats['avg_epoch_credits']})",
                f"• Last Vote: {analysis['checks']['voting']['last_vote']}",
                f"• Status: {'DELINQUENT' if analysis['checks']['voting'].get('delinquent') else 'Active'}"
            ])

        if analysis["checks"]["double_sign"].get("suspicious_slots"):
            report.extend([
                "\n[DOUBLE-SIGNING CHECK]",
                f"• Suspicious slots: {len(analysis['checks']['double_sign']['suspicious_slots'])}",
                f"• Total recent transactions: {analysis['checks']['double_sign']['total_txs']}"
            ])

        if analysis["checks"]["performance"]:
            report.extend([
                "\n[PERFORMANCE METRICS]",
                f"• Skipped slots: {analysis['checks']['performance']['skipped_slots']}%",
                f"• Software version: {analysis['checks']['performance']['software']}"
            ])

        if analysis["checks"]["censorship"].get("suspicious"):
            report.extend([
                "\n[CENSORSHIP CHECK]",
                f"• Suspicious: {analysis['checks']['censorship']['suspicious']}",
                f"• Reasons: {', '.join(analysis['checks']['censorship']['reasons'])}",
                f"• Skipped slot percent: {analysis['checks']['censorship']['skipped_slot_percent']}%",
                f"• MEV commission: {analysis['checks']['censorship']['mev_commission']}"
            ])

        # Add performance score breakdown
        perf_score = analysis["performance_score"]
        report.append("\n=== PERFORMANCE SCORE BREAKDOWN ===")

        # Helper function to get icon based on score
        def get_score_icon(score):
            if score == 2:
                return colored("✅", 'green')  # Excellent
            elif score == 1:
                return colored("⚠️", 'yellow')  # OK
            elif score == 0:
                return colored("❌", 'red')     # Needs improvement
            elif score < 0:
                return colored("⛔", 'red')     # Negative score
            return colored("?", 'blue')         # Unknown

        report.extend([
            f"\n{get_score_icon(perf_score['root_block_distance'])} Root Block Distance: {perf_score['root_block_distance']} points",
            f"{get_score_icon(perf_score['vote_distance'])} Vote Distance: {perf_score['vote_distance']} points",
            f"{get_score_icon(perf_score['skipped_slot'])} Skipped Slot %: {perf_score['skipped_slot']} points",
            f"{get_score_icon(perf_score['vote_latency'])} Vote Latency: {perf_score['vote_latency']} points",
            f"{get_score_icon(perf_score['published_info'])} Published Information: {perf_score['published_info']} points",
            f"{get_score_icon(perf_score['software_version'])} Software Version: {perf_score['software_version']} points",
            f"{get_score_icon(perf_score['bonus_point'])} Security Bonus: {perf_score['bonus_point']} points"
        ])

        # Add contra-scores (if any)
        contra_scores = []
        if perf_score["stake_concentration"] < 0:
            contra_scores.append(f"{get_score_icon(perf_score['stake_concentration'])} Stake Concentration: {perf_score['stake_concentration']} points")
        if perf_score["data_center_concentration"] < 0:
            contra_scores.append(f"{get_score_icon(perf_score['data_center_concentration'])} Data Center Concentration: {perf_score['data_center_concentration']} points")
        if perf_score["authorized_withdrawer"] < 0:
            contra_scores.append(f"{get_score_icon(perf_score['authorized_withdrawer'])} Authorized Withdrawer Risk: {perf_score['authorized_withdrawer']} points")
        if perf_score["consensus_mods"] < 0:
            contra_scores.append(f"{get_score_icon(perf_score['consensus_mods'])} Consensus Mods: {perf_score['consensus_mods']} points")

        if contra_scores:
            report.append("\n[CONTRA-SCORES]")
            report.extend(contra_scores)

        # Add context and recommendations
        report.extend([
            "\n=== RECOMMENDATIONS ===",
            colored("🚨 Immediate action recommended", 'red') if analysis['risk_score'] > 70 else
            colored("⚠️ Monitor closely", 'yellow') if analysis['risk_score'] > 30 else
            colored("✅ No immediate concerns", 'green'),
            f"\nReport generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        ])

        return "\n".join(report)

def run_cli():
    """Run the command-line interface version of the tool"""
    print(__doc__)  # Show tool documentation
    detector = ValidatorDetector()

    while True:
        print("\n=== MAIN MENU ===")
        print("1. Check single validator")
        print("2. Check top validators")
        print("3. View network statistics")
        print("4. Exit")
        choice = input("Select option (1-4): ").strip()

        if choice == "1":
            validator = input("Enter validator pubkey: ").strip()
            if not validator:
                print("Please enter a validator public key")
                continue
            print(detector.generate_report(validator))
        elif choice == "2":
            try:
                limit = int(input("How many top validators to check? (1-50): "))
                if not 1 <= limit <= 50:
                    print("Please enter a number between 1 and 50")
                    continue

                print(f"\nChecking top {limit} validators...")
                validators = detector.get_top_validators(limit)

                if not validators:
                    print("No validators found or API error occurred")
                    continue

                for i, validator in enumerate(validators[:limit], 1):
                    name = validator.get('name', validator.get('account', 'Unknown'))
                    print(f"\n{i}/{limit} Checking {name}...")
                    print(detector.generate_report(validator['account']))
                    print("-"*50)
            except ValueError:
                print("Please enter a valid number")
        elif choice == "3":
            print("\n=== NETWORK STATISTICS ===")
            print(f"• Average epoch credits: {detector.network_stats['avg_epoch_credits']}")
            print(f"• Total active validators: {detector.network_stats['total_validators']}")
        elif choice == "4":
            break
        else:
            print("Invalid option, please try again")

if __name__ == "__main__":
    run_cli()
