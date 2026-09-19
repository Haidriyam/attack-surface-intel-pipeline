"""
Executive & SIEM Security Telemetry Output Generator.
Generates structured security intelligence data in JSON format for SIEM/SOAR.
"""
from typing import List, Dict, Any
from datetime import datetime, timezone


class SecurityReportGenerator:
    @staticmethod
    def generate_siem_telemetry(evaluations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Output structured high-level security intelligence telemetry suitable for ingestion
        into enterprise SIEM (Elastic/Splunk) or executive monitoring dashboards.
        """
        total_assets = len(evaluations)
        critical_count = sum(1 for e in evaluations if e["posture"] == "CRITICAL")
        elevated_count = sum(1 for e in evaluations if e["posture"] == "ELEVATED")
        hardened_count = sum(1 for e in evaluations if e["posture"] == "HARDENED")

        overall_mean_score = (
            round(sum(e["risk_score"] for e in evaluations) / total_assets, 2)
            if total_assets > 0
            else 0.0
        )

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "pipeline_version": "1.0.0",
            "executive_summary": {
                "monitored_assets": total_assets,
                "overall_risk_index": overall_mean_score,
                "critical_exposures": critical_count,
                "elevated_exposures": elevated_count,
                "hardened_assets": hardened_count
            },
            "telemetry_events": evaluations
        }