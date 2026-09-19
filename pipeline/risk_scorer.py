"""
Attack Surface Risk Engine.
Evaluates normalized exposure artifacts and calculates actionable risk scores.
"""
from typing import Dict, Any, List


class AttackSurfaceRiskEngine:
    @staticmethod
    def evaluate_asset(normalized_asset: Dict[str, Any]) -> Dict[str, Any]:
        score = 0.0
        findings: List[str] = []

        # High-risk management ports exposed to public internet
        for port in normalized_asset.get("exposed_admin_services", []):
            score += 25.0
            findings.append(f"CRITICAL_EXPOSURE: Public administration port {port} open")

        # TLS posture
        tls_days = normalized_asset.get("tls_days_remaining", 365)
        if tls_days <= 7:
            score += 30.0
            findings.append("HIGH_SEVERITY: TLS certificate expires in <= 7 days")
        elif tls_days <= 30:
            score += 10.0
            findings.append("MEDIUM_SEVERITY: TLS certificate renewal window open (< 30 days)")

        # Lack of DNSSEC
        if not normalized_asset.get("dnssec_active", False):
            score += 10.0
            findings.append("LOW_SEVERITY: DNSSEC not configured on authoritative zone")

        final_score = min(100.0, score)

        if final_score >= 70.0:
            posture = "CRITICAL"
        elif final_score >= 40.0:
            posture = "ELEVATED"
        elif final_score > 0.0:
            posture = "GUARDED"
        else:
            posture = "HARDENED"

        return {
            "asset_id": normalized_asset["asset_id"],
            "risk_score": final_score,
            "posture": posture,
            "findings_count": len(findings),
            "findings": findings
        }