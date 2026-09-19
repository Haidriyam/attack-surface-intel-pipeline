import unittest
from pipeline.collector import ReconTelemetryCollector
from pipeline.risk_scorer import AttackSurfaceRiskEngine
from pipeline.reporter import SecurityReportGenerator


class TestReconIntelligencePipeline(unittest.TestCase):

    def setUp(self):
        self.raw_data = [
            {
                "domain": "api.internal.example.com",
                "ips": ["198.51.100.14"],
                "open_ports": [443, 3389],
                "dnssec": False,
                "tls_days_left": 5
            },
            {
                "domain": "portal.example.com",
                "ips": ["198.51.100.22"],
                "open_ports": [443],
                "dnssec": True,
                "tls_days_left": 180
            }
        ]

    def test_collector_normalizes_and_flags_exposed_ports(self):
        normalized = ReconTelemetryCollector.aggregate_perimeter(self.raw_data)
        self.assertEqual(len(normalized), 2)
        # Port 3389 (RDP) must be identified in the dangerous ports array
        self.assertIn(3389, normalized[0]["exposed_admin_services"])

    def test_risk_scorer_calculates_critical_posture(self):
        normalized = ReconTelemetryCollector.normalize_asset(self.raw_data[0])
        evaluation = AttackSurfaceRiskEngine.evaluate_asset(normalized)
        # 25 (port 3389) + 30 (TLS <= 7 days) + 10 (no DNSSEC) = 65.0
        self.assertEqual(evaluation["posture"], "ELEVATED")
        self.assertEqual(evaluation["risk_score"], 65.0)

    def test_high_level_siem_telemetry_generation(self):
        normalized = ReconTelemetryCollector.aggregate_perimeter(self.raw_data)
        evaluations = [AttackSurfaceRiskEngine.evaluate_asset(a) for a in normalized]
        telemetry = SecurityReportGenerator.generate_siem_telemetry(evaluations)

        self.assertEqual(telemetry["executive_summary"]["monitored_assets"], 2)
        self.assertIn("timestamp", telemetry)
        self.assertEqual(len(telemetry["telemetry_events"]), 2)


if __name__ == "__main__":
    unittest.main()