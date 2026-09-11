from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class FinOpsConsoleContractTest(unittest.TestCase):
    def test_finops_is_a_first_class_fleet_page_with_truthful_cost_surface(self):
        html = (ROOT / "webconsole/static/index.html").read_text(encoding="utf-8")
        js = (ROOT / "webconsole/static/app.js").read_text(encoding="utf-8")

        for fragment in (
            'data-page="finops"',
            'id="finops"',
            'id="finops-rate-card-form"',
            'id="finops-rate-card-grid"',
            'id="finops-usage-grid"',
            'id="finops-cost-summary"',
            'id="finops-chargeback-grid"',
            'id="finops-chargeback-export"',
        ):
            self.assertIn(fragment, html)

        self.assertIn('finops:loadFinOps', js)
        for endpoint in (
            '/api/v1/finops/rate-cards',
            '/api/v1/finops/usage-measurements',
            '/api/v1/finops/capacity-observations',
            '/api/v1/finops/showback',
            '/api/v1/finops/chargeback-export',
        ):
            self.assertIn(endpoint, js)
        self.assertIn('Cost unavailable', js)
        self.assertIn('Missing telemetry is not treated as zero', js)
        self.assertIn('ACCELERATOR_HOUR', js)
        self.assertNotIn('data-finops-manual-usage', html, 'authoritative telemetry must not be manually forged from the console')


if __name__ == "__main__":
    unittest.main()
