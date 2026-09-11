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

    def test_finops_v2_budget_forecast_and_rightsizing_surface_is_fail_closed(self):
        html = (ROOT / "webconsole/static/index.html").read_text(encoding="utf-8")
        js = (ROOT / "webconsole/static/app.js").read_text(encoding="utf-8")

        for fragment in (
            'id="finops-budget-form"',
            'id="finops-budget-grid"',
            'id="finops-insight-summary"',
            'id="finops-rightsizing-grid"',
        ):
            self.assertIn(fragment, html)
        self.assertIn('/api/v1/finops/budget-policies', js)
        self.assertIn('/api/v1/finops/insights', js)
        self.assertIn('Forecast unavailable', js)
        self.assertIn('Review only · never auto-applied', js)
        self.assertNotIn('Auto-apply rightsizing', html)


if __name__ == "__main__":
    unittest.main()
