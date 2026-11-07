"""Authentication and CSRF regression tests for the dashboard."""
import os
import re
import unittest

# Configure a test-only administrator before importing the Flask application.
os.environ["FACTORYSHIELD_SECRET_KEY"] = "test-only-secret-key-not-for-production"
os.environ["FACTORYSHIELD_ADMIN_USERNAME"] = "test-admin"
os.environ["FACTORYSHIELD_ADMIN_PASSWORD"] = "test-only-password"

from factoryshield.dashboard.app import app


class DashboardAuthenticationTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = app.test_client()

    def login(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        match = re.search(r'name="csrf_token" value="([^"]+)"', response.get_data(as_text=True))
        self.assertIsNotNone(match)
        return self.client.post(
            "/login",
            data={
                "csrf_token": match.group(1),
                "username": "test-admin",
                "password": "test-only-password",
            },
            follow_redirects=False,
        )

    def test_api_rejects_anonymous_requests(self):
        response = self.client.get("/api/incidents")
        self.assertEqual(response.status_code, 401)

    def test_dashboard_redirects_anonymous_users_to_login(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_authenticated_user_can_read_dashboard_api(self):
        response = self.login()
        self.assertEqual(response.status_code, 302)
        api_response = self.client.get("/api/stats")
        self.assertEqual(api_response.status_code, 200)

    def test_state_changing_api_requires_csrf_header(self):
        self.login()
        response = self.client.post("/api/simulate/normal")
        self.assertEqual(response.status_code, 400)

    def test_state_changing_api_accepts_valid_csrf_token(self):
        self.login()
        with self.client.session_transaction() as current_session:
            token = current_session["csrf_token"]
        response = self.client.post(
            "/api/simulate/normal",
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(response.status_code, 200)

    def test_logout_requires_csrf_token(self):
        self.login()
        response = self.client.post("/logout")
        self.assertEqual(response.status_code, 400)

    def test_logout_accepts_session_csrf_token(self):
        self.login()
        with self.client.session_transaction() as current_session:
            token = current_session["csrf_token"]
        response = self.client.post("/logout", data={"csrf_token": token})
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])


if __name__ == "__main__":
    unittest.main()
