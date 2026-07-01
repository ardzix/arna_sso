from django.test import SimpleTestCase
from django.urls import reverse


class SSOLoginPageTests(SimpleTestCase):
    def test_sso_login_page_renders(self):
        response = self.client.get(
            reverse("sso_login_page"),
            {
                "client_id": "ols-mp",
                "redirect_uri": "https://sales.ourlilstudio.com/auth/callback",
                "state": "state",
                "code_challenge": "a" * 43,
                "code_challenge_method": "S256",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Continue with passkey")
