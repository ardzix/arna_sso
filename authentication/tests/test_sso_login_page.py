from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from django.test import Client, TestCase, override_settings
from django.urls import reverse
from rest_framework_simplejwt.tokens import AccessToken

from authentication.models import SSOAllowedRedirectURI, User
from authentication.serializers import MyTokenObtainPairSerializer, PreAuthTokenSerializer
from authentication.sso_views import SSO_BROWSER_COOKIE


class SSOLoginPageTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('browser@example.test', 'synthetic-password', is_active=True, is_staff=True)
        self.params = {'client_id': 'browser-test', 'redirect_uri': 'https://example.test/callback',
                       'state': 'test-state', 'code_challenge': 'a' * 43, 'code_challenge_method': 'S256'}
        SSOAllowedRedirectURI.objects.create(client_id=self.params['client_id'], redirect_uri=self.params['redirect_uri'])
        self.browser = Client(enforce_csrf_checks=True)
        self.login = reverse('sso_login_page')
        self.complete = reverse('sso_browser_session')

    def access(self):
        return MyTokenObtainPairSerializer.get_token(self.user).access_token

    def finish(self, payload=None, token=None, csrf=True):
        if csrf and 'csrftoken' not in self.browser.cookies:
            self.browser.get(self.login)
        headers = {'HTTP_AUTHORIZATION': 'Bearer ' + str(token or self.access()), 'HTTP_ORIGIN': 'https://sso.arnatech.id'}
        if csrf:
            headers['HTTP_X_CSRFTOKEN'] = self.browser.cookies['csrftoken'].value
        return self.browser.post(self.complete, data=payload or {}, content_type='application/json', **headers)

    def test_direct_url_renders_login_methods(self):
        response = self.browser.get(self.login)
        self.assertContains(response, 'Masuk dengan passkey')
        self.assertContains(response, 'Masuk dengan Google')
        self.assertContains(response, 'Email &amp; password')
        self.assertContains(response, 'Kirim kode ke WhatsApp saya')
        self.assertContains(response, 'Saya minta kode lewat chat WhatsApp')
        self.assertIn('no-store', response['Cache-Control'])

    def test_partial_unregistered_and_duplicate_requests_do_not_show_login_form(self):
        for query in ({'client_id': 'browser-test'}, {**self.params, 'redirect_uri': 'https://wrong.test/callback'},
                      {**self.params, 'client_id': ['browser-test', 'another-client']}):
            response = self.browser.get(self.login, query)
            self.assertNotContains(response, 'id="passwordForm"', status_code=400)

    def test_direct_login_has_secure_session_and_no_admin_authentication(self):
        response = self.finish()
        self.assertEqual(response.json(), {'redirect_url': '/login/'})
        cookie = response.cookies[SSO_BROWSER_COOKIE]
        self.assertTrue(cookie['secure'] and cookie['httponly'])
        self.assertEqual(cookie['samesite'], 'Lax')
        self.assertEqual(cookie['domain'], '')
        self.assertContains(self.browser.get(self.login), self.user.email)
        self.assertEqual(self.browser.get('/admin/').status_code, 302)

    def test_pkce_redirect_reuses_central_session_and_preserves_state(self):
        self.assertEqual(self.finish().status_code, 200)
        response = self.browser.get(self.login, self.params)
        self.assertEqual(response.status_code, 302)
        url = urlsplit(response['Location'])
        self.assertEqual(url.netloc, 'example.test')
        self.assertEqual(parse_qs(url.query)['state'], ['test-state'])
        self.assertIn('code', parse_qs(url.query))
        self.assertNotIn('access', parse_qs(url.query))

    def test_login_with_pkce_finishes_with_code(self):
        response = self.finish(self.params)
        self.assertEqual(response.status_code, 200)
        self.assertIn('code', parse_qs(urlsplit(response.json()['redirect_url']).query))
        self.assertIn(SSO_BROWSER_COOKIE, response.cookies)

    def test_csrf_and_non_human_tokens_cannot_start_session(self):
        self.assertEqual(self.finish(csrf=False).status_code, 403)
        challenge = PreAuthTokenSerializer.get_token(self.user)
        self.assertEqual(self.finish(token=challenge).status_code, 401)
        access = AccessToken.for_user(self.user)
        access['aud'] = 'storage'
        access['principal_type'] = 'user'
        self.assertEqual(self.finish(token=access).status_code, 403)
        self.assertEqual(self.finish({**self.params, 'redirect_uri': 'https://wrong.test/callback'}).status_code, 400)
        self.assertNotIn(SSO_BROWSER_COOKIE, self.browser.cookies)

    def test_password_change_and_logout_invalidate_session(self):
        self.assertEqual(self.finish().status_code, 200)
        self.user.set_password('another-synthetic-password')
        self.user.save(update_fields=['password'])
        self.assertContains(self.browser.get(self.login), 'id="passwordForm"')
        self.assertEqual(self.finish().status_code, 200)
        cookie = self.browser.cookies[SSO_BROWSER_COOKIE].value
        csrf = self.browser.cookies['csrftoken'].value
        response = self.browser.post(reverse('sso_browser_logout'), {'csrfmiddlewaretoken': csrf}, HTTP_ORIGIN='https://sso.arnatech.id')
        self.assertEqual(response.status_code, 302)
        self.browser.cookies[SSO_BROWSER_COOKIE] = cookie
        self.assertContains(self.browser.get(self.login), 'id="passwordForm"')

    @override_settings(SSO_GOOGLE_CLIENT_ID='trusted-client.apps.googleusercontent.com')
    @patch('authentication.views.id_token.verify_oauth2_token')
    def test_google_requires_audience_and_authoritative_mailbox(self, verify):
        url = reverse('google-login')
        verify.side_effect = ValueError('wrong audience')
        response = self.browser.post(url, {'token': 'synthetic'}, content_type='application/json')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(verify.call_args.kwargs['audience'], 'trusted-client.apps.googleusercontent.com')
        verify.side_effect = None
        verify.return_value = {'sub': '123', 'email': self.user.email, 'email_verified': True}
        response = self.browser.post(url, {'token': 'synthetic'}, content_type='application/json')
        self.assertEqual(response.status_code, 403)
        verify.return_value['hd'] = 'example.test'
        self.user.mfa_secret = 'JBSWY3DPEHPK3PXP'
        self.user.save(update_fields=['mfa_secret'])
        response = self.browser.post(url, {'token': 'synthetic'}, content_type='application/json')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['mfa_required'])
        self.assertNotIn('access', response.json())
