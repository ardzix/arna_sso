from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from authentication.models import User
from rest_framework_simplejwt.tokens import RefreshToken
import pyotp

class AuthenticationTests(APITestCase):

    def setUp(self):
        # Create a test user
        self.user_data = {
            'email': 'testuser@example.com',
            'password': 'testpassword'
        }
        self.user = User.objects.create_user(**self.user_data)
        self.login_url = reverse('login')
        self.register_url = reverse('register')
        self.logout_url = reverse('logout')
        self.mfa_set_url = reverse('set_mfa')
        self.mfa_verify_url = reverse('mfa_verify')
        self.refresh_token_url = reverse('token_refresh')

    def test_user_registration(self):
        """Test user registration."""
        user_data = {
            'email': 'testuser2@example.com',
            'password': 'testpassword'
        }
        response = self.client.post(self.register_url, user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_user_login(self):
        """Test user login with correct credentials."""
        response = self.client.post(self.login_url, self.user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_user_login_invalid_credentials(self):
        """Test login with invalid credentials."""
        invalid_data = {
            'email': 'wrong@example.com',
            'password': 'wrongpassword'
        }
        response = self.client.post(self.login_url, invalid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_mfa_setup(self):
        """Test setting up MFA for a user."""
        self.client.force_authenticate(user=self.user)
        response = self.client.post(self.mfa_set_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('mfa_secret', response.data)

    def test_mfa_login(self):
        """Test logging in with MFA enabled."""
        # Set up MFA first
        self.client.force_authenticate(user=self.user)
        response = self.client.post(self.mfa_set_url)
        self.assertIn('mfa_secret', response.data)

        # Get MFA token
        mfa_secret = response.data['mfa_secret']
        totp = pyotp.TOTP(mfa_secret)
        mfa_token = totp.now()

        # Try MFA login
        response = self.client.post(self.mfa_verify_url, {
            'email': self.user.email,
            'mfa_token': mfa_token
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_token_refresh(self):
        """Test refreshing an access token."""
        # Log in to get refresh token
        response = self.client.post(self.login_url, self.user_data, format='json')
        refresh_token = response.data['refresh']

        # Refresh the access token
        response = self.client.post(self.refresh_token_url, {'refresh': refresh_token}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)

    def test_user_logout(self):
        """Test logging out by blacklisting the refresh token."""
        # Log in to get refresh token
        response = self.client.post(self.login_url, self.user_data, format='json')
        refresh_token = response.data['refresh']

        # Logout
        response = self.client.post(self.logout_url, {'refresh': refresh_token}, format='json')
        print(response)
        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)
