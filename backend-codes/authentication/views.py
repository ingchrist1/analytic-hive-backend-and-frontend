from django.shortcuts import render, redirect
from django.http import HttpResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import status
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from .serializers import UserSerializer, GoogleAuthSerializer
from django.conf import settings
from google.oauth2 import id_token
from google.auth.transport import requests
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
import requests as http_requests
from urllib.parse import urlencode
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()

class LoginRateThrottle(AnonRateThrottle):
    rate = '5/minute'
    scope = 'login'

class RegisterRateThrottle(AnonRateThrottle):
    rate = '3/hour'
    scope = 'register'

class RegisterView(APIView):
    throttle_classes = [RegisterRateThrottle]
    
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class GoogleLoginView(APIView):
    permission_classes = [AllowAny]
    serializer_class = GoogleAuthSerializer

    def get(self, request):
        # OAuth2 configuration
        oauth2_params = {
            'client_id': settings.GOOGLE_CLIENT_ID,
            'redirect_uri': settings.GOOGLE_CALLBACK_URL,  # Use the URL from settings
            'scope': 'email profile openid',
            'response_type': 'code',
            'access_type': 'offline',
            'prompt': 'consent',
        }
        
        # Construct Google OAuth2 URL with proper URL encoding
        auth_url = 'https://accounts.google.com/o/oauth2/v2/auth?' + urlencode(oauth2_params)
        
        # Redirect the user to Google's OAuth page
        return redirect(auth_url)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            # Verify the Google token
            idinfo = id_token.verify_oauth2_token(
                serializer.validated_data['id_token'],
                requests.Request(),
                settings.GOOGLE_CLIENT_ID
            )

            if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                raise ValueError('Wrong issuer.')

            # Get or create user
            email = idinfo['email']
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    'username': email.split('@')[0],
                    'profile_picture': idinfo.get('picture'),
                    'google_id': idinfo['sub']
                }
            )

            if not created:
                # Update existing user's profile picture
                user.profile_picture = idinfo.get('picture')
                user.google_id = idinfo['sub']
                user.save()

            # Create or update social account
            SocialAccount.objects.get_or_create(
                user=user,
                provider='google',
                uid=idinfo['sub'],
                defaults={'extra_data': idinfo}
            )

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'user': UserSerializer(user).data,
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
            })

        except ValueError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class GoogleCallback(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        code = request.GET.get('code')
        error = request.GET.get('error')

        if error:
            return Response({'error': error}, status=status.HTTP_400_BAD_REQUEST)

        if not code:
            return Response({'error': 'Code parameter missing'}, 
                          status=status.HTTP_400_BAD_REQUEST)

        try:
            # Exchange the authorization code for tokens
            token_url = 'https://oauth2.googleapis.com/token'
            data = {
                'code': code,
                'client_id': settings.GOOGLE_CLIENT_ID,
                'client_secret': settings.GOOGLE_CLIENT_SECRET,
                'redirect_uri': settings.GOOGLE_CALLBACK_URL,
                'grant_type': 'authorization_code'
            }

            response = http_requests.post(token_url, data=data)
            token_data = response.json()

            if 'error' in token_data:
                return Response({'error': token_data['error']}, status=status.HTTP_400_BAD_REQUEST)

            # Verify ID token and get user info
            idinfo = id_token.verify_oauth2_token(
                token_data['id_token'],
                requests.Request(),
                settings.GOOGLE_CLIENT_ID
            )

            if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                raise ValueError('Wrong issuer.')

            # Get or create user
            email = idinfo['email']
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    'username': email.split('@')[0],
                    'profile_picture': idinfo.get('picture'),
                    'google_id': idinfo['sub']
                }
            )

            if not created:
                # Update existing user's profile picture
                user.profile_picture = idinfo.get('picture')
                user.google_id = idinfo['sub']
                user.save()

            # Create or update social account
            SocialAccount.objects.get_or_create(
                user=user,
                provider='google',
                uid=idinfo['sub'],
                defaults={'extra_data': idinfo}
            )

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            
            # For development, create a simple HTML response that shows the tokens
            response_data = {
                'user': UserSerializer(user).data,
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
            }
            
            html_content = f"""
            <html>
                <head><title>Login Successful</title></head>
                <body>
                    <h1>Login Successful!</h1>
                    <h2>User Info:</h2>
                    <pre>{response_data['user']}</pre>
                    <h2>Access Token:</h2>
                    <pre>{response_data['access_token']}</pre>
                    <h2>Refresh Token:</h2>
                    <pre>{response_data['refresh_token']}</pre>
                </body>
            </html>
            """
            return HttpResponse(html_content)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def get(self, request):
        return Response({
            "message": "This is a protected endpoint.",
            "user": {
                "id": request.user.id,
                "email": request.user.email,
                "username": request.user.username,
                "profile_picture": request.user.profile_picture
            }
        })

class IndexView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return render(request, 'authentication/index.html')
