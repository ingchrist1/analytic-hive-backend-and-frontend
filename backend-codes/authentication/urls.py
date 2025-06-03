from django.urls import path
from .views import (
    RegisterView, 
    ProtectedView, 
    GoogleLoginView, 
    GoogleCallback,
    IndexView
)
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    # Landing page
    path('', IndexView.as_view(), name='index'),
    
    # JWT endpoints
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # Registration and protected endpoints
    path('register/', RegisterView.as_view(), name='register'),
    path('protected/', ProtectedView.as_view(), name='protected'),
    
    # Google authentication endpoints
    path('google/login/', GoogleLoginView.as_view(), name='google_login'),
    path('google/callback/', GoogleCallback.as_view(), name='google_callback'),
]
