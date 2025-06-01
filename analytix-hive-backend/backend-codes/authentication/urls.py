from django.urls import path
from .views import (
    RegisterView, 
    ProtectedView, 
    GoogleLoginView, 
    GoogleCallback,
    IndexView,
    CustomTokenObtainPairView
)
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    # Landing page
    path('', IndexView.as_view(), name='index'),
    
    # JWT endpoints
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # Registration and protected endpoints
    path('register/', RegisterView.as_view(), name='register'),
    path('protected/', ProtectedView.as_view(), name='protected'),
    
    # Google authentication endpoints
    path('google/login/', GoogleLoginView.as_view(), name='google_login'),
    path('google/callback/', GoogleCallback.as_view(), name='google_callback'),
]
