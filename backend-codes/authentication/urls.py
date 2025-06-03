from django.urls import path
from .views import (
    RegisterView, 
    ProtectedView, 
    GoogleLoginView, 
    GoogleCallback,
    IndexView,
    CustomTokenObtainPairView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('protected/', ProtectedView.as_view(), name='protected'),
    path('google-login/', GoogleLoginView.as_view(), name='google_login'),
    path('google-callback/', GoogleCallback.as_view(), name='google_callback'),
    path('', IndexView.as_view(), name='index'),
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
]
