"""
URL configuration for analytix_hive_backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
"""

from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect

def redirect_to_auth(request):
    return redirect('auth/')

urlpatterns = [
    path('', redirect_to_auth, name='root'),  # Redirect root to auth/
    path('admin/', admin.site.urls),
    path('auth/', include('authentication.urls')),  # All authentication routes under /auth/
]
