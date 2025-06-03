#!/usr/bin/env python
"""
Django deployment checklist script.
Run this before deploying to production to ensure secure settings.
"""
import os
import sys
import environ

def check_deployment_settings():
    issues = []
    
    # Load environment variables
    env = environ.Env()
    try:
        env.read_env()
    except Exception as e:
        issues.append(f"❌ Cannot read .env file: {str(e)}")
        return issues

    # Check DEBUG setting
    if env.bool('DEBUG', True):
        issues.append("❌ DEBUG is set to True. Set DEBUG=False in production.")

    # Check SECRET_KEY
    if 'SECRET_KEY' not in os.environ:
        issues.append("❌ SECRET_KEY not set in environment variables.")
    elif 'insecure' in os.environ.get('SECRET_KEY', '').lower():
        issues.append("❌ Using default/insecure SECRET_KEY. Generate a new one.")

    # Check ALLOWED_HOSTS
    allowed_hosts = env.list('ALLOWED_HOSTS', default=[])
    if not allowed_hosts or '*' in allowed_hosts:
        issues.append("❌ ALLOWED_HOSTS is empty or contains '*'. Specify your domain(s).")

    # Check CORS settings
    cors_origins = env.list('CORS_ALLOWED_ORIGINS', default=[])
    if not cors_origins:
        issues.append("❌ CORS_ALLOWED_ORIGINS not configured. Specify allowed origins.")

    # Check security settings
    if not env.bool('SECURE_SSL_REDIRECT', False):
        issues.append("❌ SECURE_SSL_REDIRECT should be True in production.")
    if not env.bool('SESSION_COOKIE_SECURE', False):
        issues.append("❌ SESSION_COOKIE_SECURE should be True in production.")
    if not env.bool('CSRF_COOKIE_SECURE', False):
        issues.append("❌ CSRF_COOKIE_SECURE should be True in production.")

    # If no issues found
    if not issues:
        print("✅ All deployment checks passed!")
    else:
        print("Found the following issues:")
        for issue in issues:
            print(issue)

if __name__ == '__main__':
    check_deployment_settings()
