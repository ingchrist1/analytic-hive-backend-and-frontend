import requests
import json
import sys
import logging
from datetime import datetime
from requests.exceptions import ConnectionError

# Set up logging
logging.basicConfig(
    filename=f'auth_test_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_and_print(message):
    print(message)
    logging.info(message)

def test_signup():
    # Test data
    signup_data = {
        "email": "test@example.com",
        "password1": "Test@1234!",
        "password2": "Test@1234!"
    }
    
    # Signup request
    log_and_print("\n=== Testing Signup ===")
    try:
        response = requests.post(
            'http://localhost:8000/auth/register/',
            json=signup_data,
            headers={'Content-Type': 'application/json'}
        )
        log_and_print(f"Status Code: {response.status_code}")
        try:
            response_data = response.json()
            log_and_print(f"Response: {json.dumps(response_data, indent=2)}")
        except json.JSONDecodeError:
            log_and_print(f"Raw Response: {response.text}")
        
        return response.json() if response.status_code == 201 else None
    except ConnectionError:
        log_and_print("Error: Could not connect to the server. Is the Django server running?")
        sys.exit(1)
    except Exception as e:
        log_and_print(f"Error during signup: {str(e)}")
        return None

def test_signin():
    # Test data
    signin_data = {
        "email": "test@example.com",
        "password": "Test@1234!"
    }
    
    # Signin request
    log_and_print("\n=== Testing Signin ===")
    try:
        response = requests.post(
            'http://localhost:8000/auth/token/',
            json=signin_data,
            headers={'Content-Type': 'application/json'}
        )
        log_and_print(f"Status Code: {response.status_code}")
        try:
            response_data = response.json()
            log_and_print(f"Response: {json.dumps(response_data, indent=2)}")
        except json.JSONDecodeError:
            log_and_print(f"Raw Response: {response.text}")
        
        return response.json() if response.status_code == 200 else None
    except ConnectionError:
        log_and_print("Error: Could not connect to the server. Is the Django server running?")
        sys.exit(1)
    except Exception as e:
        log_and_print(f"Error during signin: {str(e)}")
        return None

def test_protected_endpoint(access_token):
    log_and_print("\n=== Testing Protected Endpoint ===")
    try:
        response = requests.get(
            'http://localhost:8000/auth/protected/',
            headers={
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
        )
        log_and_print(f"Status Code: {response.status_code}")
        try:
            response_data = response.json()
            log_and_print(f"Response: {json.dumps(response_data, indent=2)}")
        except json.JSONDecodeError:
            log_and_print(f"Raw Response: {response.text}")
    except ConnectionError:
        log_and_print("Error: Could not connect to the server. Is the Django server running?")
    except Exception as e:
        log_and_print(f"Error accessing protected endpoint: {str(e)}")

if __name__ == "__main__":
    log_and_print("Starting authentication tests...")
    log_and_print("Making sure server is accessible...")
    
    try:
        requests.get('http://localhost:8000/auth/')
    except ConnectionError:
        log_and_print("Error: Could not connect to the server. Please make sure the Django server is running on port 8000")
        sys.exit(1)
    
    # Test signup
    signup_result = test_signup()
    
    # Test signin
    signin_result = test_signin()
    
    # If signin successful, test protected endpoint
    if signin_result and 'access' in signin_result:
        test_protected_endpoint(signin_result['access'])
    else:
        log_and_print("\nSkipping protected endpoint test as signin was not successful")
