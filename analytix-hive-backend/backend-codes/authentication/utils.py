from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from django.core.exceptions import ValidationError
from django.http import Http404

def custom_exception_handler(exc, context):
    """
    Custom exception handler for REST framework that handles additional exceptions.
    """
    # Call REST framework's default exception handler first
    response = exception_handler(exc, context)

    # If response is None, there was an unhandled exception
    if response is None:
        if isinstance(exc, ValidationError):
            response = Response({
                'error': 'Validation Error',
                'message': 'The submitted data is invalid.',
                'details': exc.messages if hasattr(exc, 'messages') else str(exc)
            }, status=status.HTTP_400_BAD_REQUEST)
        elif isinstance(exc, Http404):
            response = Response({
                'error': 'Not Found',
                'message': 'The requested resource was not found.'
            }, status=status.HTTP_404_NOT_FOUND)
        else:
            # Log the error here (but don't expose details to the client)
            print(f'Unhandled exception: {exc}')  # Replace with proper logging
            response = Response({
                'error': 'Internal Server Error',
                'message': 'An unexpected error occurred.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Ensure sensitive information is not exposed
    if response is not None and response.status_code >= 400:
        if 'detail' in response.data:
            # Make error messages more user-friendly
            response.data = {
                'error': response.status_text,
                'message': response.data['detail']
            }

    return response
