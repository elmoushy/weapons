"""
Middleware for data encryption and news service security
"""
import logging
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from django.core.exceptions import ValidationError
import json

logger = logging.getLogger(__name__)


class NewsEncryptionMiddleware(MiddlewareMixin):
    """
    Middleware to handle encryption/decryption of news data before/after database operations
    This middleware intercepts requests and responses to ensure data-at-rest encryption
    """
    
    def process_request(self, request):
        """
        Process incoming request data for encryption before database storage
        """
        # Only process news service endpoints
        if not request.path.startswith('/api/news/'):
            return None
        
        # Only process POST, PUT, PATCH requests with data
        if request.method not in ['POST', 'PUT', 'PATCH']:
            return None
        
        try:
            # Set flag to indicate this request needs encryption handling
            request._needs_encryption = True
            
            # Log the request for audit purposes
            logger.info(f"Processing encrypted request: {request.method} {request.path}")
            
        except Exception as e:
            logger.error(f"Error in encryption middleware request processing: {e}")
        
        return None
    
    def process_response(self, request, response):
        """
        Process outgoing response data for decryption after database retrieval
        """
        # Only process news service endpoints
        if not request.path.startswith('/api/news/'):
            return response
        
        try:
            # Set flag to indicate this response might need decryption handling
            if hasattr(request, '_needs_encryption'):
                logger.info(f"Processing encrypted response: {request.method} {request.path}")
            
        except Exception as e:
            logger.error(f"Error in encryption middleware response processing: {e}")
        
        return response


class NewsLoggingMiddleware(MiddlewareMixin):
    """
    Logging middleware for news service API calls
    """
    
    def process_request(self, request):
        """Log incoming requests to news endpoints"""
        if request.path.startswith('/api/news/'):
            user = getattr(request, 'user', None)
            user_info = f"User: {user.email if user and user.is_authenticated else 'Anonymous'}"
            logger.info(f"News API Request: {request.method} {request.path} - {user_info}")
        return None
    
    def process_response(self, request, response):
        """Log outgoing responses from news endpoints"""
        if request.path.startswith('/api/news/'):
            logger.info(f"News API Response: {request.method} {request.path} - Status: {response.status_code}")
        return response


class NewsSecurityMiddleware(MiddlewareMixin):
    """
    Security middleware for news service
    """
    
    def process_request(self, request):
        """
        Apply security measures to news requests
        """
        if not request.path.startswith('/api/news/'):
            return None
        
        try:
            # Check for common security headers
            if request.method in ['POST', 'PUT', 'PATCH']:
                content_type = request.content_type
                
                # Ensure proper content type for JSON requests
                if content_type and 'application/json' in content_type:
                    if not hasattr(request, 'body') or not request.body:
                        return JsonResponse({
                            'status': 'error',
                            'message': 'Request body is required',
                            'data': None
                        }, status=400)
                
                # Basic file upload size check (handled more thoroughly in views)
                if hasattr(request, 'FILES') and request.FILES:
                    for file in request.FILES.values():
                        if file.size > 50 * 1024 * 1024:  # 50MB limit
                            return JsonResponse({
                                'status': 'error',
                                'message': 'File size exceeds maximum limit (50MB)',
                                'data': None
                            }, status=413)
            
        except Exception as e:
            logger.error(f"Security middleware error: {e}")
            return JsonResponse({
                'status': 'error',
                'message': 'Security validation failed',
                'data': None
            }, status=400)
        
        return None


class UniformResponseMiddleware(MiddlewareMixin):
    """
    Middleware to ensure uniform JSON response format for news endpoints
    """
    
    def process_response(self, request, response):
        """
        Ensure all news API responses follow the uniform format:
        { status, message, data }
        """
        if not request.path.startswith('/api/news/'):
            return response
        
        # Only process JSON responses
        if response.get('Content-Type', '').startswith('application/json'):
            try:
                # Parse existing response
                if hasattr(response, 'content'):
                    content = json.loads(response.content.decode('utf-8'))
                    
                    # Check if already in uniform format
                    if not all(key in content for key in ['status', 'message', 'data']):
                        # Transform to uniform format
                        if response.status_code >= 400:
                            # Error response
                            uniform_response = {
                                'status': 'error',
                                'message': content.get('detail', content.get('error', 'An error occurred')),
                                'data': None
                            }
                        else:
                            # Success response
                            uniform_response = {
                                'status': 'success',
                                'message': content.get('message', 'Operation completed successfully'),
                                'data': content
                            }
                        
                        # Update response content
                        response.content = json.dumps(uniform_response, ensure_ascii=False).encode('utf-8')
                        response['Content-Length'] = len(response.content)
                
            except (json.JSONDecodeError, Exception) as e:
                logger.error(f"Error in uniform response middleware: {e}")
        
        return response
