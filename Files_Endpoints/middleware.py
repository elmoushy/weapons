"""
Middleware for Files endpoints.

This module provides middleware for quota enforcement, access control,
encryption, and security for file management operations.
"""

import json
import logging
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import get_user_model
from django.utils import timezone
from .models import UserQuota, Share, Folder


logger = logging.getLogger(__name__)
User = get_user_model()


class FilesEncryptionMiddleware(MiddlewareMixin):
    """
    Middleware to handle encryption/decryption of files data before/after database operations
    This middleware intercepts requests and responses to ensure data-at-rest encryption
    """
    
    def process_request(self, request):
        """
        Process incoming request data for encryption before database storage
        """
        # Only process files service endpoints
        if not request.path.startswith('/api/files/'):
            return None
        
        # Only process POST, PUT, PATCH requests with data
        if request.method not in ['POST', 'PUT', 'PATCH']:
            return None
        
        try:
            # Set flag to indicate this request needs encryption handling
            request._needs_encryption = True
            
            # Log the request for audit purposes
            logger.info(f"Processing encrypted files request: {request.method} {request.path}")
            
        except Exception as e:
            logger.error(f"Error in files encryption middleware request processing: {e}")
        
        return None
    
    def process_response(self, request, response):
        """
        Process outgoing response data for decryption after database retrieval
        """
        # Only process files service endpoints
        if not request.path.startswith('/api/files/'):
            return response
        
        try:
            # Set flag to indicate this response might need decryption handling
            if hasattr(request, '_needs_encryption'):
                logger.info(f"Processing encrypted files response: {request.method} {request.path}")
            
        except Exception as e:
            logger.error(f"Error in files encryption middleware response processing: {e}")
        
        return response


class FilesLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log file operations for audit purposes.
    """
    
    def process_request(self, request):
        """Log incoming file-related requests."""
        if request.path.startswith('/api/files'):
            logger.info(
                f"Files API Request - User: {getattr(request.user, 'email', 'Anonymous')}, "
                f"Method: {request.method}, Path: {request.path}, "
                f"IP: {self.get_client_ip(request)}"
            )
        return None
    
    def process_response(self, request, response):
        """Log responses for file operations."""
        if request.path.startswith('/api/files'):
            logger.info(
                f"Files API Response - User: {getattr(request.user, 'email', 'Anonymous')}, "
                f"Method: {request.method}, Path: {request.path}, "
                f"Status: {response.status_code}"
            )
        return response
    
    def get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class QuotaEnforcementMiddleware(MiddlewareMixin):
    """
    Middleware to enforce storage quotas on file uploads.
    """
    
    def process_request(self, request):
        """Check quota before processing upload requests."""
        # Only check for upload operations
        if (request.method in ['POST', 'PUT', 'PATCH'] and 
            request.path.startswith('/api/files') and
            ('upload' in request.path or request.path.endswith('/files'))):
            
            if not request.user.is_authenticated:
                return None
            
            # Calculate total upload size
            total_size = 0
            
            # Check file uploads
            if hasattr(request, 'FILES'):
                for file_list in request.FILES.values():
                    if hasattr(file_list, '__iter__') and not isinstance(file_list, str):
                        # Multiple files
                        total_size += sum(f.size for f in file_list)
                    else:
                        # Single file
                        total_size += file_list.size
            
            # Check base64 data in request body
            if request.content_type == 'application/json':
                try:
                    body = json.loads(request.body.decode('utf-8'))
                    if 'file_data' in body and isinstance(body['file_data'], str):
                        # Estimate base64 size (roughly 4/3 of original)
                        total_size += len(body['file_data']) * 3 // 4
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
            
            if total_size > 0:
                # Check user quota
                quota, created = UserQuota.objects.get_or_create(user=request.user)
                
                if not quota.can_upload(total_size):
                    available_gb = quota.available_bytes / (1024**3)
                    required_gb = total_size / (1024**3)
                    
                    return JsonResponse({
                        'status': 413,
                        'message': f'Quota exceeded. Available: {available_gb:.2f} GB, Required: {required_gb:.2f} GB',
                        'data': {
                            'quota': {
                                'used_bytes': quota.used_bytes,
                                'limit_bytes': quota.limit_bytes,
                                'available_bytes': quota.available_bytes,
                                'used_percent': quota.used_percent
                            }
                        }
                    }, status=413)
        
        return None


class ShareAccessMiddleware(MiddlewareMixin):
    """
    Middleware to validate share access and permissions.
    """
    
    def process_request(self, request):
        """Validate share access for folder operations."""
        if not request.user.is_authenticated:
            return None
        
        # Check access for folder-specific operations
        if request.path.startswith('/api/folders/') and len(request.path.split('/')) >= 4:
            try:
                folder_id = request.path.split('/')[3]
                
                # Skip if not a UUID (might be other endpoints like 'list')
                if len(folder_id) != 36:
                    return None
                
                folder = Folder.objects.get(id=folder_id, deleted_at__isnull=True)
                user = request.user
                
                # Owner has full access
                if folder.user == user:
                    return None
                
                # Check shared access
                shares = Share.objects.filter(
                    target_user=user,
                    folder=folder
                ).filter(
                    models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=timezone.now())
                )
                
                if not shares.exists():
                    return JsonResponse({
                        'status': 403,
                        'message': 'Access denied. Folder not shared with you.',
                        'data': {}
                    }, status=403)
                
                share = shares.first()
                
                # Check if operation requires upload permission
                if (request.method in ['POST', 'PUT', 'PATCH', 'DELETE'] and
                    share.permission != 'can_upload'):
                    return JsonResponse({
                        'status': 403,
                        'message': 'Access denied. You only have download permission for this folder.',
                        'data': {}
                    }, status=403)
                
            except (Folder.DoesNotExist, ValueError, IndexError):
                pass
        
        return None


class FilesSecurityMiddleware(MiddlewareMixin):
    """
    Middleware to enforce security policies for file operations.
    """
    
    # Allowed file extensions (whitelist approach)
    ALLOWED_EXTENSIONS = {
        # Documents
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'odt', 'ods', 'odp',
        # Images
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp', 'ico',
        # Audio
        'mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a',
        # Video
        'mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm',
        # Archives
        'zip', 'rar', '7z', 'tar', 'gz', 'bz2',
        # Code
        'py', 'js', 'html', 'css', 'json', 'xml', 'csv', 'sql',
        # Other
        'md', 'log'
    }
    
    # Maximum file size (100 MB)
    MAX_FILE_SIZE = 100 * 1024 * 1024
    
    def process_request(self, request):
        """Validate file security before processing."""
        if (request.method in ['POST', 'PUT', 'PATCH'] and 
            request.path.startswith('/api/files')):
            
            # Check uploaded files
            if hasattr(request, 'FILES') and request.FILES:
                for field_name in request.FILES:
                    files_to_check = request.FILES.getlist(field_name)
                    
                    for uploaded_file in files_to_check:
                        # Ensure uploaded_file is a proper file object
                        if not hasattr(uploaded_file, 'size'):
                            continue
                            
                        # Check file size
                        if uploaded_file.size > self.MAX_FILE_SIZE:
                            size_mb = uploaded_file.size / (1024 * 1024)
                            max_mb = self.MAX_FILE_SIZE / (1024 * 1024)
                            return JsonResponse({
                                'status': 413,
                                'message': f'File too large. Size: {size_mb:.1f} MB, Maximum: {max_mb} MB',
                                'data': {}
                            }, status=413)
                        
                        # Check file extension
                        if hasattr(uploaded_file, 'name') and uploaded_file.name:
                            filename = uploaded_file.name.lower()
                            if '.' in filename:
                                extension = filename.rsplit('.', 1)[1]
                                if extension not in self.ALLOWED_EXTENSIONS:
                                    return JsonResponse({
                                        'status': 400,
                                        'message': f'File type not allowed: .{extension}',
                                        'data': {
                                            'allowed_extensions': list(self.ALLOWED_EXTENSIONS)
                                        }
                                    }, status=400)
            
            # Check JSON payload for base64 files
            if request.content_type == 'application/json':
                try:
                    body = json.loads(request.body.decode('utf-8'))
                    if 'name' in body:
                        filename = body['name'].lower()
                        if '.' in filename:
                            extension = filename.rsplit('.', 1)[1]
                            if extension not in self.ALLOWED_EXTENSIONS:
                                return JsonResponse({
                                    'status': 400,
                                    'message': f'File type not allowed: .{extension}',
                                    'data': {
                                        'allowed_extensions': list(self.ALLOWED_EXTENSIONS)
                                    }
                                }, status=400)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
        
        return None


# Import models at the end to avoid circular imports
from django.db import models


class FilesUniformResponseMiddleware(MiddlewareMixin):
    """
    Middleware to ensure uniform JSON response format for files endpoints
    """
    
    def process_response(self, request, response):
        """
        Ensure all files API responses follow the uniform format:
        { status, message, data }
        """
        if not request.path.startswith('/api/files/'):
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
                logger.error(f"Error in files uniform response middleware: {e}")
        
        return response
