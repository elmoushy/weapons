"""
Custom permissions for Files endpoints.

This module provides role-based access control and sharing permissions
for file management operations.
"""

from rest_framework import permissions
from django.contrib.auth import get_user_model
from django.utils import timezone
from .models import Share, Folder, File


User = get_user_model()


class IsAdminOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow admins to edit objects.
    Authenticated users can read, but only admins can create, update, or delete.
    """
    
    def has_permission(self, request, view):
        """
        Check if user has permission to access the view.
        """
        # All methods require authentication
        if not (request.user and request.user.is_authenticated):
            return False
        
        # Read permissions are allowed for authenticated users
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed for admin users
        return self.is_admin_user(request.user)
    
    def has_object_permission(self, request, view, obj):
        """
        Check if user has permission to access the specific object.
        """
        # All methods require authentication
        if not (request.user and request.user.is_authenticated):
            return False
        
        # Read permissions are allowed for authenticated users
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed for admin users
        return self.is_admin_user(request.user)
    
    @staticmethod
    def is_admin_user(user):
        """
        Check if user has admin role.
        
        Args:
            user: User instance
            
        Returns:
            bool: True if user is admin, False otherwise
        """
        return (
            user.is_superuser or 
            user.is_staff or 
            (hasattr(user, 'role') and user.role == 'admin')
        )


class IsAdminUser(permissions.BasePermission):
    """
    Custom permission to only allow admin users.
    """
    
    def has_permission(self, request, view):
        """
        Check if user has admin permission.
        """
        return (
            request.user and 
            request.user.is_authenticated and 
            IsAdminOrReadOnly.is_admin_user(request.user)
        )


class IsOwnerOrShared(permissions.BasePermission):
    """
    Custom permission to allow file/folder owners or users with shared access.
    """
    
    def has_permission(self, request, view):
        """
        Check if user has basic permission to access the view.
        """
        return request.user and request.user.is_authenticated
    
    def has_object_permission(self, request, view, obj):
        """
        Check if user has permission to access the specific file/folder.
        """
        if not (request.user and request.user.is_authenticated):
            return False
        
        user = request.user
        
        # Handle File objects
        if isinstance(obj, File):
            # Owner has full access
            if obj.user == user:
                return True
            
            # Check if file is in a shared folder
            if obj.folder:
                return self._has_folder_access(user, obj.folder, request.method)
            
            return False
        
        # Handle Folder objects
        elif isinstance(obj, Folder):
            # Owner has full access
            if obj.user == user:
                return True
            
            # Check shared access
            return self._has_folder_access(user, obj, request.method)
        
        return False
    
    def _has_folder_access(self, user, folder, method):
        """
        Check if user has access to folder through sharing.
        
        Args:
            user: User requesting access
            folder: Folder to check access for
            method: HTTP method (GET, POST, etc.)
            
        Returns:
            bool: True if user has access, False otherwise
        """
        # Get active shares for this folder and user
        shares = Share.objects.filter(
            target_user=user,
            folder=folder
        ).filter(
            models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=timezone.now())
        )
        
        if not shares.exists():
            return False
        
        share = shares.first()
        
        # Read access is allowed for any valid share
        if method in permissions.SAFE_METHODS:
            return True
        
        # Write access requires 'can_upload' permission
        return share.permission == 'can_upload'


class IsOwner(permissions.BasePermission):
    """
    Custom permission to only allow owners to access their objects.
    """
    
    def has_permission(self, request, view):
        """
        Check if user has basic permission to access the view.
        """
        return request.user and request.user.is_authenticated
    
    def has_object_permission(self, request, view, obj):
        """
        Check if user is the owner of the object.
        """
        if not (request.user and request.user.is_authenticated):
            return False
        
        # Handle different object types
        if hasattr(obj, 'user'):
            return obj.user == request.user
        elif hasattr(obj, 'owner'):
            return obj.owner == request.user
        
        return False


class CanUploadToFolder(permissions.BasePermission):
    """
    Custom permission to check if user can upload files to a folder.
    """
    
    def has_permission(self, request, view):
        """
        Check if user has permission to upload.
        """
        if not (request.user and request.user.is_authenticated):
            return False
        
        # Only check for non-safe methods (POST, PUT, PATCH)
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Get folder from request data
        folder_id = request.data.get('folder')
        if not folder_id:
            # No folder specified, user can upload to root
            return True
        
        try:
            folder = Folder.objects.get(id=folder_id, deleted_at__isnull=True)
        except Folder.DoesNotExist:
            return False
        
        user = request.user
        
        # Owner can always upload
        if folder.user == user:
            return True
        
        # Check shared access with upload permission
        shares = Share.objects.filter(
            target_user=user,
            folder=folder,
            permission='can_upload'
        ).filter(
            models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=timezone.now())
        )
        
        return shares.exists()


class HasQuotaSpace(permissions.BasePermission):
    """
    Custom permission to check if user has enough quota space for upload.
    """
    
    def has_permission(self, request, view):
        """
        Check if user has enough quota space.
        """
        if not (request.user and request.user.is_authenticated):
            return False
        
        # Only check for upload operations
        if request.method not in ['POST', 'PUT', 'PATCH']:
            return True
        
        user = request.user
        
        # Get file size from request
        file_size = 0
        
        # Check if uploading file
        if 'file_upload' in request.FILES:
            file_size = request.FILES['file_upload'].size
        elif 'files' in request.FILES:
            # Multiple files
            file_size = sum(f.size for f in request.FILES.getlist('files'))
        
        if file_size == 0:
            return True
        
        # Check quota
        from .models import UserQuota
        quota, created = UserQuota.objects.get_or_create(user=user)
        
        return quota.can_upload(file_size)


# Import models at the end to avoid circular imports
from django.db import models
