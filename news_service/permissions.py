"""
Permissions for the news service
"""
from rest_framework import permissions
import logging

logger = logging.getLogger(__name__)


class IsAdminOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow admin users to create/edit/delete news.
    All users can read news.
    """
    
    def has_permission(self, request, view):
        """
        Check if user has permission for the action
        """
        # Read permissions are allowed for any request
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions only for authenticated admin users
        if not request.user or not request.user.is_authenticated:
            logger.warning(f"Unauthenticated user attempted {request.method} on {request.path}")
            return False
        
        # Check if user has admin role
        user_role = getattr(request.user, 'role', None)
        is_admin = user_role == 'admin' or request.user.is_staff or request.user.is_superuser
        
        if not is_admin:
            logger.warning(f"Non-admin user {request.user.email} attempted {request.method} on {request.path}")
            return False
        
        logger.info(f"Admin user {request.user.email} granted {request.method} permission on {request.path}")
        return True
    
    def has_object_permission(self, request, view, obj):
        """
        Check if user has permission for a specific object
        """
        # Read permissions are allowed for any request
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions only for authenticated admin users
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Check if user has admin role
        user_role = getattr(request.user, 'role', None)
        is_admin = user_role == 'admin' or request.user.is_staff or request.user.is_superuser
        
        return is_admin


class NewsImagePermission(permissions.BasePermission):
    """
    Permission for news image operations
    """
    
    def has_permission(self, request, view):
        """
        Check permission for image operations
        """
        # Read permissions for authenticated users
        if request.method in permissions.SAFE_METHODS:
            return request.user.is_authenticated
        
        # Write permissions only for admin users
        if not request.user or not request.user.is_authenticated:
            return False
        
        user_role = getattr(request.user, 'role', None)
        return user_role == 'admin' or request.user.is_staff or request.user.is_superuser


class PublicReadOnlyPermission(permissions.BasePermission):
    """
    Allow read-only access to all users (including anonymous)
    """
    
    def has_permission(self, request, view):
        """
        Allow read access to everyone
        """
        return request.method in permissions.SAFE_METHODS
    
    def has_object_permission(self, request, view, obj):
        """
        Allow read access to everyone for any object
        """
        return request.method in permissions.SAFE_METHODS
