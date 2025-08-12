"""
Serializers for Files management endpoints.

This module provides serializers for converting model instances to JSON
and handling validation for API requests related to file management with encryption support.
"""

import base64
import mimetypes
import os
from rest_framework import serializers
from django.core.files.base import ContentFile
from django.contrib.auth import get_user_model
from django.utils import timezone
from .models import File, Folder, Share, UserQuota
import logging

logger = logging.getLogger(__name__)
User = get_user_model()


class Base64FileField(serializers.Field):
    """
    Custom field to handle base64 encoded files with encryption support.
    """
    
    def to_representation(self, value):
        """Convert binary file data to base64 string."""
        if value:
            try:
                # Value is already decrypted by the EncryptedBinaryField
                if isinstance(value, (bytes, memoryview)):
                    return base64.b64encode(bytes(value)).decode('utf-8')
                return value
            except Exception as e:
                logger.error(f"Error converting file to base64: {e}")
                return None
        return None
    
    def to_internal_value(self, data):
        """Convert base64 string to binary data for encrypted storage."""
        if isinstance(data, str) and data.startswith('data:'):
            # Handle data URL format (data:mime/type;base64,data)
            try:
                header, data = data.split(',', 1)
                return base64.b64decode(data)
            except ValueError:
                raise serializers.ValidationError("Invalid data URL format")
        elif isinstance(data, str):
            # Handle plain base64 string
            try:
                return base64.b64decode(data)
            except Exception:
                raise serializers.ValidationError("Invalid base64 data")
        return data


class UserSummarySerializer(serializers.ModelSerializer):
    """
    Serializer for user summary (for sharing lists).
    """
    
    full_name = serializers.CharField(read_only=True)
    
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'full_name']
        read_only_fields = ['id', 'email', 'first_name', 'last_name', 'full_name']


class UserQuotaSerializer(serializers.ModelSerializer):
    """
    Serializer for user quota information.
    """
    
    used_percent = serializers.FloatField(read_only=True)
    available_bytes = serializers.IntegerField(read_only=True)
    limit_gb = serializers.SerializerMethodField()
    used_gb = serializers.SerializerMethodField()
    
    class Meta:
        model = UserQuota
        fields = [
            'limit_bytes', 'used_bytes', 'used_percent', 'available_bytes',
            'limit_gb', 'used_gb', 'updated_at'
        ]
        read_only_fields = ['used_bytes', 'used_percent', 'available_bytes', 'updated_at']
    
    def get_limit_gb(self, obj):
        """Convert limit to GB."""
        return round(obj.limit_bytes / (1024**3), 2)
    
    def get_used_gb(self, obj):
        """Convert used to GB."""
        return round(obj.used_bytes / (1024**3), 2)


class FolderSerializer(serializers.ModelSerializer):
    """
    Serializer for Folder model with role-based field filtering.
    """
    
    full_path = serializers.CharField(read_only=True)
    is_shared = serializers.BooleanField(read_only=True)
    file_count = serializers.SerializerMethodField()
    subfolder_count = serializers.SerializerMethodField()
    user_email = serializers.CharField(source='user.email', read_only=True)
    
    class Meta:
        model = Folder
        fields = [
            'id', 'name', 'parent', 'full_path', 'is_shared',
            'file_count', 'subfolder_count', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_file_count(self, obj):
        """Get number of files in folder."""
        return obj.files.filter(deleted_at__isnull=True).count()
    
    def get_subfolder_count(self, obj):
        """Get number of subfolders."""
        return obj.subfolders.filter(deleted_at__isnull=True).count()
    
    def validate_name(self, value):
        """Validate folder name."""
        if not value.strip():
            raise serializers.ValidationError("Folder name cannot be empty")
        
        # Check for invalid characters
        invalid_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
        for char in invalid_chars:
            if char in value:
                raise serializers.ValidationError(f"Folder name cannot contain '{char}'")
        
        return value.strip()
    
    def validate(self, data):
        """Validate folder creation."""
        user = self.context['request'].user
        name = data.get('name')
        parent = data.get('parent')
        
        # Check for duplicate names in same parent folder
        existing = Folder.objects.filter(
            user=user,
            parent=parent,
            name=name,
            deleted_at__isnull=True
        )
        
        if self.instance:
            existing = existing.exclude(pk=self.instance.pk)
        
        if existing.exists():
            raise serializers.ValidationError("A folder with this name already exists in the parent folder")
        
        return data


class FileSerializer(serializers.ModelSerializer):
    """
    Serializer for File model (without binary data) with role-based filtering.
    """
    
    extension = serializers.CharField(read_only=True)
    size_human = serializers.CharField(read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    folder_name = serializers.CharField(source='folder.name', read_only=True)
    folder_path = serializers.CharField(source='folder.full_path', read_only=True)
    download_url = serializers.SerializerMethodField()
    
    class Meta:
        model = File
        fields = [
            'id', 'name', 'mime_type', 'size_bytes', 'extension', 'size_human',
            'folder', 'folder_name', 'folder_path', 'user_email', 'is_favorite',
            'download_url', 'uploaded_at', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'mime_type', 'size_bytes', 'extension', 'size_human',
            'uploaded_at', 'created_at', 'updated_at'
        ]
    
    def get_download_url(self, obj):
        """Get download URL for file."""
        try:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(f'/api/files/{obj.id}/download/')
            return f'/api/files/{obj.id}/download/'
        except Exception as e:
            logging.getLogger(__name__).error(f"Error getting download URL: {str(e)}")
            return None
    
    def to_representation(self, instance):
        """Apply role-based filtering to output fields."""
        data = super().to_representation(instance)
        request = self.context.get('request')
        
        if request and request.user.is_authenticated:
            user_role = getattr(request.user, 'role', 'user')
            
            # Public users can only see their own files or shared files
            if user_role == 'user' and instance.user != request.user:
                # Check if user has access through folder sharing
                from django.utils import timezone
                from django.db.models import Q
                
                has_access = False
                if instance.folder:
                    shares = Share.objects.filter(
                        target_user=request.user,
                        folder=instance.folder
                    ).filter(
                        Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())
                    )
                    has_access = shares.exists()
                
                if not has_access:
                    # Filter out sensitive fields for non-accessible files
                    filtered_fields = ['id', 'name', 'extension', 'created_at']
                    data = {k: v for k, v in data.items() if k in filtered_fields}
            
            # Admins get all fields (no filtering)
            # File owners get all fields (no filtering)
        
        return data


class FileUploadSerializer(serializers.ModelSerializer):
    """
    Serializer for file upload operations with role-based filtering and encryption support.
    """
    
    file_data = serializers.FileField(write_only=True)
    folder = serializers.PrimaryKeyRelatedField(queryset=Folder.objects.all(), required=False, allow_null=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    folder_name = serializers.CharField(source='folder.name', read_only=True)
    folder_path = serializers.CharField(source='folder.full_path', read_only=True)
    download_url = serializers.SerializerMethodField()
    
    class Meta:
        model = File
        fields = ['id', 'name', 'folder', 'file_data', 'user_email', 'folder_name', 
                 'folder_path', 'download_url', 'mime_type', 'size_bytes', 'is_favorite',
                 'uploaded_at', 'created_at', 'updated_at']
        read_only_fields = ['id', 'mime_type', 'size_bytes', 'uploaded_at', 'created_at', 'updated_at']
    
    def get_download_url(self, obj):
        """Get download URL for file."""
        try:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(f'/api/files/{obj.id}/download/')
            return f'/api/files/{obj.id}/download/'
        except Exception as e:
            logging.getLogger(__name__).error(f"Error getting download URL: {str(e)}")
            return None
    
    def to_representation(self, instance):
        """Apply role-based filtering to output fields."""
        data = super().to_representation(instance)
        request = self.context.get('request')
        
        if request and request.user.is_authenticated:
            user_role = getattr(request.user, 'role', 'user')
            
            # Public users can only see basic info for their own files
            if user_role == 'user' and instance.user != request.user:
                # User can only see files they own or have been shared with
                from django.utils import timezone
                from django.db.models import Q
                
                has_access = False
                if instance.folder:
                    shares = Share.objects.filter(
                        target_user=request.user,
                        folder=instance.folder
                    ).filter(
                        Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())
                    )
                    has_access = shares.exists()
                
                if not has_access:
                    # Filter out sensitive fields for non-accessible files
                    filtered_fields = ['id', 'name', 'created_at']
                    data = {k: v for k, v in data.items() if k in filtered_fields}
            
            # Admins get all fields (no filtering)
            # File owners get all fields (no filtering)
        
        return data
    
    def validate(self, data):
        """Validate file upload with enhanced security checks."""
        user = self.context['request'].user
        folder = data.get('folder')
        uploaded_file = data.get('file_data')
        
        if not uploaded_file:
            raise serializers.ValidationError("file_data is required")
        
        # Security: Validate file type
        allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx', 
                            '.txt', '.zip', '.rar', '.mp4', '.mp3', '.wav']
        file_extension = os.path.splitext(uploaded_file.name)[1].lower()
        if file_extension not in allowed_extensions:
            raise serializers.ValidationError(f"File type {file_extension} not allowed")
        
        # Security: Validate file size (max 100MB)
        max_size = 100 * 1024 * 1024  # 100MB
        if uploaded_file.size > max_size:
            raise serializers.ValidationError("File size cannot exceed 100MB")
        
        # Check quota
        quota, created = UserQuota.objects.get_or_create(user=user)
        if not quota.can_upload(uploaded_file.size):
            available_gb = quota.available_bytes / (1024**3)
            required_gb = uploaded_file.size / (1024**3)
            raise serializers.ValidationError(
                f"Quota exceeded. Available: {available_gb:.2f} GB, Required: {required_gb:.2f} GB"
            )
        
        # Validate folder ownership if folder is specified
        if folder:
            if folder.user != user:
                # Check if user has upload permission to this folder
                from django.utils import timezone
                from django.db.models import Q
                shares = Share.objects.filter(
                    target_user=user,
                    folder=folder,
                    permission='can_upload'
                ).filter(
                    Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())
                )
                
                if not shares.exists():
                    raise serializers.ValidationError("Cannot upload to folder you don't own or don't have upload permission")
        
        return data
    
    def create(self, validated_data):
        """Create file with binary data from uploaded file and proper error handling."""
        try:
            uploaded = validated_data.pop('file_data')
            
            # Create file instance with encrypted data
            instance = File(
                name=validated_data.get('name', uploaded.name),
                folder=validated_data.get('folder'),
                mime_type=uploaded.content_type or 'application/octet-stream',
                size_bytes=uploaded.size,
                data_blob=uploaded.read(),  # This will be encrypted by EncryptedBinaryField
                user=self.context['request'].user,
            )
            
            instance.save()
            
            # Update user quota
            quota, created = UserQuota.objects.get_or_create(user=instance.user)
            quota.update_usage()
            
            return instance
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Error creating file upload: {str(e)}")
            raise serializers.ValidationError(f"Failed to upload file: {str(e)}")


class ShareSerializer(serializers.ModelSerializer):
    """
    Serializer for Share model with role-based filtering.
    """
    
    owner_name = serializers.CharField(source='owner.full_name', read_only=True)
    owner_email = serializers.CharField(source='owner.email', read_only=True)
    target_user_name = serializers.CharField(source='target_user.full_name', read_only=True)
    target_user_email = serializers.CharField(source='target_user.email', read_only=True)
    folder_name = serializers.CharField(source='folder.name', read_only=True)
    folder_path = serializers.CharField(source='folder.full_path', read_only=True)
    is_expired = serializers.BooleanField(read_only=True)
    is_active = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = Share
        fields = [
            'id', 'owner', 'owner_name', 'owner_email', 'target_user', 'target_user_name', 'target_user_email',
            'folder', 'folder_name', 'folder_path', 'permission',
            'is_expired', 'is_active', 'created_at', 'expires_at', 'updated_at'
        ]
        read_only_fields = ['id', 'owner', 'created_at', 'updated_at']
    
    def to_representation(self, instance):
        """Apply role-based filtering to output fields."""
        data = super().to_representation(instance)
        request = self.context.get('request')
        
        if request and request.user.is_authenticated:
            user_role = getattr(request.user, 'role', 'user')
            
            # Public users can only see shares they are involved in
            if user_role == 'user':
                if instance.owner != request.user and instance.target_user != request.user:
                    # Filter out sensitive fields for non-involved users
                    filtered_fields = ['id', 'folder_name', 'created_at']
                    data = {k: v for k, v in data.items() if k in filtered_fields}
                    
            # Admins get all fields (no filtering)
        
        return data
    
    def validate(self, data):
        """Validate share creation with enhanced security checks."""
        owner = self.context['request'].user
        target_user = data.get('target_user')
        folder = data.get('folder')
        
        # Validate owner
        if owner == target_user:
            raise serializers.ValidationError("Cannot share folder with yourself")
        
        # Validate folder ownership
        if folder and folder.user != owner:
            raise serializers.ValidationError("Can only share folders you own")
        
        # Security: Check if target user exists and is active
        if target_user and not target_user.is_active:
            raise serializers.ValidationError("Cannot share with inactive user")
        
        # Security: Validate expiration date
        expires_at = data.get('expires_at')
        if expires_at and expires_at <= timezone.now():
            raise serializers.ValidationError("Expiration date must be in the future")
        
        return data
    
    def create(self, validated_data):
        """Create share with owner assignment and proper error handling."""
        try:
            validated_data['owner'] = self.context['request'].user
            return super().create(validated_data)
        except Exception as e:
            logging.getLogger(__name__).error(f"Error creating share: {str(e)}")
            raise serializers.ValidationError(f"Failed to create share: {str(e)}")


class SharedFolderSerializer(serializers.ModelSerializer):
    """
    Serializer for folders shared with user with role-based filtering.
    """
    
    owner_name = serializers.CharField(source='user.full_name', read_only=True)
    owner_email = serializers.CharField(source='user.email', read_only=True)
    permission = serializers.SerializerMethodField()
    shared_at = serializers.SerializerMethodField()
    expires_at = serializers.SerializerMethodField()
    file_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Folder
        fields = [
            'id', 'name', 'full_path', 'owner_name', 'owner_email', 'permission',
            'shared_at', 'expires_at', 'file_count', 'created_at'
        ]
        read_only_fields = ['id', 'name', 'full_path', 'created_at']
    
    def get_permission(self, obj):
        """Get user's permission for this folder."""
        try:
            user = self.context['request'].user
            share = obj.shares.filter(
                target_user=user
            ).filter(
                expires_at__gt=timezone.now()
            ).first()
            return share.permission if share else None
        except Exception as e:
            logging.getLogger(__name__).error(f"Error getting permission: {str(e)}")
            return None
    
    def get_shared_at(self, obj):
        """Get when folder was shared."""
        try:
            user = self.context['request'].user
            share = obj.shares.filter(target_user=user).first()
            return share.created_at if share else None
        except Exception as e:
            logging.getLogger(__name__).error(f"Error getting shared_at: {str(e)}")
            return None
    
    def get_expires_at(self, obj):
        """Get when share expires."""
        try:
            user = self.context['request'].user
            share = obj.shares.filter(target_user=user).first()
            return share.expires_at if share else None
        except Exception as e:
            logging.getLogger(__name__).error(f"Error getting expires_at: {str(e)}")
            return None
    
    def get_file_count(self, obj):
        """Get number of files in this folder."""
        try:
            return obj.files.filter(deleted_at__isnull=True).count()
        except Exception as e:
            logging.getLogger(__name__).error(f"Error getting file count: {str(e)}")
            return 0
    
    def to_representation(self, instance):
        """Apply role-based filtering to output fields."""
        data = super().to_representation(instance)
        request = self.context.get('request')
        
        if request and request.user.is_authenticated:
            user_role = getattr(request.user, 'role', 'user')
            
            # Public users can only see folders shared with them
            if user_role == 'user':
                # Verify user has access to this shared folder
                has_access = instance.shares.filter(
                    target_user=request.user,
                    expires_at__gt=timezone.now()
                ).exists()
                
                if not has_access:
                    # Filter out sensitive fields for non-accessible folders
                    filtered_fields = ['id', 'name', 'created_at']
                    data = {k: v for k, v in data.items() if k in filtered_fields}
                    
            # Admins get all fields (no filtering)
        
        return data


class FileFavoriteSerializer(serializers.ModelSerializer):
    """
    Serializer for toggling file favorites with role-based filtering.
    """
    
    file_name = serializers.CharField(source='name', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    folder_name = serializers.CharField(source='folder.name', read_only=True)
    
    class Meta:
        model = File
        fields = ['id', 'file_name', 'user_email', 'folder_name', 'is_favorite']
        read_only_fields = ['id', 'file_name', 'user_email', 'folder_name']
    
    def to_representation(self, instance):
        """Apply role-based filtering to output fields."""
        data = super().to_representation(instance)
        request = self.context.get('request')
        
        if request and request.user.is_authenticated:
            user_role = getattr(request.user, 'role', 'user')
            
            # Public users can only modify favorites for their own files
            if user_role == 'user' and instance.user != request.user:
                # Users cannot see or modify other users' file favorites
                filtered_fields = ['id', 'file_name']
                data = {k: v for k, v in data.items() if k in filtered_fields}
                    
            # Admins get all fields (no filtering)
        
        return data
    
    def validate(self, data):
        """Validate favorite toggle with security checks."""
        request = self.context.get('request')
        
        # Security: Users can only toggle favorites for their own files
        if self.instance and self.instance.user != request.user:
            user_role = getattr(request.user, 'role', 'user')
            if user_role != 'admin':
                raise serializers.ValidationError("You can only modify favorites for your own files")
        
        return data
