"""
Views for Files management endpoints.

This module provides REST API views for managing files, folders, sharing,
and quotas with role-based access control and security features.
"""

import io
import logging
import zipfile
from django.shortcuts import get_object_or_404
from django.db.models import Q, Sum
from django.utils import timezone
from django.http import HttpResponse, JsonResponse
from django.contrib.auth import get_user_model
from rest_framework import status, generics, filters
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django_filters.rest_framework import DjangoFilterBackend

from .models import File, Folder, Share, UserQuota
from .serializers import (
    FileSerializer, FileUploadSerializer, FolderSerializer, ShareSerializer,
    UserQuotaSerializer, UserSummarySerializer, SharedFolderSerializer,
    FileFavoriteSerializer
)
from .permissions import IsOwnerOrShared, IsOwner, IsAdminUser, CanUploadToFolder, HasQuotaSpace


logger = logging.getLogger(__name__)
User = get_user_model()


# Quota Management Views
class UserQuotaView(APIView):
    """
    Get current user's quota usage and limit.
    
    GET: Returns quota information for authenticated user
    """
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get user quota information."""
        quota, created = UserQuota.objects.get_or_create(user=request.user)
        serializer = UserQuotaSerializer(quota)
        
        return Response({
            'status': 200,
            'message': 'Quota information retrieved successfully',
            'data': serializer.data
        })


class AdminUserQuotaView(APIView):
    """
    Admin endpoint to manage user quotas.
    
    PATCH: Update a user's quota limit (admin only)
    """
    
    permission_classes = [IsAdminUser]
    
    def patch(self, request, user_id):
        """Update user quota limit."""
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({
                'status': 404,
                'message': 'User not found',
                'data': {}
            }, status=status.HTTP_404_NOT_FOUND)
        
        quota, created = UserQuota.objects.get_or_create(user=user)
        
        # Handle limit_gb parameter
        if 'limit_gb' in request.data:
            limit_gb = request.data['limit_gb']
            try:
                limit_bytes = int(float(limit_gb) * 1024**3)
                quota.limit_bytes = limit_bytes
            except (ValueError, TypeError):
                return Response({
                    'status': 400,
                    'message': 'Invalid limit_gb value',
                    'data': {}
                }, status=status.HTTP_400_BAD_REQUEST)
        
        # Handle limit_bytes parameter
        if 'limit_bytes' in request.data:
            try:
                quota.limit_bytes = int(request.data['limit_bytes'])
            except (ValueError, TypeError):
                return Response({
                    'status': 400,
                    'message': 'Invalid limit_bytes value',
                    'data': {}
                }, status=status.HTTP_400_BAD_REQUEST)
        
        quota.save()
        serializer = UserQuotaSerializer(quota)
        
        logger.info(f"Admin {request.user.email} updated quota for {user.email}")
        
        return Response({
            'status': 200,
            'message': 'User quota updated successfully',
            'data': serializer.data
        })


# File Management Views
class FileListView(generics.ListAPIView):
    """
    List user's files with filtering and search capabilities.
    
    GET: Returns paginated list of user's files based on scope and filters
    """
    
    serializer_class = FileSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['folder', 'mime_type', 'is_favorite']
    search_fields = ['name']
    ordering_fields = ['uploaded_at', 'name', 'size_bytes']
    ordering = ['-uploaded_at']
    
    def get_queryset(self):
        """Get filtered queryset based on scope and filters."""
        user = self.request.user
        scope = self.request.query_params.get('scope', 'my')
        
        if scope == 'my':
            # User's own files
            queryset = File.objects.filter(user=user, deleted_at__isnull=True)
        
        elif scope == 'shared':
            # Files in folders shared with user
            shared_folders = Folder.objects.filter(
                shares__target_user=user,
                deleted_at__isnull=True
            ).filter(
                Q(shares__expires_at__isnull=True) | Q(shares__expires_at__gt=timezone.now())
            )
            queryset = File.objects.filter(
                folder__in=shared_folders,
                deleted_at__isnull=True
            )
        
        elif scope == 'recent':
            # Recent files (max 3 by default) - don't slice here, let pagination handle it
            queryset = File.objects.filter(
                user=user,
                deleted_at__isnull=True
            )
            # Store the limit for later use in list method
            self._recent_limit = int(self.request.query_params.get('limit', 3))
        
        else:
            # Default to user's files
            queryset = File.objects.filter(user=user, deleted_at__isnull=True)
        
        # Apply additional filters
        name_filter = self.request.query_params.get('name')
        if name_filter:
            queryset = queryset.filter(name__icontains=name_filter)
        
        type_filter = self.request.query_params.get('type')
        if type_filter:
            queryset = queryset.filter(mime_type__icontains=type_filter)
        
        # Size filters
        size_min = self.request.query_params.get('size_min')
        if size_min:
            try:
                queryset = queryset.filter(size_bytes__gte=int(size_min))
            except ValueError:
                pass
        
        size_max = self.request.query_params.get('size_max')
        if size_max:
            try:
                queryset = queryset.filter(size_bytes__lte=int(size_max))
            except ValueError:
                pass
        
        # Date filters
        date_from = self.request.query_params.get('date_from')
        if date_from:
            try:
                queryset = queryset.filter(uploaded_at__gte=date_from)
            except ValueError:
                pass
        
        date_to = self.request.query_params.get('date_to')
        if date_to:
            try:
                queryset = queryset.filter(uploaded_at__lte=date_to)
            except ValueError:
                pass
        
        return queryset
    
    def list(self, request, *args, **kwargs):
        """Override list to return custom response format."""
        scope = self.request.query_params.get('scope', 'my')
        queryset = self.filter_queryset(self.get_queryset())
        
        # Handle recent scope limiting after filtering/ordering
        if scope == 'recent' and hasattr(self, '_recent_limit'):
            # For recent scope, if no ordering is specified, default to -uploaded_at
            ordering_param = request.query_params.get('ordering')
            if not ordering_param:
                queryset = queryset.order_by('-uploaded_at')
            # Apply the limit after filtering and ordering
            queryset = queryset[:self._recent_limit]
        
        page = self.paginate_queryset(queryset)
        
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            paginated_response = self.get_paginated_response(serializer.data)
            return Response({
                'status': 200,
                'message': 'Files retrieved successfully',
                'data': paginated_response.data
            })
        
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'status': 200,
            'message': 'Files retrieved successfully',
            'data': {
                'results': serializer.data,
                'count': len(serializer.data)
            }
        })


class FileUploadView(APIView):
    """
    Upload single or multiple files.
    
    POST: Upload files to root or specific folder
    """
    
    permission_classes = [IsAuthenticated, HasQuotaSpace]
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    
    def post(self, request):
        """Handle file upload."""
        folder_id = request.data.get('folder_id')
        folder = None
        
        # Validate folder if specified
        if folder_id:
            try:
                folder = Folder.objects.get(id=folder_id, deleted_at__isnull=True)
                
                # Check if user can upload to this folder
                if folder.user != request.user:
                    # Check share permission
                    shares = Share.objects.filter(
                        target_user=request.user,
                        folder=folder,
                        permission='can_upload'
                    ).filter(
                        Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())
                    )
                    
                    if not shares.exists():
                        return Response({
                            'status': 403,
                            'message': 'Cannot upload to this folder. Insufficient permissions.',
                            'data': {}
                        }, status=status.HTTP_403_FORBIDDEN)
                
            except Folder.DoesNotExist:
                return Response({
                    'status': 404,
                    'message': 'Folder not found',
                    'data': {}
                }, status=status.HTTP_404_NOT_FOUND)
        
        uploaded_files = []
        errors = []
        
        # Handle multiple file uploads
        files = (
            request.FILES.getlist('files')          # what your FE sends
            or request.FILES.getlist('file_data')   # fallback
            or ([request.FILES.get('file')] if request.FILES.get('file') else [])
        )
        
        if not files:
            return Response({
                'status': 400,
                'message': 'No files provided',
                'data': {}
            }, status=status.HTTP_400_BAD_REQUEST)
        
        for uploaded_file in files:
            try:
                # Prepare data for serializer
                payload = {
                    'name': uploaded_file.name,
                    'folder': folder.id if folder else None,  # Pass folder ID, not object
                    'file_data': uploaded_file   # match serializer field
                }
                
                logger.info(f"Attempting to upload file: {uploaded_file.name}, folder: {folder.name if folder else 'root'}")
                
                serializer = FileUploadSerializer(data=payload, context={'request': request})
                
                if serializer.is_valid():
                    file_instance = serializer.save()
                    uploaded_files.append(FileSerializer(file_instance).data)
                    logger.info(f"File uploaded by {request.user.email}: {file_instance.name}")
                else:
                    logger.error(f"Serializer validation failed for {uploaded_file.name}: {serializer.errors}")
                    errors.append({
                        'filename': uploaded_file.name,
                        'errors': serializer.errors
                    })
            
            except Exception as e:
                logger.error(f"File upload error for {uploaded_file.name}: {str(e)}", exc_info=True)
                errors.append({
                    'filename': uploaded_file.name,
                    'errors': {'upload': [str(e)]}
                })
        
        if uploaded_files:
            response_data = {
                'uploaded_files': uploaded_files,
                'errors': errors if errors else []
            }
            
            if errors:
                return Response({
                    'status': 207,  # Multi-status
                    'message': f'{len(uploaded_files)} files uploaded successfully, {len(errors)} failed',
                    'data': response_data
                }, status=status.HTTP_207_MULTI_STATUS)
            else:
                return Response({
                    'status': 201,
                    'message': f'{len(uploaded_files)} files uploaded successfully',
                    'data': response_data
                }, status=status.HTTP_201_CREATED)
        else:
            return Response({
                'status': 400,
                'message': 'All file uploads failed',
                'data': {'errors': errors}
            }, status=status.HTTP_400_BAD_REQUEST)


class FileDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update, or delete a file.
    
    GET: Return file metadata (no binary data)
    PATCH: Update file metadata
    DELETE: Soft delete file
    """
    
    queryset = File.objects.filter(deleted_at__isnull=True)
    serializer_class = FileSerializer
    permission_classes = [IsOwnerOrShared]
    lookup_field = 'id'
    
    def destroy(self, request, *args, **kwargs):
        """Soft delete the file."""
        instance = self.get_object()
        instance.soft_delete()
        
        logger.info(f"File deleted by {request.user.email}: {instance.name}")
        
        return Response({
            'status': 200,
            'message': 'File deleted successfully',
            'data': {}
        })


class FileDownloadView(APIView):
    """
    Download a single file.
    
    GET: Return file binary data with appropriate headers
    """
    
    permission_classes = [IsOwnerOrShared]
    
    def get(self, request, file_id):
        """Download file."""
        try:
            file_obj = File.objects.get(id=file_id, deleted_at__isnull=True)
        except File.DoesNotExist:
            return Response({
                'status': 404,
                'message': 'File not found',
                'data': {}
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Check permissions
        self.check_object_permissions(request, file_obj)
        
        # Create HTTP response with file data
        response = HttpResponse(
            file_obj.data_blob,
            content_type=file_obj.mime_type or 'application/octet-stream'
        )
        response['Content-Disposition'] = f'attachment; filename="{file_obj.name}"'
        response['Content-Length'] = file_obj.size_bytes
        
        logger.info(f"File downloaded by {request.user.email}: {file_obj.name}")
        
        return response


class FileFavoriteToggleView(APIView):
    """
    Toggle file favorite status.
    
    PATCH: Toggle or set favorite status
    """
    
    permission_classes = [IsOwner]
    
    def patch(self, request, file_id):
        """Toggle file favorite status."""
        try:
            file_obj = File.objects.get(id=file_id, user=request.user, deleted_at__isnull=True)
        except File.DoesNotExist:
            return Response({
                'status': 404,
                'message': 'File not found',
                'data': {}
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Handle explicit value or toggle
        if 'is_favorite' in request.data:
            file_obj.is_favorite = bool(request.data['is_favorite'])
        else:
            file_obj.is_favorite = not file_obj.is_favorite
        
        file_obj.save()
        
        serializer = FileFavoriteSerializer(file_obj)
        
        return Response({
            'status': 200,
            'message': f'File {"added to" if file_obj.is_favorite else "removed from"} favorites',
            'data': serializer.data
        })


# Folder Management Views
class FolderListCreateView(generics.ListCreateAPIView):
    """
    List folders or create a new folder.
    
    GET: Returns list of user's folders
    POST: Create new folder
    """
    
    serializer_class = FolderSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['parent']
    search_fields = ['name']
    ordering_fields = ['created_at', 'name']
    ordering = ['name']
    
    def get_queryset(self):
        """Get user's folders."""
        return Folder.objects.filter(user=self.request.user, deleted_at__isnull=True)
    
    def perform_create(self, serializer):
        """Set the user field to the current user."""
        serializer.save(user=self.request.user)
        logger.info(f"Folder created by {self.request.user.email}: {serializer.instance.name}")
    
    def list(self, request, *args, **kwargs):
        """Override list to return custom response format."""
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        
        return Response({
            'status': 200,
            'message': 'Folders retrieved successfully',
            'data': {
                'results': serializer.data,
                'count': len(serializer.data)
            }
        })
    
    def create(self, request, *args, **kwargs):
        """Override create to return custom response format."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        
        return Response({
            'status': 201,
            'message': 'Folder created successfully',
            'data': serializer.data
        }, status=status.HTTP_201_CREATED)


class FolderDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update, or delete a folder.
    
    GET: Return folder details
    PATCH: Update folder
    DELETE: Soft delete folder and contents
    """
    
    queryset = Folder.objects.filter(deleted_at__isnull=True)
    serializer_class = FolderSerializer
    permission_classes = [IsOwnerOrShared]
    lookup_field = 'id'
    
    def destroy(self, request, *args, **kwargs):
        """Soft delete the folder and all its contents."""
        instance = self.get_object()
        instance.soft_delete()
        
        logger.info(f"Folder deleted by {request.user.email}: {instance.name}")
        
        return Response({
            'status': 200,
            'message': 'Folder deleted successfully',
            'data': {}
        })


class FolderUploadView(APIView):
    """
    Upload files to a specific folder.
    
    POST: Upload multiple files to folder
    """
    
    permission_classes = [IsAuthenticated, CanUploadToFolder, HasQuotaSpace]
    parser_classes = [MultiPartParser, FormParser]
    
    def post(self, request, folder_id):
        """Upload files to folder."""
        try:
            folder = Folder.objects.get(id=folder_id, deleted_at__isnull=True)
        except Folder.DoesNotExist:
            return Response({
                'status': 404,
                'message': 'Folder not found',
                'data': {}
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Check permissions through middleware and permissions
        self.check_object_permissions(request, folder)
        
        files = request.FILES.getlist('files') or request.FILES.getlist('file_data')
        if not files:
            return Response({
                'status': 400,
                'message': 'No files provided',
                'data': {}
            }, status=status.HTTP_400_BAD_REQUEST)
        
        uploaded_files = []
        errors = []
        
        for uploaded_file in files:
            try:
                payload = {
                    'name': uploaded_file.name,
                    'folder': folder.id,  # Pass folder ID, not object
                    'file_data': uploaded_file
                }
                
                serializer = FileUploadSerializer(data=payload, context={'request': request})
                
                if serializer.is_valid():
                    file_instance = serializer.save()
                    uploaded_files.append(FileSerializer(file_instance).data)
                else:
                    errors.append({
                        'filename': uploaded_file.name,
                        'errors': serializer.errors
                    })
            
            except Exception as e:
                errors.append({
                    'filename': uploaded_file.name,
                    'errors': {'upload': [str(e)]}
                })
        
        if uploaded_files:
            logger.info(f"{len(uploaded_files)} files uploaded to folder {folder.name} by {request.user.email}")
            
            response_data = {
                'folder': FolderSerializer(folder).data,
                'uploaded_files': uploaded_files,
                'errors': errors if errors else []
            }
            
            return Response({
                'status': 201,
                'message': f'{len(uploaded_files)} files uploaded to folder successfully',
                'data': response_data
            }, status=status.HTTP_201_CREATED)
        else:
            return Response({
                'status': 400,
                'message': 'All file uploads failed',
                'data': {'errors': errors}
            }, status=status.HTTP_400_BAD_REQUEST)


class FolderDownloadView(APIView):
    """
    Download entire folder contents.
    
    GET: Return folder contents as raw files or ZIP
    """
    
    permission_classes = [IsOwnerOrShared]
    
    def get(self, request, folder_id):
        """Download folder contents."""
        try:
            folder = Folder.objects.get(id=folder_id, deleted_at__isnull=True)
        except Folder.DoesNotExist:
            return Response({
                'status': 404,
                'message': 'Folder not found',
                'data': {}
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Check permissions
        self.check_object_permissions(request, folder)
        
        # Get all files in folder and subfolders
        all_files = folder.get_all_files()
        
        if not all_files.exists():
            return Response({
                'status': 404,
                'message': 'No files found in folder',
                'data': {}
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Create ZIP file in memory
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for file_obj in all_files:
                # Create file path in ZIP
                if file_obj.folder:
                    # Get relative path from the downloaded folder
                    relative_path = file_obj.folder.full_path
                    if relative_path.startswith(folder.full_path):
                        relative_path = relative_path[len(folder.full_path):].lstrip('/')
                    file_path = f"{relative_path}/{file_obj.name}" if relative_path else file_obj.name
                else:
                    file_path = file_obj.name
                
                # Add file to ZIP
                zip_file.writestr(file_path, file_obj.data_blob)
        
        zip_buffer.seek(0)
        
        # Create response
        response = HttpResponse(
            zip_buffer.read(),
            content_type='application/zip'
        )
        response['Content-Disposition'] = f'attachment; filename="{folder.name}.zip"'
        
        logger.info(f"Folder downloaded by {request.user.email}: {folder.name}")
        
        return response


# Sharing Views
class FolderShareView(APIView):
    """
    Share a folder with another user.
    
    POST: Create new share
    """
    
    permission_classes = [IsOwner]
    
    def post(self, request, folder_id):
        """Share folder with user."""
        try:
            folder = Folder.objects.get(id=folder_id, user=request.user, deleted_at__isnull=True)
        except Folder.DoesNotExist:
            return Response({
                'status': 404,
                'message': 'Folder not found or you do not own it',
                'data': {}
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Prepare data for serializer
        share_data = request.data.copy()
        share_data['folder'] = folder.id
        
        serializer = ShareSerializer(data=share_data, context={'request': request})
        
        if serializer.is_valid():
            share = serializer.save()
            
            logger.info(
                f"Folder shared by {request.user.email}: {folder.name} "
                f"with {share.target_user.email} ({share.permission})"
            )
            
            return Response({
                'status': 201,
                'message': 'Folder shared successfully',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)
        
        return Response({
            'status': 400,
            'message': 'Invalid share data',
            'data': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class SharedFoldersView(generics.ListAPIView):
    """
    List folders shared with the current user.
    
    GET: Returns folders shared with user
    """
    
    serializer_class = SharedFolderSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Get folders shared with current user."""
        return Folder.objects.filter(
            shares__target_user=self.request.user,
            deleted_at__isnull=True
        ).filter(
            Q(shares__expires_at__isnull=True) | Q(shares__expires_at__gt=timezone.now())
        ).distinct()
    
    def list(self, request, *args, **kwargs):
        """Override list to return custom response format."""
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        
        return Response({
            'status': 200,
            'message': 'Shared folders retrieved successfully',
            'data': {
                'results': serializer.data,
                'count': len(serializer.data)
            }
        })


# User Management Views
class UserListView(generics.ListAPIView):
    """
    List all application users for sharing.
    
    GET: Returns list of users (id, name, email)
    """
    
    serializer_class = UserSummarySerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['email', 'first_name', 'last_name']
    
    def get_queryset(self):
        """Get all active users except current user."""
        return User.objects.filter(is_active=True).exclude(id=self.request.user.id)
    
    def list(self, request, *args, **kwargs):
        """Override list to return custom response format."""
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        
        return Response({
            'status': 200,
            'message': 'Users retrieved successfully',
            'data': {
                'results': serializer.data,
                'count': len(serializer.data)
            }
        })
