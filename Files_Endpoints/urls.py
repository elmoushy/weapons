"""
URL configuration for Files_Endpoints app.

This module defines the URL patterns for file management, folder operations,
sharing, and quota management endpoints.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    # Quota views
    UserQuotaView,
    AdminUserQuotaView,
    
    # File views
    FileListView,
    FileUploadView,
    FileDetailView,
    FileDownloadView,
    FileFavoriteToggleView,
    
    # Folder views
    FolderListCreateView,
    FolderDetailView,
    FolderUploadView,
    FolderDownloadView,
    
    # Sharing views
    FolderShareView,
    SharedFoldersView,
    
    # User views
    UserListView,
)

app_name = 'files'

urlpatterns = [
    # Quota endpoints
    path('quota/', UserQuotaView.as_view(), name='user-quota'),
    
    # File endpoints
    path('files/', FileListView.as_view(), name='file-list'),
    path('files/upload/', FileUploadView.as_view(), name='file-upload'),
    path('files/<uuid:id>/', FileDetailView.as_view(), name='file-detail'),
    path('files/<uuid:file_id>/download/', FileDownloadView.as_view(), name='file-download'),
    path('files/<uuid:file_id>/favorite/', FileFavoriteToggleView.as_view(), name='file-favorite'),
    
    # Folder endpoints
    path('folders/', FolderListCreateView.as_view(), name='folder-list-create'),
    path('folders/<uuid:id>/', FolderDetailView.as_view(), name='folder-detail'),
    path('folders/<uuid:folder_id>/upload/', FolderUploadView.as_view(), name='folder-upload'),
    path('folders/<uuid:folder_id>/download/', FolderDownloadView.as_view(), name='folder-download'),
    path('folders/<uuid:folder_id>/download-zip/', FolderDownloadView.as_view(), name='folder-download-zip'),
    path('folders/<uuid:folder_id>/share/', FolderShareView.as_view(), name='folder-share'),
    
    # Shared folders
    path('shared/', SharedFoldersView.as_view(), name='shared-folders'),
    
    # Users for sharing
    path('users/list/', UserListView.as_view(), name='user-list'),
    
    # Admin endpoints
    path('admin/users/<int:user_id>/quota/', AdminUserQuotaView.as_view(), name='admin-user-quota'),
]
