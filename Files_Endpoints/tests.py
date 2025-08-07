"""
Tests for Files_Endpoints functionality.

This module contains tests for file management, folder operations,
sharing, and quota management.
"""

import uuid
import io
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework.test import APITestCase
from rest_framework import status
from unittest.mock import patch

from .models import File, Folder, Share, UserQuota


User = get_user_model()


class FilesEndpointsTestCase(APITestCase):
    """Base test case for Files endpoints."""
    
    def setUp(self):
        """Set up test data."""
        self.user1 = User.objects.create_user(
            username='testuser1',
            email='test1@example.com',
            first_name='Test',
            last_name='User1'
        )
        self.user2 = User.objects.create_user(
            username='testuser2',
            email='test2@example.com',
            first_name='Test',
            last_name='User2'
        )
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            role='admin'
        )
        
        # Create test folder
        self.folder = Folder.objects.create(
            user=self.user1,
            name='Test Folder'
        )
        
        # Create test file data
        self.test_file_content = b'Test file content for unit testing'
        self.test_file = File.objects.create(
            user=self.user1,
            folder=self.folder,
            name='test.txt',
            mime_type='text/plain',
            size_bytes=len(self.test_file_content),
            data_blob=self.test_file_content
        )


class UserQuotaTestCase(FilesEndpointsTestCase):
    """Test cases for user quota management."""
    
    def test_quota_creation(self):
        """Test automatic quota creation for new users."""
        quota, created = UserQuota.objects.get_or_create(user=self.user1)
        self.assertTrue(created)
        self.assertEqual(quota.limit_bytes, 107374182400)  # 100 GB
        self.assertEqual(quota.used_bytes, 0)
    
    def test_quota_usage_calculation(self):
        """Test quota usage is updated when files are uploaded."""
        quota = UserQuota.objects.get(user=self.user1)
        self.assertEqual(quota.used_bytes, len(self.test_file_content))
    
    def test_quota_check(self):
        """Test quota checking for uploads."""
        quota = UserQuota.objects.get(user=self.user1)
        
        # Should be able to upload small file
        self.assertTrue(quota.can_upload(1024))
        
        # Should not be able to upload file larger than limit
        self.assertFalse(quota.can_upload(quota.limit_bytes + 1))
    
    def test_get_quota_endpoint(self):
        """Test GET /api/files/quota/ endpoint."""
        self.client.force_authenticate(user=self.user1)
        url = reverse('files:user-quota')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 200)
        self.assertIn('data', response.data)
        self.assertIn('used_bytes', response.data['data'])
        self.assertIn('limit_bytes', response.data['data'])
    
    def test_admin_update_quota(self):
        """Test admin can update user quotas."""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('files:admin-user-quota', kwargs={'user_id': self.user1.id})
        
        data = {'limit_gb': 200}
        response = self.client.patch(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        quota = UserQuota.objects.get(user=self.user1)
        self.assertEqual(quota.limit_bytes, 200 * 1024**3)


class FileManagementTestCase(FilesEndpointsTestCase):
    """Test cases for file management operations."""
    
    def test_file_upload(self):
        """Test file upload functionality."""
        self.client.force_authenticate(user=self.user1)
        url = reverse('files:file-upload')
        
        file_content = b'Test upload content'
        uploaded_file = SimpleUploadedFile(
            'test_upload.txt',
            file_content,
            content_type='text/plain'
        )
        
        data = {
            'files': uploaded_file,
            'folder_id': str(self.folder.id)
        }
        response = self.client.post(url, data, format='multipart')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['status'], 201)
        self.assertIn('uploaded_files', response.data['data'])
    
    def test_file_list(self):
        """Test file listing with different scopes."""
        self.client.force_authenticate(user=self.user1)
        url = reverse('files:file-list')
        
        # Test 'my' scope
        response = self.client.get(url, {'scope': 'my'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['data']['results']), 1)
        
        # Test 'recent' scope
        response = self.client.get(url, {'scope': 'recent'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_file_download(self):
        """Test file download functionality."""
        self.client.force_authenticate(user=self.user1)
        url = reverse('files:file-download', kwargs={'file_id': self.test_file.id})
        
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, self.test_file_content)
        self.assertEqual(response['Content-Type'], 'text/plain')
    
    def test_file_favorite_toggle(self):
        """Test toggling file favorite status."""
        self.client.force_authenticate(user=self.user1)
        url = reverse('files:file-favorite', kwargs={'file_id': self.test_file.id})
        
        # Toggle to favorite
        response = self.client.patch(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        self.test_file.refresh_from_db()
        self.assertTrue(self.test_file.is_favorite)
        
        # Toggle back
        response = self.client.patch(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        self.test_file.refresh_from_db()
        self.assertFalse(self.test_file.is_favorite)
    
    def test_file_deletion(self):
        """Test file soft deletion."""
        self.client.force_authenticate(user=self.user1)
        url = reverse('files:file-detail', kwargs={'id': self.test_file.id})
        
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        self.test_file.refresh_from_db()
        self.assertIsNotNone(self.test_file.deleted_at)


class FolderManagementTestCase(FilesEndpointsTestCase):
    """Test cases for folder management operations."""
    
    def test_folder_creation(self):
        """Test folder creation."""
        self.client.force_authenticate(user=self.user1)
        url = reverse('files:folder-list-create')
        
        data = {
            'name': 'New Test Folder',
            'parent': str(self.folder.id)
        }
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['status'], 201)
        
        # Check folder was created
        new_folder = Folder.objects.get(name='New Test Folder')
        self.assertEqual(new_folder.user, self.user1)
        self.assertEqual(new_folder.parent, self.folder)
    
    def test_folder_list(self):
        """Test folder listing."""
        self.client.force_authenticate(user=self.user1)
        url = reverse('files:folder-list-create')
        
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 200)
        self.assertEqual(len(response.data['data']['results']), 1)
    
    def test_folder_upload(self):
        """Test uploading files to a folder."""
        self.client.force_authenticate(user=self.user1)
        url = reverse('files:folder-upload', kwargs={'folder_id': self.folder.id})
        
        file_content = b'Folder upload test'
        uploaded_file = SimpleUploadedFile(
            'folder_test.txt',
            file_content,
            content_type='text/plain'
        )
        
        data = {'files': uploaded_file}
        response = self.client.post(url, data, format='multipart')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('uploaded_files', response.data['data'])
    
    def test_folder_download_zip(self):
        """Test downloading folder as ZIP."""
        self.client.force_authenticate(user=self.user1)
        url = reverse('files:folder-download', kwargs={'folder_id': self.folder.id})
        
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Type'], 'application/zip')
        self.assertIn('attachment', response['Content-Disposition'])


class SharingTestCase(FilesEndpointsTestCase):
    """Test cases for folder sharing functionality."""
    
    def test_folder_sharing(self):
        """Test sharing a folder with another user."""
        self.client.force_authenticate(user=self.user1)
        url = reverse('files:folder-share', kwargs={'folder_id': self.folder.id})
        
        data = {
            'target_user': self.user2.id,
            'permission': 'download_only',
            'expires_at': (timezone.now() + timezone.timedelta(days=30)).isoformat()
        }
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Check share was created
        share = Share.objects.get(folder=self.folder, target_user=self.user2)
        self.assertEqual(share.permission, 'download_only')
        self.assertEqual(share.owner, self.user1)
    
    def test_shared_folders_list(self):
        """Test listing folders shared with user."""
        # Create a share
        Share.objects.create(
            owner=self.user1,
            target_user=self.user2,
            folder=self.folder,
            permission='can_upload'
        )
        
        self.client.force_authenticate(user=self.user2)
        url = reverse('files:shared-folders')
        
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['data']['results']), 1)
    
    def test_shared_folder_access(self):
        """Test accessing shared folder content."""
        # Create a share with upload permission
        Share.objects.create(
            owner=self.user1,
            target_user=self.user2,
            folder=self.folder,
            permission='can_upload'
        )
        
        # User2 should be able to upload to shared folder
        self.client.force_authenticate(user=self.user2)
        url = reverse('files:folder-upload', kwargs={'folder_id': self.folder.id})
        
        file_content = b'Shared folder upload'
        uploaded_file = SimpleUploadedFile(
            'shared_test.txt',
            file_content,
            content_type='text/plain'
        )
        
        data = {'files': uploaded_file}
        response = self.client.post(url, data, format='multipart')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
    
    def test_download_only_permission(self):
        """Test download-only permission restrictions."""
        # Create a share with download-only permission
        Share.objects.create(
            owner=self.user1,
            target_user=self.user2,
            folder=self.folder,
            permission='download_only'
        )
        
        # User2 should NOT be able to upload
        self.client.force_authenticate(user=self.user2)
        url = reverse('files:folder-upload', kwargs={'folder_id': self.folder.id})
        
        file_content = b'Should not work'
        uploaded_file = SimpleUploadedFile(
            'restricted.txt',
            file_content,
            content_type='text/plain'
        )
        
        data = {'files': uploaded_file}
        response = self.client.post(url, data, format='multipart')
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        # But should be able to download
        download_url = reverse('files:folder-download', kwargs={'folder_id': self.folder.id})
        response = self.client.get(download_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class SecurityTestCase(FilesEndpointsTestCase):
    """Test cases for security and access control."""
    
    def test_unauthorized_file_access(self):
        """Test that users cannot access files they don't own."""
        self.client.force_authenticate(user=self.user2)
        url = reverse('files:file-detail', kwargs={'id': self.test_file.id})
        
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
    
    def test_unauthorized_folder_access(self):
        """Test that users cannot access folders they don't own."""
        self.client.force_authenticate(user=self.user2)
        url = reverse('files:folder-detail', kwargs={'id': self.folder.id})
        
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
    
    def test_quota_enforcement(self):
        """Test that quota limits are enforced."""
        # Set very low quota
        quota = UserQuota.objects.get(user=self.user1)
        quota.limit_bytes = 10  # 10 bytes
        quota.save()
        
        self.client.force_authenticate(user=self.user1)
        url = reverse('files:file-upload')
        
        large_file = SimpleUploadedFile(
            'large.txt',
            b'This file is larger than 10 bytes',
            content_type='text/plain'
        )
        
        data = {'files': large_file}
        response = self.client.post(url, data, format='multipart')
        
        self.assertEqual(response.status_code, status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
    
    def test_file_type_restrictions(self):
        """Test file type restrictions."""
        self.client.force_authenticate(user=self.user1)
        url = reverse('files:file-upload')
        
        # Try to upload a potentially dangerous file type
        dangerous_file = SimpleUploadedFile(
            'malicious.exe',
            b'Potentially dangerous content',
            content_type='application/x-executable'
        )
        
        data = {'files': dangerous_file}
        response = self.client.post(url, data, format='multipart')
        
        # Should be rejected by security middleware
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class ModelTestCase(FilesEndpointsTestCase):
    """Test cases for model functionality."""
    
    def test_folder_full_path(self):
        """Test folder full path calculation."""
        subfolder = Folder.objects.create(
            user=self.user1,
            parent=self.folder,
            name='Subfolder'
        )
        
        self.assertEqual(self.folder.full_path, 'Test Folder')
        self.assertEqual(subfolder.full_path, 'Test Folder/Subfolder')
    
    def test_file_size_human(self):
        """Test human-readable file size formatting."""
        # Test bytes
        small_file = File.objects.create(
            user=self.user1,
            name='small.txt',
            mime_type='text/plain',
            size_bytes=500,
            data_blob=b'x' * 500
        )
        self.assertTrue(small_file.size_human.endswith('B'))
        
        # Test KB
        kb_file = File.objects.create(
            user=self.user1,
            name='kb.txt',
            mime_type='text/plain',
            size_bytes=2048,
            data_blob=b'x' * 2048
        )
        self.assertTrue(kb_file.size_human.endswith('KB'))
    
    def test_share_expiration(self):
        """Test share expiration functionality."""
        # Create expired share
        expired_share = Share.objects.create(
            owner=self.user1,
            target_user=self.user2,
            folder=self.folder,
            permission='download_only',
            expires_at=timezone.now() - timezone.timedelta(days=1)
        )
        
        self.assertTrue(expired_share.is_expired)
        self.assertFalse(expired_share.is_active)
        
        # Create active share
        active_share = Share.objects.create(
            owner=self.user1,
            target_user=self.user2,
            folder=self.folder,
            permission='download_only',
            expires_at=timezone.now() + timezone.timedelta(days=1)
        )
        
        self.assertFalse(active_share.is_expired)
        self.assertTrue(active_share.is_active)
    
    def test_soft_delete_cascade(self):
        """Test that soft deleting folder cascades to files."""
        initial_file_count = File.objects.filter(deleted_at__isnull=True).count()
        
        self.folder.soft_delete()
        
        # Folder should be soft deleted
        self.folder.refresh_from_db()
        self.assertIsNotNone(self.folder.deleted_at)
        
        # File should also be soft deleted
        self.test_file.refresh_from_db()
        self.assertIsNotNone(self.test_file.deleted_at)
        
        # Count should decrease
        final_file_count = File.objects.filter(deleted_at__isnull=True).count()
        self.assertEqual(final_file_count, initial_file_count - 1)
