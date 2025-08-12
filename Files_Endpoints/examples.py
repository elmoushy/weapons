"""
Example implementation and usage of Files_Endpoints.

This script demonstrates how to interact with the Files_Endpoints API
and provides example code for common operations.
"""

import json
import base64
from datetime import datetime, timedelta

# Example API responses and request patterns

# 1. Upload a file
def example_file_upload():
    """Example of uploading a file using multipart form data."""
    
    # Using requests library (example)
    """
    import requests
    
    url = "http://localhost:8000/api/files/files/upload/"
    headers = {
        "Authorization": "Bearer your-jwt-token"
    }
    
    # Option 1: Upload file directly
    with open('document.pdf', 'rb') as f:
        files = {'files': f}
        data = {'folder_id': 'folder-uuid-here'}  # optional
        response = requests.post(url, headers=headers, files=files, data=data)
    
    # Option 2: Upload multiple files
    files = [
        ('files', open('file1.pdf', 'rb')),
        ('files', open('file2.jpg', 'rb')),
    ]
    response = requests.post(url, headers=headers, files=files)
    """
    
    # Expected response:
    return {
        "status": 201,
        "message": "2 files uploaded successfully",
        "data": {
            "uploaded_files": [
                {
                    "id": "123e4567-e89b-12d3-a456-426614174000",
                    "name": "document.pdf",
                    "mime_type": "application/pdf",
                    "size_bytes": 1048576,
                    "size_human": "1.0 MB",
                    "folder": None,
                    "folder_name": None,
                    "folder_path": None,
                    "is_favorite": False,
                    "uploaded_at": "2025-07-27T10:00:00Z",
                    "created_at": "2025-07-27T10:00:00Z",
                    "updated_at": "2025-07-27T10:00:00Z"
                }
            ],
            "errors": []
        }
    }

# 2. Create folder structure
def example_folder_creation():
    """Example of creating nested folder structure."""
    
    # Create root folder
    """
    POST /api/files/folders/
    {
        "name": "Projects"
    }
    """
    
    # Create subfolder
    """
    POST /api/files/folders/
    {
        "name": "Website Redesign",
        "parent": "projects-folder-uuid"
    }
    """
    
    return {
        "status": 201,
        "message": "Folder created successfully",
        "data": {
            "id": "folder-uuid",
            "name": "Website Redesign",
            "parent": "projects-folder-uuid",
            "full_path": "Projects/Website Redesign",
            "is_shared": False,
            "file_count": 0,
            "subfolder_count": 0,
            "created_at": "2025-07-27T10:00:00Z",
            "updated_at": "2025-07-27T10:00:00Z"
        }
    }

# 3. Share folder with permissions
def example_folder_sharing():
    """Example of sharing a folder with another user."""
    
    # First, get list of users to share with
    """
    GET /api/files/users/list/?search=jane
    """
    
    users_response = {
        "status": 200,
        "message": "Users retrieved successfully",
        "data": {
            "results": [
                {
                    "id": 42,
                    "email": "jane.smith@company.com",
                    "first_name": "Jane",
                    "last_name": "Smith",
                    "full_name": "Jane Smith"
                }
            ],
            "count": 1
        }
    }
    
    # Share folder with upload permission
    """
    POST /api/files/folders/{folder_id}/share/
    {
        "target_user": 42,
        "permission": "can_upload",
        "expires_at": "2025-12-31T23:59:59Z"
    }
    """
    
    return {
        "status": 201,
        "message": "Folder shared successfully",
        "data": {
            "id": "share-uuid",
            "owner": 1,
            "owner_name": "John Doe",
            "target_user": 42,
            "target_user_name": "Jane Smith",
            "folder": "folder-uuid",
            "folder_name": "Website Redesign",
            "folder_path": "Projects/Website Redesign",
            "permission": "can_upload",
            "is_expired": False,
            "is_active": True,
            "created_at": "2025-07-27T10:00:00Z",
            "expires_at": "2025-12-31T23:59:59Z",
            "updated_at": "2025-07-27T10:00:00Z"
        }
    }

# 4. List files with filtering
def example_file_listing():
    """Example of listing files with various filters."""
    
    # List my recent files
    """
    GET /api/files/files/?scope=recent&limit=5
    """
    
    # List PDF files larger than 1MB
    """
    GET /api/files/files/?type=pdf&size_min=1048576
    """
    
    # List files in specific folder
    """
    GET /api/files/files/?folder=folder-uuid
    """
    
    # List favorite files
    """
    GET /api/files/files/?is_favorite=true
    """
    
    return {
        "status": 200,
        "message": "Files retrieved successfully",
        "data": {
            "count": 15,
            "next": "http://localhost:8000/api/files/files/?page=2",
            "previous": None,
            "results": [
                {
                    "id": "file-uuid",
                    "name": "proposal.pdf",
                    "mime_type": "application/pdf",
                    "size_bytes": 2097152,
                    "size_human": "2.0 MB",
                    "extension": "pdf",
                    "folder": "folder-uuid",
                    "folder_name": "Website Redesign",
                    "folder_path": "Projects/Website Redesign",
                    "is_favorite": True,
                    "uploaded_at": "2025-07-27T10:00:00Z",
                    "created_at": "2025-07-27T10:00:00Z",
                    "updated_at": "2025-07-27T10:00:00Z"
                }
            ]
        }
    }

# 5. Check and manage quota
def example_quota_management():
    """Example of quota management operations."""
    
    # Check current quota
    """
    GET /api/files/quota/
    """
    
    quota_response = {
        "status": 200,
        "message": "Quota information retrieved successfully",
        "data": {
            "limit_bytes": 107374182400,  # 100 GB
            "used_bytes": 21474836480,   # 20 GB
            "used_percent": 20.0,
            "available_bytes": 85899345920,  # 80 GB
            "limit_gb": 100.0,
            "used_gb": 20.0,
            "updated_at": "2025-07-27T10:00:00Z"
        }
    }
    
    # Admin updates user quota
    """
    PATCH /api/files/admin/users/42/quota/
    {
        "limit_gb": 200
    }
    """
    
    return quota_response

# 6. Download operations
def example_downloads():
    """Example of downloading files and folders."""
    
    # Download single file
    """
    GET /api/files/files/{file_id}/download/
    Response: Binary file data with headers:
    Content-Type: application/pdf
    Content-Disposition: attachment; filename="document.pdf"
    Content-Length: 1048576
    """
    
    # Download folder as ZIP
    """
    GET /api/files/folders/{folder_id}/download/
    Response: ZIP file containing all folder contents
    Content-Type: application/zip
    Content-Disposition: attachment; filename="Website Redesign.zip"
    """
    
    return "Binary file data"

# 7. Error handling examples
def example_error_responses():
    """Examples of error responses and handling."""
    
    # Quota exceeded error
    quota_error = {
        "status": 413,
        "message": "Quota exceeded. Available: 5.2 GB, Required: 10.0 GB",
        "data": {
            "quota": {
                "used_bytes": 102005473280,
                "limit_bytes": 107374182400,
                "available_bytes": 5368709120,
                "used_percent": 95.0
            }
        }
    }
    
    # Access denied error
    access_error = {
        "status": 403,
        "message": "Access denied. Folder not shared with you.",
        "data": {}
    }
    
    # File type not allowed error
    filetype_error = {
        "status": 400,
        "message": "File type not allowed: .exe",
        "data": {
            "allowed_extensions": ["pdf", "doc", "docx", "jpg", "png", "zip"]
        }
    }
    
    return {
        "quota_exceeded": quota_error,
        "access_denied": access_error,
        "invalid_filetype": filetype_error
    }

# 8. Frontend integration example
def frontend_integration_example():
    """Example of how to integrate with frontend applications."""
    
    return """
    // React/Vue.js example for file upload with progress
    const uploadFiles = async (files, folderId = null) => {
        const formData = new FormData();
        
        // Add files to form data
        files.forEach(file => {
            formData.append('files', file);
        });
        
        // Add folder ID if specified
        if (folderId) {
            formData.append('folder_id', folderId);
        }
        
        try {
            const response = await fetch('/api/files/files/upload/', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                body: formData
            });
            
            const result = await response.json();
            
            if (result.status === 201) {
                console.log('Upload successful:', result.data.uploaded_files);
                return result.data.uploaded_files;
            } else {
                console.error('Upload failed:', result.message);
                throw new Error(result.message);
            }
        } catch (error) {
            console.error('Upload error:', error);
            throw error;
        }
    };
    
    // Example usage
    const handleFileUpload = async (event) => {
        const files = Array.from(event.target.files);
        const uploadedFiles = await uploadFiles(files, selectedFolderId);
        
        // Update UI with uploaded files
        setUserFiles(prev => [...prev, ...uploadedFiles]);
    };
    
    // Download file example
    const downloadFile = async (fileId, fileName) => {
        try {
            const response = await fetch(`/api/files/files/${fileId}/download/`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = fileName;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
            }
        } catch (error) {
            console.error('Download failed:', error);
        }
    };
    """

# 9. Management command examples
def management_commands_example():
    """Examples of using management commands."""
    
    return """
    # Cleanup old deleted files (older than 30 days)
    python manage.py cleanup_files --days=30
    
    # Dry run to see what would be deleted
    python manage.py cleanup_files --days=30 --dry-run
    
    # Set quota for all admin users to 500 GB
    python manage.py set_user_quotas --role=admin --quota-gb=500
    
    # Set quota for specific user
    python manage.py set_user_quotas --user-email=user@example.com --quota-gb=200
    
    # Preview quota changes without applying them
    python manage.py set_user_quotas --role=manager --quota-gb=250 --dry-run
    """

# 10. Testing examples
def testing_examples():
    """Examples of testing the Files_Endpoints functionality."""
    
    return """
    # Run all tests
    python manage.py test Files_Endpoints
    
    # Run specific test class
    python manage.py test Files_Endpoints.tests.FileManagementTestCase
    
    # Run with coverage
    coverage run --source='.' manage.py test Files_Endpoints
    coverage report
    coverage html
    
    # Example test case
    from django.test import TestCase
    from django.contrib.auth import get_user_model
    from Files_Endpoints.models import File, Folder, UserQuota
    
    class CustomFileTestCase(TestCase):
        def setUp(self):
            User = get_user_model()
            self.user = User.objects.create_user(
                username='testuser',
                email='test@example.com'
            )
            
        def test_file_upload_updates_quota(self):
            # Create a file
            file_data = b'Test file content'
            file = File.objects.create(
                user=self.user,
                name='test.txt',
                mime_type='text/plain',
                size_bytes=len(file_data),
                data_blob=file_data
            )
            
            # Check quota was updated
            quota = UserQuota.objects.get(user=self.user)
            self.assertEqual(quota.used_bytes, len(file_data))
    """

if __name__ == "__main__":
    print("Files_Endpoints API Examples")
    print("="*50)
    
    examples = [
        ("File Upload", example_file_upload),
        ("Folder Creation", example_folder_creation),
        ("Folder Sharing", example_folder_sharing),
        ("File Listing", example_file_listing),
        ("Quota Management", example_quota_management),
        ("Downloads", example_downloads),
        ("Error Responses", example_error_responses),
    ]
    
    for title, func in examples:
        print(f"\n{title}:")
        print("-" * len(title))
        result = func()
        if isinstance(result, dict):
            print(json.dumps(result, indent=2))
        else:
            print(result)
