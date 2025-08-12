"""
Django admin configuration for Files_Endpoints models.
"""

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from .models import File, Folder, Share, UserQuota


@admin.register(UserQuota)
class UserQuotaAdmin(admin.ModelAdmin):
    """Admin interface for UserQuota model."""
    
    list_display = ['user_email', 'used_gb', 'limit_gb', 'used_percent_display', 'updated_at']
    list_filter = ['updated_at']
    search_fields = ['user__email', 'user__first_name', 'user__last_name']
    readonly_fields = ['used_bytes', 'used_percent_display', 'updated_at']
    
    def user_email(self, obj):
        """Display user email."""
        return obj.user.email
    user_email.short_description = 'User Email'
    
    def used_gb(self, obj):
        """Display used storage in GB."""
        return f"{obj.used_bytes / (1024**3):.2f} GB"
    used_gb.short_description = 'Used Storage'
    
    def limit_gb(self, obj):
        """Display limit in GB."""
        return f"{obj.limit_bytes / (1024**3):.2f} GB"
    limit_gb.short_description = 'Storage Limit'
    
    def used_percent_display(self, obj):
        """Display usage percentage with color coding."""
        percent = obj.used_percent
        if percent >= 90:
            color = 'red'
        elif percent >= 75:
            color = 'orange'
        else:
            color = 'green'
        
        return format_html(
            '<span style="color: {};">{:.1f}%</span>',
            color,
            percent
        )
    used_percent_display.short_description = 'Usage %'


@admin.register(Folder)
class FolderAdmin(admin.ModelAdmin):
    """Admin interface for Folder model."""
    
    list_display = ['name', 'user_email', 'parent_folder', 'file_count', 'is_shared_display', 'created_at']
    list_filter = ['created_at', 'updated_at', 'deleted_at']
    search_fields = ['name', 'user__email']
    readonly_fields = ['id', 'created_at', 'updated_at', 'full_path', 'file_count', 'is_shared']
    
    def user_email(self, obj):
        """Display user email."""
        return obj.user.email
    user_email.short_description = 'Owner'
    
    def parent_folder(self, obj):
        """Display parent folder name."""
        return obj.parent.name if obj.parent else '-'
    parent_folder.short_description = 'Parent Folder'
    
    def file_count(self, obj):
        """Display number of files in folder."""
        return obj.files.filter(deleted_at__isnull=True).count()
    file_count.short_description = 'Files'
    
    def is_shared_display(self, obj):
        """Display if folder is shared."""
        return '✓' if obj.is_shared else '✗'
    is_shared_display.short_description = 'Shared'
    is_shared_display.boolean = True


@admin.register(File)
class FileAdmin(admin.ModelAdmin):
    """Admin interface for File model."""
    
    list_display = ['name', 'user_email', 'folder_name', 'size_display', 'mime_type', 'is_favorite', 'uploaded_at']
    list_filter = ['mime_type', 'is_favorite', 'uploaded_at', 'deleted_at']
    search_fields = ['name', 'user__email', 'mime_type']
    readonly_fields = ['id', 'size_bytes', 'size_display', 'extension', 'uploaded_at', 'created_at', 'updated_at']
    exclude = ['data_blob']  # Don't show binary data in admin
    
    def user_email(self, obj):
        """Display user email."""
        return obj.user.email
    user_email.short_description = 'Owner'
    
    def folder_name(self, obj):
        """Display folder name."""
        return obj.folder.name if obj.folder else 'Root'
    folder_name.short_description = 'Folder'
    
    def size_display(self, obj):
        """Display file size in human readable format."""
        return obj.size_human
    size_display.short_description = 'Size'
    
    def get_queryset(self, request):
        """Filter out deleted files by default."""
        qs = super().get_queryset(request)
        return qs.filter(deleted_at__isnull=True)


@admin.register(Share)
class ShareAdmin(admin.ModelAdmin):
    """Admin interface for Share model."""
    
    list_display = ['folder_name', 'owner_email', 'target_user_email', 'permission', 'is_active_display', 'created_at', 'expires_at']
    list_filter = ['permission', 'created_at', 'expires_at']
    search_fields = ['folder__name', 'owner__email', 'target_user__email']
    readonly_fields = ['id', 'created_at', 'updated_at', 'is_active']
    
    def folder_name(self, obj):
        """Display folder name."""
        return obj.folder.name
    folder_name.short_description = 'Folder'
    
    def owner_email(self, obj):
        """Display owner email."""
        return obj.owner.email
    owner_email.short_description = 'Owner'
    
    def target_user_email(self, obj):
        """Display target user email."""
        return obj.target_user.email
    target_user_email.short_description = 'Shared With'
    
    def is_active_display(self, obj):
        """Display if share is currently active."""
        return '✓' if obj.is_active else '✗'
    is_active_display.short_description = 'Active'
    is_active_display.boolean = True
