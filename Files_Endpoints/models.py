"""
Models for Files management system - Google Drive-like functionality.

This module defines the database models for file storage, folder organization,
sharing permissions, and user quotas with BLOB storage support and encryption.
"""

import uuid
import mimetypes
import logging

from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db.models import Sum

from .encryption import files_data_encryption

logger = logging.getLogger(__name__)
User = get_user_model()


class EncryptedTextField(models.TextField):
    """
    Custom text field that automatically encrypts/decrypts data for files
    """
    def from_db_value(self, value, expression, connection):
        if not value:
            return value
        try:
            return files_data_encryption.decrypt(value)
        except Exception as e:
            logger.error(f"Failed to decrypt files text field: {e}")
            return value

    def to_python(self, value):
        if not value:
            return value
        if isinstance(value, str):
            return value
        try:
            return files_data_encryption.decrypt(value)
        except Exception as e:
            logger.error(f"Failed to decrypt files text field in to_python: {e}")
            return value

    def get_prep_value(self, value):
        if not value:
            return value
        try:
            return files_data_encryption.encrypt(value)
        except Exception as e:
            logger.error(f"Failed to encrypt files text field: {e}")
            return value


class EncryptedCharField(models.CharField):
    """
    Custom char field that automatically encrypts/decrypts data for files
    """
    def from_db_value(self, value, expression, connection):
        if not value:
            return value
        try:
            return files_data_encryption.decrypt(value)
        except Exception as e:
            logger.error(f"Failed to decrypt files char field: {e}")
            return value

    def to_python(self, value):
        if not value:
            return value
        if isinstance(value, str):
            return value
        try:
            return files_data_encryption.decrypt(value)
        except Exception as e:
            logger.error(f"Failed to decrypt files char field in to_python: {e}")
            return value

    def get_prep_value(self, value):
        if not value:
            return value
        try:
            return files_data_encryption.encrypt(value)
        except Exception as e:
            logger.error(f"Failed to encrypt files char field: {e}")
            return value


class EncryptedBinaryField(models.BinaryField):
    """
    Custom binary field that automatically encrypts/decrypts binary data for files
    """
    def from_db_value(self, value, expression, connection):
        if not value:
            return value
        try:
            return files_data_encryption.decrypt_binary(value)
        except Exception as e:
            logger.error(f"Failed to decrypt files binary field: {e}")
            return value

    def to_python(self, value):
        if not value:
            return value
        if isinstance(value, (bytes, memoryview)):
            return bytes(value)
        try:
            return files_data_encryption.decrypt_binary(value)
        except Exception as e:
            logger.error(f"Failed to decrypt files binary field in to_python: {e}")
            return value

    def get_prep_value(self, value):
        if not value:
            return value
        try:
            return files_data_encryption.encrypt_binary(value)
        except Exception as e:
            logger.error(f"Failed to encrypt files binary field: {e}")
            return value


class UserQuota(models.Model):
    """
    Model to track user storage quotas and usage.
    """
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name='quota'
    )
    limit_bytes = models.BigIntegerField(
        default=107374182400,  # 100 GB default
        help_text='Storage limit in bytes (default: 100 GB)'
    )
    used_bytes = models.BigIntegerField(
        default=0,
        help_text='Currently used storage in bytes'
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'files_user_quota'
        verbose_name = 'User Quota'
        verbose_name_plural = 'User Quotas'

    def __str__(self):
        return f"{getattr(self.user, 'email', self.user_id)} - {self.used_bytes}/{self.limit_bytes} bytes"

    @property
    def used_percent(self):
        if self.limit_bytes == 0:
            return 0
        return (self.used_bytes / self.limit_bytes) * 100

    @property
    def available_bytes(self):
        return max(0, self.limit_bytes - self.used_bytes)

    def can_upload(self, file_size):
        return self.available_bytes >= file_size

    def update_usage(self):
        total_used = self.user.files.aggregate(total=Sum('size_bytes'))['total'] or 0
        self.used_bytes = total_used
        self.save(update_fields=['used_bytes', 'updated_at'])


class Folder(models.Model):
    """
    Model for organizing files in folders (supports nested structure).
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='folders'
    )
    parent = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='subfolders'
    )
    name = EncryptedCharField(max_length=255, help_text='Folder name (encrypted)')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'files_folder'
        verbose_name = 'Folder'
        verbose_name_plural = 'Folders'
        # IMPORTANT for Oracle: don't add explicit indexes on FK columns (user, parent)
        unique_together = [('user', 'parent', 'name', 'deleted_at')]
        indexes = [
            models.Index(fields=['deleted_at'], name='files_folde_deleted_b26502_idx'),
        ]

    def __str__(self):
        return f"{getattr(self.user, 'email', self.user_id)} - {self.name}"

    def clean(self):
        if self.parent and self.parent.user != self.user:
            raise ValidationError("Parent folder must belong to the same user")

        # Check for circular references
        if self.parent:
            current = self.parent
            while current:
                if current == self:
                    raise ValidationError("Circular folder reference detected")
                current = current.parent

    @property
    def full_path(self):
        if self.parent:
            return f"{self.parent.full_path}/{self.name}"
        return self.name

    @property
    def is_shared(self):
        return self.shares.exists()

    def get_all_files(self):
        from django.db.models import Q

        folder_ids = [self.id]

        def get_descendants(folder):
            descendants = []
            for subfolder in folder.subfolders.filter(deleted_at__isnull=True):
                descendants.append(subfolder.id)
                descendants.extend(get_descendants(subfolder))
            return descendants

        folder_ids.extend(get_descendants(self))

        return File.objects.filter(
            Q(folder_id__in=folder_ids) | Q(folder__isnull=True, user=self.user),
            deleted_at__isnull=True
        )

    def soft_delete(self):
        self.deleted_at = timezone.now()
        self.save()

        for subfolder in self.subfolders.filter(deleted_at__isnull=True):
            subfolder.soft_delete()

        self.files.filter(deleted_at__isnull=True).update(deleted_at=timezone.now())


class File(models.Model):
    """
    Model for storing files with BLOB data in database.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='files'
    )
    folder = models.ForeignKey(
        Folder,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='files'
    )
    name = EncryptedCharField(max_length=255, help_text='Original filename (encrypted)')
    mime_type = models.CharField(max_length=255, help_text='MIME type of the file')
    size_bytes = models.BigIntegerField(help_text='File size in bytes')
    data_blob = EncryptedBinaryField(help_text='Binary file data stored in database (encrypted)')
    is_favorite = models.BooleanField(default=False, help_text='Whether file is marked as favorite')
    uploaded_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'files_file'
        verbose_name = 'File'
        verbose_name_plural = 'Files'
        # IMPORTANT for Oracle: don't add explicit indexes on FK columns (user, folder)
        indexes = [
            models.Index(fields=['uploaded_at'], name='files_file_uploade_726d10_idx'),
            models.Index(fields=['is_favorite'], name='files_file_is_favo_340ec9_idx'),
            models.Index(fields=['deleted_at'], name='files_file_deleted_007431_idx'),
            models.Index(fields=['mime_type'], name='files_file_mime_ty_57dbdc_idx'),
        ]

    def __str__(self):
        return f"{getattr(self.user, 'email', self.user_id)} - {self.name}"

    def clean(self):
        if self.folder and self.folder.user != self.user:
            raise ValidationError("File folder must belong to the same user")

    @property
    def extension(self):
        if '.' in self.name:
            return self.name.rsplit('.', 1)[1].lower()
        return ''

    @property
    def size_human(self):
        """Return human-readable file size without mutating size_bytes."""
        size = float(self.size_bytes or 0)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
            if size < 1024 or unit == 'PB':
                return f"{size:.1f} {unit}"
            size /= 1024.0

    def save(self, *args, **kwargs):
        # Auto-detect MIME type if not provided
        if not self.mime_type and self.name:
            guessed, _ = mimetypes.guess_type(self.name)
            self.mime_type = guessed or 'application/octet-stream'

        is_new = self._state.adding
        old_size = 0

        if not is_new:
            try:
                old_file = File.objects.get(pk=self.pk)
                old_size = old_file.size_bytes
            except File.DoesNotExist:
                is_new = True

        super().save(*args, **kwargs)

        quota, _ = UserQuota.objects.get_or_create(user=self.user)
        if is_new:
            quota.used_bytes += self.size_bytes
        else:
            quota.used_bytes = max(0, quota.used_bytes - old_size + self.size_bytes)
        quota.save(update_fields=['used_bytes', 'updated_at'])

    def soft_delete(self):
        self.deleted_at = timezone.now()
        self.save()
        quota = UserQuota.objects.get(user=self.user)
        quota.used_bytes = max(0, quota.used_bytes - self.size_bytes)
        quota.save(update_fields=['used_bytes', 'updated_at'])


class Share(models.Model):
    """
    Model for sharing folders with other users.
    """
    PERMISSION_CHOICES = [
        ('download_only', 'Download Only'),
        ('can_upload', 'Can Upload'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='owned_shares'
    )
    target_user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='received_shares'
    )
    folder = models.ForeignKey(
        Folder,
        on_delete=models.CASCADE,
        related_name='shares'
    )
    permission = models.CharField(max_length=20, choices=PERMISSION_CHOICES, default='download_only')
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'files_share'
        verbose_name = 'Share'
        verbose_name_plural = 'Shares'
        unique_together = [('owner', 'target_user', 'folder')]
        # IMPORTANT for Oracle: don't add explicit indexes on FK columns (target_user, folder)
        indexes = [
            models.Index(fields=['expires_at'], name='files_share_expires_41f2fd_idx'),
        ]

    def __str__(self):
        owner_email = getattr(self.owner, 'email', self.owner_id)
        target_email = getattr(self.target_user, 'email', self.target_user_id)
        return f"{owner_email} shared {self.folder.name} with {target_email}"

    def clean(self):
        if self.owner == self.target_user:
            raise ValidationError("Cannot share folder with yourself")
        if self.folder.user != self.owner:
            raise ValidationError("Can only share folders you own")

    @property
    def is_expired(self):
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False

    @property
    def is_active(self):
        return not self.is_expired

    def can_download(self):
        return self.is_active

    def can_upload(self):
        return self.is_active and self.permission == 'can_upload'
