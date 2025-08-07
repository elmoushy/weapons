"""
Models for the surveys service with encryption support.

This module defines the database models for surveys, questions, responses,
and sharing with role-based access control and AES-256 encryption.
"""

from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model
from .encryption import surveys_data_encryption
import logging
import uuid

logger = logging.getLogger(__name__)
User = get_user_model()

# Import Group model from authentication app
try:
    from authentication.models import Group
except ImportError:
    # Handle case where authentication app is not available
    Group = None


class EncryptedTextField(models.TextField):
    """Custom text field that automatically encrypts/decrypts data for surveys"""
    
    def from_db_value(self, value, expression, connection):
        if not value:
            return value
        try:
            return surveys_data_encryption.decrypt(value)
        except Exception as e:
            logger.error(f"Failed to decrypt text field: {e}")
            return value
    
    def to_python(self, value):
        if not value:
            return value
        if isinstance(value, str):
            # Always decrypt string values to handle all scenarios
            try:
                return surveys_data_encryption.decrypt(value)
            except Exception as e:
                logger.error(f"Failed to decrypt text field in to_python: {e}")
                return value
        try:
            return surveys_data_encryption.decrypt(value)
        except Exception as e:
            logger.error(f"Failed to decrypt text field in to_python: {e}")
            return value
    
    def get_prep_value(self, value):
        if not value:
            return value
        try:
            return surveys_data_encryption.encrypt(value)
        except Exception as e:
            logger.error(f"Failed to encrypt text field: {e}")
            return value


class EncryptedCharField(models.CharField):
    """Custom char field that automatically encrypts/decrypts data for surveys"""
    
    def from_db_value(self, value, expression, connection):
        if not value:
            return value
        try:
            return surveys_data_encryption.decrypt(value)
        except Exception as e:
            logger.error(f"Failed to decrypt char field: {e}")
            return value
    
    def to_python(self, value):
        if not value:
            return value
        if isinstance(value, str):
            # Always decrypt string values to handle all scenarios
            try:
                return surveys_data_encryption.decrypt(value)
            except Exception as e:
                logger.error(f"Failed to decrypt char field in to_python: {e}")
                return value
        try:
            return surveys_data_encryption.decrypt(value)
        except Exception as e:
            logger.error(f"Failed to decrypt char field in to_python: {e}")
            return value
    
    def get_prep_value(self, value):
        if not value:
            return value
        try:
            return surveys_data_encryption.encrypt(value)
        except Exception as e:
            logger.error(f"Failed to encrypt char field: {e}")
            return value


class Survey(models.Model):
    """
    Main survey model with four visibility levels:
    - PRIVATE: Creator + explicitly shared users only
    - AUTH: Any authenticated user with valid JWT
    - PUBLIC: Anonymous visitors can access
    - GROUPS: Shared with specific groups
    """
    
    VISIBILITY_CHOICES = [
        ("PRIVATE", "Creator & shared list"),
        ("AUTH", "All authenticated users"),
        ("PUBLIC", "Everyone, even anonymous"),
        ("GROUPS", "Shared with specific groups"),
    ]
    
    # Primary fields
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    title = EncryptedCharField(
        max_length=255,
        help_text='Survey title (encrypted)'
    )
    title_hash = models.CharField(
        max_length=64,
        blank=True,
        help_text='SHA256 hash of title for search indexing'
    )
    description = EncryptedTextField(
        blank=True,
        help_text='Survey description (encrypted)'
    )
    
    # Ownership and sharing
    creator = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="created_surveys",
        help_text='User who created this survey'
    )
    visibility = models.CharField(
        max_length=8,
        choices=VISIBILITY_CHOICES,
        default="AUTH",
        help_text='Survey visibility level'
    )
    shared_with = models.ManyToManyField(
        User,
        blank=True,
        related_name="shared_surveys",
        help_text='Users who can access this private survey'
    )
    shared_with_groups = models.ManyToManyField(
        'authentication.Group',
        blank=True,
        related_name="shared_surveys_groups",
        help_text='Groups who can access this survey'
    )
    
    # Survey scheduling
    start_date = models.DateTimeField(
        null=True,
        blank=True,
        help_text='Survey start date/time. If not set, survey starts immediately when created.'
    )
    end_date = models.DateTimeField(
        null=True,
        blank=True,
        help_text='Survey end date/time. If not set, survey runs indefinitely.'
    )
    
    # Survey settings
    is_locked = models.BooleanField(
        default=False,
        help_text='Whether survey is locked for editing'
    )
    is_active = models.BooleanField(
        default=True,
        help_text='Whether survey is active and accepting responses'
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'surveys_survey'
        verbose_name = 'Survey'
        verbose_name_plural = 'Surveys'
        ordering = ['-created_at']
        # Indexes are already created by migrations 0001_initial and 0006_survey_end_date_survey_start_date_and_more
    
    def __str__(self):
        return f"Survey: {self.title} ({self.visibility})"
    
    def soft_delete(self):
        """Soft delete the survey"""
        self.deleted_at = timezone.now()
        self.save()
    
    def is_currently_active(self):
        """Check if survey is currently active based on date range and is_active flag"""
        if not self.is_active or self.deleted_at is not None:
            return False
        
        now = timezone.now()
        
        # Check start date
        if self.start_date and now < self.start_date:
            return False
        
        # Check end date
        if self.end_date and now > self.end_date:
            return False
        
        return True
    
    def get_status(self):
        """Get current status of the survey"""
        if self.deleted_at is not None:
            return 'deleted'
        
        if not self.is_active:
            return 'inactive'
        
        now = timezone.now()
        
        if self.start_date and now < self.start_date:
            return 'scheduled'
        
        if self.end_date and now > self.end_date:
            return 'expired'
        
        return 'active'
    
    def save(self, *args, **kwargs):
        """Override save to generate title hash and handle date logic"""
        if self.title:
            import hashlib
            self.title_hash = hashlib.sha256(self.title.encode()).hexdigest()
        
        # If only end_date is provided, set start_date to created_at (or now if updating)
        if self.end_date and not self.start_date:
            if not self.pk:  # New survey
                self.start_date = timezone.now()
            elif not self.start_date:  # Existing survey without start_date
                self.start_date = self.created_at or timezone.now()
        
        # If no end_date is provided, survey runs indefinitely until deactivated
        # This is handled by the is_currently_active() method which only checks end_date if it exists
        
        super().save(*args, **kwargs)


class Question(models.Model):
    """Survey question with encrypted content"""
    
    QUESTION_TYPES = [
        ('text', 'Text Input'),
        ('textarea', 'Long Text'),
        ('single_choice', 'Single Choice'),
        ('multiple_choice', 'Multiple Choice'),
        ('rating', 'Rating Scale'),
        ('yes_no', 'Yes/No'),
    ]
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    survey = models.ForeignKey(
        Survey,
        on_delete=models.CASCADE,
        related_name='questions'
    )
    text = EncryptedTextField(help_text='Question text (encrypted)')
    text_hash = models.CharField(
        max_length=64,
        blank=True,
        help_text='SHA256 hash of question text for search indexing'
    )
    question_type = models.CharField(
        max_length=20,
        choices=QUESTION_TYPES,
        default='text'
    )
    options = EncryptedTextField(
        blank=True,
        help_text='JSON array of options for choice questions (encrypted)'
    )
    is_required = models.BooleanField(default=False)
    order = models.PositiveIntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'surveys_question'
        verbose_name = 'Question'
        verbose_name_plural = 'Questions'
        ordering = ['survey', 'order']
        # Indexes are already created by migration 0001_initial
    
    def __str__(self):
        return f"Q{self.order}: {self.text[:50]}..."
    
    def save(self, *args, **kwargs):
        """Override save to generate text hash for searching"""
        if self.text:
            import hashlib
            self.text_hash = hashlib.sha256(self.text.encode()).hexdigest()
        super().save(*args, **kwargs)


class Response(models.Model):
    """Survey response with encrypted answers"""
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    survey = models.ForeignKey(
        Survey,
        on_delete=models.CASCADE,
        related_name='responses'
    )
    respondent = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='survey_responses',
        help_text='Null for anonymous responses'
    )
    respondent_email = models.EmailField(
        null=True,
        blank=True,
        help_text='Email for anonymous responses (when respondent is null)'
    )
    
    # Response metadata
    submitted_at = models.DateTimeField(auto_now_add=True)
    is_complete = models.BooleanField(default=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    class Meta:
        db_table = 'surveys_response'
        verbose_name = 'Response'
        verbose_name_plural = 'Responses'
        ordering = ['-submitted_at']
        # Indexes are already created by migrations 0001_initial and 0005_add_unique_response_constraints
        # Note: Oracle doesn't support unique constraints with conditions
        # We'll handle uniqueness validation in the model's clean() method instead
    
    def __str__(self):
        user_info = self.respondent.email if self.respondent else "Anonymous"
        return f"Response to {self.survey.title} by {user_info}"
    
    def clean(self):
        """Custom validation to handle uniqueness constraints that Oracle doesn't support."""
        from django.core.exceptions import ValidationError
        
        # Check for authenticated user duplicate responses
        if self.respondent:
            existing = Response.objects.filter(
                survey=self.survey, 
                respondent=self.respondent
            ).exclude(pk=self.pk)
            if existing.exists():
                raise ValidationError("You have already submitted a response to this survey.")
        
        # Check for anonymous user duplicate responses (same email)
        elif self.respondent_email:
            existing = Response.objects.filter(
                survey=self.survey,
                respondent__isnull=True,
                respondent_email=self.respondent_email
            ).exclude(pk=self.pk)
            if existing.exists():
                raise ValidationError("A response has already been submitted with this email address.")

    def save(self, *args, **kwargs):
        """Override save to call clean validation."""
        self.clean()
        super().save(*args, **kwargs)


class Answer(models.Model):
    """Individual answer to a survey question with encryption"""
    
    id = models.AutoField(primary_key=True)  # Integer PK for better performance
    response = models.ForeignKey(
        Response,
        on_delete=models.CASCADE,
        related_name='answers'
    )
    question = models.ForeignKey(
        Question,
        on_delete=models.CASCADE,
        related_name='answers'
    )
    answer_text = EncryptedTextField(
        help_text='Answer content (encrypted)'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'surveys_answer'
        verbose_name = 'Answer'
        verbose_name_plural = 'Answers'
        unique_together = ['response', 'question']
        # Indexes are already created by migration 0001_initial
    
    def __str__(self):
        return f"Answer to {self.question.text[:30]}..."


class PublicAccessToken(models.Model):
    """
    Public access tokens for surveys to enable anonymous access.
    """
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    survey = models.ForeignKey(
        Survey,
        on_delete=models.CASCADE,
        related_name="public_tokens",
        help_text='Survey this token provides access to'
    )
    token = models.CharField(
        max_length=64,
        unique=True,
        help_text='Unique token string for public access'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(
        help_text='Token expiration date'
    )
    created_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="created_tokens",
        help_text='User who created this token'
    )
    is_active = models.BooleanField(
        default=True,
        help_text='Whether token is active'
    )
    
    class Meta:
        db_table = 'surveys_public_access_token'
        verbose_name = 'Public Access Token'
        verbose_name_plural = 'Public Access Tokens'
        ordering = ['-created_at']
        # Indexes are already created by migration 0002_publicaccesstoken
    
    def __str__(self):
        return f"Token for {self.survey.title} (expires {self.expires_at})"
    
    def is_expired(self):
        """Check if token is expired"""
        return timezone.now() > self.expires_at
    
    def is_valid(self):
        """Check if token is valid (active and not expired)"""
        return self.is_active and not self.is_expired()
    
    @classmethod
    def generate_token(cls):
        """Generate a unique token string"""
        import secrets
        return secrets.token_urlsafe(32)
