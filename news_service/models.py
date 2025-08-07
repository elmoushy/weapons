"""
Models for the news service with encryption support
"""
from django.db import models
from django.utils import timezone
from django.core.validators import FileExtensionValidator
from django.contrib.auth import get_user_model
from .encryption import data_encryption
from .image_utils import ImageCompressor
import logging

logger = logging.getLogger(__name__)
User = get_user_model()


class EncryptedTextField(models.TextField):
    """
    Custom text field that automatically encrypts/decrypts data
    """
    
    def from_db_value(self, value, expression, connection):
        if not value:
            return value
        try:
            return data_encryption.decrypt(value)
        except Exception as e:
            logger.error(f"Failed to decrypt text field: {e}")
            return value
    
    def to_python(self, value):
        if not value:
            return value
        if isinstance(value, str):
            return value
        try:
            return data_encryption.decrypt(value)
        except Exception as e:
            logger.error(f"Failed to decrypt text field in to_python: {e}")
            return value
    
    def get_prep_value(self, value):
        if not value:
            return value
        try:
            return data_encryption.encrypt(value)
        except Exception as e:
            logger.error(f"Failed to encrypt text field: {e}")
            return value


class EncryptedCharField(models.CharField):
    """
    Custom char field that automatically encrypts/decrypts data
    """
    
    def from_db_value(self, value, expression, connection):
        if not value:
            return value
        try:
            return data_encryption.decrypt(value)
        except Exception as e:
            logger.error(f"Failed to decrypt char field: {e}")
            return value
    
    def to_python(self, value):
        if not value:
            return value
        if isinstance(value, str):
            return value
        try:
            return data_encryption.decrypt(value)
        except Exception as e:
            logger.error(f"Failed to decrypt char field in to_python: {e}")
            return value
    
    def get_prep_value(self, value):
        if not value:
            return value
        try:
            return data_encryption.encrypt(value)
        except Exception as e:
            logger.error(f"Failed to encrypt char field: {e}")
            return value


class EncryptedBinaryField(models.BinaryField):
    """
    Custom binary field that automatically encrypts/decrypts binary data (images)
    """
    
    def from_db_value(self, value, expression, connection):
        if not value:
            return value
        try:
            return data_encryption.decrypt_binary(value)
        except Exception as e:
            logger.error(f"Failed to decrypt binary field: {e}")
            return value
    
    def to_python(self, value):
        if not value:
            return value
        if isinstance(value, (bytes, memoryview)):
            return bytes(value)
        try:
            return data_encryption.decrypt_binary(value)
        except Exception as e:
            logger.error(f"Failed to decrypt binary field in to_python: {e}")
            return value
    
    def get_prep_value(self, value):
        if not value:
            return value
        try:
            # Compress image before encryption
            if isinstance(value, bytes):
                compressed_value = ImageCompressor.compress_image(value, 'main_image')
                return data_encryption.encrypt_binary(compressed_value)
            return data_encryption.encrypt_binary(value)
        except Exception as e:
            logger.error(f"Failed to encrypt binary field: {e}")
            return value


class BaseNewsModel(models.Model):
    """
    Abstract base model for all news items
    """
    
    # Encrypted text fields
    title_arabic = EncryptedCharField(
        max_length=500,
        verbose_name="Arabic Title",
        help_text="News title in Arabic"
    )
    title_english = EncryptedCharField(
        max_length=500,
        verbose_name="English Title",
        help_text="News title in English"
    )
    description = EncryptedTextField(
        verbose_name="Description",
        help_text="Detailed description of the news item"
    )
    
    # Main image (encrypted binary)
    main_image = EncryptedBinaryField(
        null=True,
        blank=True,
        verbose_name="Main Image",
        help_text="Primary image for the news item"
    )
    
    # Metadata (not encrypted)
    date = models.DateTimeField(
        default=timezone.now,
        verbose_name="Publication Date"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="%(class)s_created",
        verbose_name="Created By"
    )
    is_active = models.BooleanField(
        default=True,
        verbose_name="Active",
        help_text="Whether this news item is active and visible"
    )
    
    class Meta:
        abstract = True
        ordering = ['-date', '-created_at']
    
    def __str__(self):
        return f"{self.title_english} ({self.title_arabic})"
    
    def save(self, *args, **kwargs):
        """
        Override save to handle image compression and validation
        """
        # Validate and compress main image if provided
        if self.main_image:
            try:
                # Validate image
                is_valid, error_msg = ImageCompressor.validate_image(self.main_image)
                if not is_valid:
                    raise ValueError(f"Invalid main image: {error_msg}")
                
                # Compress image (handled in EncryptedBinaryField)
                logger.info(f"Saving {self.__class__.__name__} with compressed main image")
                
            except Exception as e:
                logger.error(f"Error processing main image: {e}")
                raise
        
        super().save(*args, **kwargs)


class SliderNews(BaseNewsModel):
    """
    Model for slider news items (homepage slider)
    """
    
    # Priority for slider ordering
    priority = models.IntegerField(
        default=0,
        verbose_name="Priority",
        help_text="Higher numbers appear first in slider (0-100)"
    )
    
    # Display duration in seconds
    display_duration = models.IntegerField(
        default=5,
        verbose_name="Display Duration (seconds)",
        help_text="How long to display this slide"
    )
    
    class Meta:
        verbose_name = "Slider News"
        verbose_name_plural = "Slider News"
        ordering = ['-priority', '-date']
    
    def __str__(self):
        return f"Slider: {self.title_english}"


class Achievement(BaseNewsModel):
    """
    Model for achievements and milestones
    """
    
    # Achievement category
    CATEGORY_CHOICES = [
        ('military', 'Military Achievement'),
        ('technology', 'Technology Achievement'),
        ('training', 'Training Achievement'),
        ('partnership', 'Partnership Achievement'),
        ('award', 'Award/Recognition'),
        ('general', 'General Achievement'),
        ('other', 'Other')
    ]
    
    category = models.CharField(
        max_length=20,
        choices=CATEGORY_CHOICES,
        default='other',
        verbose_name="Category"
    )
    
    # Achievement date (separate from publication date)
    achievement_date = models.DateField(
        null=True,
        blank=True,
        verbose_name="Achievement Date",
        help_text="When the achievement occurred"
    )
    
    class Meta:
        verbose_name = "Achievement"
        verbose_name_plural = "Achievements"
        ordering = ['-achievement_date', '-date']
    
    def __str__(self):
        return f"Achievement: {self.title_english}"


class CardsNews(BaseNewsModel):
    """
    Model for cards news (paginated news cards)
    """
    
    # News category
    CATEGORY_CHOICES = [
        ('general', 'General News'),
        ('military', 'Military News'),
        ('technology', 'Technology News'),
        ('training', 'Training News'),
        ('announcement', 'Announcement'),
        ('press_release', 'Press Release'),
        ('event', 'Event'),
        ('other', 'Other')
    ]
    
    category = models.CharField(
        max_length=20,
        choices=CATEGORY_CHOICES,
        default='general',
        verbose_name="Category"
    )
    
    # Featured flag for highlighting important news
    is_featured = models.BooleanField(
        default=False,
        verbose_name="Featured",
        help_text="Mark as featured news"
    )
    
    # View count (not encrypted)
    view_count = models.PositiveIntegerField(
        default=0,
        verbose_name="View Count"
    )
    
    class Meta:
        verbose_name = "Cards News"
        verbose_name_plural = "Cards News"
        ordering = ['-is_featured', '-date']
    
    def __str__(self):
        return f"Card: {self.title_english}"
    
    def increment_view_count(self):
        """Increment view count"""
        self.view_count += 1
        self.save(update_fields=['view_count'])


class NewsImage(models.Model):
    """
    Model for additional images in news items (gallery)
    """
    
    # Foreign keys to news models
    slider_news = models.ForeignKey(
        SliderNews,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='images'
    )
    achievement = models.ForeignKey(
        Achievement,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='images'
    )
    cards_news = models.ForeignKey(
        CardsNews,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='images'
    )
    
    # Encrypted image data
    image_data = EncryptedBinaryField(
        verbose_name="Image Data"
    )
    
    # Image metadata (not encrypted)
    caption = EncryptedCharField(
        max_length=200,
        blank=True,
        verbose_name="Caption"
    )
    alt_text = EncryptedCharField(
        max_length=200,
        blank=True,
        verbose_name="Alt Text"
    )
    order = models.IntegerField(
        default=0,
        verbose_name="Display Order"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['order', 'created_at']
        verbose_name = "News Image"
        verbose_name_plural = "News Images"
    
    def save(self, *args, **kwargs):
        """
        Override save to handle image compression
        """
        if self.image_data:
            try:
                # Validate image
                is_valid, error_msg = ImageCompressor.validate_image(self.image_data)
                if not is_valid:
                    raise ValueError(f"Invalid image: {error_msg}")
                
                logger.info("Saving gallery image with compression")
                
            except Exception as e:
                logger.error(f"Error processing gallery image: {e}")
                raise
        
        super().save(*args, **kwargs)
    
    def __str__(self):
        parent = self.slider_news or self.achievement or self.cards_news
        return f"Image for {parent}" if parent else "Orphaned Image"
