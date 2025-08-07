"""
Serializers for the news service with role-based field filtering
"""
import base64
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import SliderNews, Achievement, CardsNews, NewsImage
from .image_utils import ImageCompressor
import logging

logger = logging.getLogger(__name__)
User = get_user_model()


class Base64ImageField(serializers.Field):
    """
    Custom field to handle base64 encoded images
    """
    
    def to_representation(self, value):
        """
        Convert binary image data to base64 for API response
        """
        if not value:
            return None
        
        try:
            # Value is already decrypted by the model field
            if isinstance(value, (bytes, memoryview)):
                return base64.b64encode(bytes(value)).decode('utf-8')
            return value
        except Exception as e:
            logger.error(f"Error converting image to base64: {e}")
            return None
    
    def to_internal_value(self, data):
        """
        Convert base64 data to binary for storage
        """
        if not data:
            return None
        
        try:
            # Handle data URL format (data:image/jpeg;base64,...)
            if isinstance(data, str) and data.startswith('data:'):
                header, data = data.split(',', 1)
            
            # Decode base64
            image_data = base64.b64decode(data)
            
            # Validate image
            is_valid, error_msg = ImageCompressor.validate_image(image_data)
            if not is_valid:
                raise serializers.ValidationError(f"Invalid image: {error_msg}")
            
            return image_data
            
        except Exception as e:
            logger.error(f"Error processing base64 image: {e}")
            raise serializers.ValidationError("Invalid image data")


class NewsImageSerializer(serializers.ModelSerializer):
    """
    Serializer for news images (gallery)
    """
    image_data = Base64ImageField()
    
    class Meta:
        model = NewsImage
        fields = ['id', 'image_data', 'caption', 'alt_text', 'order']
        read_only_fields = ['id']


class BaseNewsSerializer(serializers.ModelSerializer):
    """
    Base serializer for all news models
    """
    main_image = Base64ImageField(required=False, allow_null=True)
    images = NewsImageSerializer(many=True, read_only=True)
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    
    class Meta:
        fields = [
            'id', 'title_arabic', 'title_english', 'description',
            'main_image', 'date', 'created_at', 'updated_at',
            'created_by', 'created_by_name', 'is_active', 'images'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'created_by', 'created_by_name', 'images']
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Get the request from context
        request = self.context.get('request')
        
        # Apply role-based field filtering
        if request and hasattr(request, 'user'):
            user = request.user
            
            # If user is not admin, remove admin-only fields
            if not (user.is_authenticated and getattr(user, 'role', None) == 'admin'):
                # Remove admin-only fields for public/non-admin users
                admin_only_fields = ['created_by', 'created_by_name']
                for field in admin_only_fields:
                    if field in self.fields:
                        self.fields.pop(field)
            
            # Remove main_image from PUT/PATCH operations (only allow via separate POST endpoint)
            if request and request.method in ['PUT', 'PATCH']:
                if 'main_image' in self.fields:
                    self.fields.pop('main_image')
    
    def create(self, validated_data):
        """
        Create a new news item
        """
        # Set the creator
        request = self.context.get('request')
        if request and hasattr(request, 'user') and request.user.is_authenticated:
            validated_data['created_by'] = request.user
        
        return super().create(validated_data)


class SliderNewsSerializer(BaseNewsSerializer):
    """
    Serializer for slider news
    """
    
    class Meta(BaseNewsSerializer.Meta):
        model = SliderNews
        fields = BaseNewsSerializer.Meta.fields + ['priority', 'display_duration']


class SliderNewsPublicSerializer(serializers.ModelSerializer):
    """
    Public serializer for slider news (limited fields)
    """
    main_image = Base64ImageField()
    images = NewsImageSerializer(many=True, read_only=True)
    
    class Meta:
        model = SliderNews
        fields = [
            'id', 'title_arabic', 'title_english', 'description',
            'main_image', 'date', 'priority', 'display_duration', 'images'
        ]


class AchievementSerializer(BaseNewsSerializer):
    """
    Serializer for achievements
    """
    
    class Meta(BaseNewsSerializer.Meta):
        model = Achievement
        fields = BaseNewsSerializer.Meta.fields + ['category', 'achievement_date']


class AchievementPublicSerializer(serializers.ModelSerializer):
    """
    Public serializer for achievements (limited fields)
    """
    main_image = Base64ImageField()
    images = NewsImageSerializer(many=True, read_only=True)
    category_display = serializers.CharField(source='get_category_display', read_only=True)
    
    class Meta:
        model = Achievement
        fields = [
            'id', 'title_arabic', 'title_english', 'description',
            'main_image', 'date', 'category', 'category_display',
            'achievement_date', 'images'
        ]


class CardsNewsSerializer(BaseNewsSerializer):
    """
    Serializer for cards news
    """
    
    class Meta(BaseNewsSerializer.Meta):
        model = CardsNews
        fields = BaseNewsSerializer.Meta.fields + ['category', 'is_featured', 'view_count']


class CardsNewsPublicSerializer(serializers.ModelSerializer):
    """
    Public serializer for cards news (limited fields)
    """
    main_image = Base64ImageField()
    images = NewsImageSerializer(many=True, read_only=True)
    category_display = serializers.CharField(source='get_category_display', read_only=True)
    
    class Meta:
        model = CardsNews
        fields = [
            'id', 'title_arabic', 'title_english', 'description',
            'main_image', 'date', 'category', 'category_display',
            'is_featured', 'view_count', 'images'
        ]


class NewsImageUploadSerializer(serializers.Serializer):
    """
    Serializer for uploading multiple images to a news item
    """
    images = serializers.ListField(
        child=serializers.DictField(
            child=serializers.CharField()
        ),
        allow_empty=False,
        max_length=10  # Limit to 10 images per upload
    )
    
    def validate_images(self, value):
        """
        Validate image upload data
        """
        validated_images = []
        
        for idx, image_data in enumerate(value):
            if 'image_data' not in image_data:
                raise serializers.ValidationError(f"Image {idx + 1}: 'image_data' field is required")
            
            try:
                # Validate base64 image data
                image_field = Base64ImageField()
                validated_image_data = image_field.to_internal_value(image_data['image_data'])
                
                validated_images.append({
                    'image_data': validated_image_data,
                    'caption': image_data.get('caption', ''),
                    'alt_text': image_data.get('alt_text', ''),
                    'order': image_data.get('order', idx)
                })
                
            except Exception as e:
                raise serializers.ValidationError(f"Image {idx + 1}: {str(e)}")
        
        return validated_images


class BulkNewsImageSerializer(serializers.ModelSerializer):
    """
    Serializer for bulk operations on news images
    """
    image_data = Base64ImageField()
    
    class Meta:
        model = NewsImage
        fields = ['id', 'image_data', 'caption', 'alt_text', 'order']
    
    def create(self, validated_data):
        """
        Create a news image and associate it with the correct parent
        """
        # Get parent model from context
        parent_model = self.context.get('parent_model')
        parent_id = self.context.get('parent_id')
        
        if parent_model and parent_id:
            if parent_model == 'slider_news':
                validated_data['slider_news_id'] = parent_id
            elif parent_model == 'achievement':
                validated_data['achievement_id'] = parent_id
            elif parent_model == 'cards_news':
                validated_data['cards_news_id'] = parent_id
        
        return super().create(validated_data)


class MainImageUploadSerializer(serializers.Serializer):
    """
    Serializer for uploading/updating the main image of a news item
    """
    main_image = Base64ImageField(required=True)
    
    def validate_main_image(self, value):
        """
        Validate main image data
        """
        if not value:
            raise serializers.ValidationError("Main image data is required")
        return value
