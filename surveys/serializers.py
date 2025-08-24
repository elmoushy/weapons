"""
Serializers for surveys with role-based field filtering and validation.

This module follows the established patterns from the authentication system
with comprehensive validation and encryption support.
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Survey, Question, Response, Answer
from .timezone_utils import serialize_datetime_uae, get_status_uae, is_currently_active_uae
import json
import logging

logger = logging.getLogger(__name__)
User = get_user_model()


class UAEDateTimeField(serializers.DateTimeField):
    """
    Custom DateTimeField that always serializes in UAE timezone
    """
    
    def to_representation(self, value):
        """Serialize datetime in UAE timezone"""
        return serialize_datetime_uae(value)


class OptionsField(serializers.CharField):
    """Custom field to handle options as JSON string in DB but list in API"""
    
    def to_representation(self, value):
        """Convert stored JSON string to list for API response"""
        if not value:
            return []
        
        if isinstance(value, str):
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                logger.warning(f"Failed to parse options: {value}")
                return []
        elif isinstance(value, list):
            return value
        
        return []
    
    def to_internal_value(self, data):
        """Convert list from API to JSON string for DB storage"""
        if data is None:
            return ""
        
        if isinstance(data, list):
            return json.dumps(data)
        elif isinstance(data, str):
            # Validate it's proper JSON
            try:
                parsed = json.loads(data)
                if isinstance(parsed, list):
                    return data
                else:
                    raise serializers.ValidationError("Options must be a list")
            except json.JSONDecodeError:
                raise serializers.ValidationError("Options must be valid JSON")
        
        raise serializers.ValidationError("Options must be a list")


class QuestionSerializer(serializers.ModelSerializer):
    """Serializer for survey questions with encrypted fields"""
    
    options = OptionsField(allow_blank=True, required=False)
    
    class Meta:
        model = Question
        fields = [
            'id', 'text', 'question_type', 'options', 
            'is_required', 'order', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def validate(self, data):
        """Cross-field validation for questions"""
        question_type = data.get('question_type')
        options = data.get('options')
        
        # Validate options for choice questions
        if question_type in ['single_choice', 'multiple_choice']:
            if not options:
                raise serializers.ValidationError(
                    "Choice questions must have options"
                )
            
            try:
                # At this point, options should be a JSON string from our custom field
                options_list = json.loads(options) if isinstance(options, str) else options
                
                if not isinstance(options_list, list) or len(options_list) < 2:
                    raise serializers.ValidationError(
                        "Choice questions must have at least 2 options"
                    )
                    
            except (json.JSONDecodeError, TypeError):
                raise serializers.ValidationError("Options must be valid JSON array")
        
        return data


class AnswerSerializer(serializers.ModelSerializer):
    """Serializer for survey answers"""
    
    class Meta:
        model = Answer
        fields = ['id', 'question', 'answer_text', 'created_at']
        read_only_fields = ['id', 'created_at']


class ResponseSerializer(serializers.ModelSerializer):
    """Serializer for survey responses with nested answers and UAE timezone"""
    
    answers = AnswerSerializer(many=True, read_only=True)
    respondent_email = serializers.SerializerMethodField()
    
    # Use UAE timezone for datetime fields
    submitted_at = UAEDateTimeField(read_only=True)
    created_at = UAEDateTimeField(read_only=True)
    updated_at = UAEDateTimeField(read_only=True)
    
    class Meta:
        model = Response
        fields = [
            'id', 'survey', 'respondent', 'respondent_email',
            'submitted_at', 'is_complete', 'answers'
        ]
        read_only_fields = ['id', 'submitted_at', 'respondent_email']
    
    def get_respondent_email(self, obj):
        """Get respondent email - either from user, stored email field, or phone"""
        if obj.respondent:
            return obj.respondent.email
        elif obj.respondent_phone:
            return obj.respondent_phone
        elif obj.respondent_email:
            return obj.respondent_email
        else:
            return "Anonymous"


class SurveySerializer(serializers.ModelSerializer):
    """
    Main survey serializer with role-based field filtering and UAE timezone handling.
    Follows the same patterns as authentication serializers.
    """
    
    questions = QuestionSerializer(many=True, required=False)
    creator_email = serializers.SerializerMethodField()
    response_count = serializers.SerializerMethodField()
    shared_with_emails = serializers.SerializerMethodField()
    status_display = serializers.SerializerMethodField()
    is_currently_active = serializers.SerializerMethodField()
    can_be_edited = serializers.SerializerMethodField()
    
    # Use custom UAE timezone fields for date/time serialization
    start_date = UAEDateTimeField(required=False, allow_null=True)
    end_date = UAEDateTimeField(required=False, allow_null=True)
    created_at = UAEDateTimeField(read_only=True)
    updated_at = UAEDateTimeField(read_only=True)
    
    class Meta:
        model = Survey
        fields = [
            'id', 'title', 'description', 'visibility', 'shared_with',
            'creator', 'creator_email', 'is_locked', 'is_active',
            'start_date', 'end_date', 'status', 'status_display', 'is_currently_active',
            'can_be_edited', 'public_contact_method', 'per_device_access', 'questions', 'response_count', 
            'shared_with_emails', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'creator', 'created_at', 'updated_at', 'status_display', 'is_currently_active', 'can_be_edited']
    
    def get_creator_email(self, obj):
        """Get creator email"""
        return obj.creator.email if obj.creator else None
    
    def get_response_count(self, obj):
        """Get total response count"""
        return obj.responses.count()
    
    def get_shared_with_emails(self, obj):
        """Get emails of users survey is shared with"""
        return [user.email for user in obj.shared_with.all()]
    
    def get_status_display(self, obj):
        """Get current status of the survey using UAE timezone"""
        return get_status_uae(obj)
    
    def get_is_currently_active(self, obj):
        """Check if survey is currently active based on dates using UAE timezone"""
        return is_currently_active_uae(obj)
    
    def get_can_be_edited(self, obj):
        """Check if survey can be edited (only drafts can be edited)"""
        return obj.can_be_edited()
    
    def validate(self, data):
        """Validate survey data including date logic"""
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        
        # If both dates are provided, ensure start_date is before end_date
        if start_date and end_date and start_date >= end_date:
            raise serializers.ValidationError(
                "Start date must be before end date."
            )
        
        return data
    
    def to_representation(self, instance):
        """Role-based field filtering following established patterns"""
        data = super().to_representation(instance)
        request = self.context.get('request')
        
        if not request or not request.user:
            # Anonymous users - minimal data for public surveys only
            if instance.visibility == 'PUBLIC':
                return {
                    'id': data['id'],
                    'title': data['title'],
                    'description': data['description'],
                    'questions': data['questions']
                }
            return {}
        
        user = request.user
        
        # Creators see everything
        if user == instance.creator:
            return data
        
        # Admin/Manager users see most fields
        if user.role in ['admin', 'manager']:
            return data
        
        # Regular users see limited fields
        if instance.visibility in ['AUTH', 'PUBLIC'] or user in instance.shared_with.all():
            return {
                'id': data['id'],
                'title': data['title'],
                'description': data['description'],
                'questions': data['questions'],
                'creator_email': data['creator_email'],
                'created_at': data['created_at']
            }
        
        return {}
    
    def to_internal_value(self, data):
        """Ensure per_device_access always has a value"""
        # Ensure per_device_access is never None and defaults to False
        if 'per_device_access' not in data:
            data['per_device_access'] = False
        elif data.get('per_device_access') is None:
            data['per_device_access'] = False
        
        return super().to_internal_value(data)
    
    def validate(self, data):
        """Enhanced validation with security checks"""
        request = self.context.get('request')
        
        if not request or not request.user.is_authenticated:
            raise serializers.ValidationError("Authentication required")
        
        # Check if survey is locked for updates
        if self.instance and self.instance.is_locked:
            raise serializers.ValidationError("Cannot modify locked survey")
        
        # Validate visibility and shared_with relationship
        visibility = data.get('visibility', 'PRIVATE')
        shared_with = data.get('shared_with', [])
        
        if visibility != 'PRIVATE' and shared_with:
            raise serializers.ValidationError(
                "Cannot share survey when visibility is not PRIVATE"
            )
        
        # Validate per_device_access - only available for PUBLIC surveys
        per_device_access = data.get('per_device_access', False)
        if per_device_access and visibility != 'PUBLIC':
            raise serializers.ValidationError(
                "Per-device access is only available for PUBLIC surveys"
            )
        
        # Validate date logic
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        
        # If both dates are provided, ensure start_date is before end_date
        if start_date and end_date and start_date >= end_date:
            raise serializers.ValidationError(
                "Start date must be before end date."
            )
        
        return data
    
    def create(self, validated_data):
        """Create survey with creator set to current user and handle nested questions"""
        request = self.context.get('request')
        validated_data['creator'] = request.user
        
        # Ensure per_device_access is never None
        if 'per_device_access' not in validated_data:
            validated_data['per_device_access'] = False
        elif validated_data['per_device_access'] is None:
            validated_data['per_device_access'] = False
            
        # Debug: Log the validated data in serializer create
        logger.info(f"Serializer create - per_device_access: {validated_data.get('per_device_access')}")
        logger.info(f"Serializer create - all validated_data keys: {list(validated_data.keys())}")
        
        # Extract questions data before creating survey
        questions_data = validated_data.pop('questions', [])
        
        # Handle shared_with separately
        shared_with = validated_data.pop('shared_with', [])
        
        # Debug: Log data just before Survey.objects.create
        logger.info(f"About to create survey with data: {validated_data}")
        survey = Survey.objects.create(**validated_data)
        
        if validated_data.get('visibility') == 'PRIVATE':
            survey.shared_with.set(shared_with)
        
        # Create questions if provided
        for question_data in questions_data:
            Question.objects.create(survey=survey, **question_data)
        
        logger.info(f"Survey created: {survey.id} with {len(questions_data)} questions by {request.user.email}")
        return survey
    
    def update(self, instance, validated_data):
        """Update survey and handle nested questions"""
        # Ensure per_device_access is never None
        if 'per_device_access' in validated_data and validated_data['per_device_access'] is None:
            validated_data['per_device_access'] = False
        
        # Extract questions data before updating survey
        questions_data = validated_data.pop('questions', None)
        
        # Handle shared_with separately
        shared_with = validated_data.pop('shared_with', None)
        
        # Update survey fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        # Handle shared_with if provided
        if shared_with is not None:
            if instance.visibility == 'PRIVATE':
                instance.shared_with.set(shared_with)
            else:
                instance.shared_with.clear()
        
        # Handle questions if provided
        if questions_data is not None:
            # Delete existing questions
            instance.questions.all().delete()
            
            # Create new questions
            for question_data in questions_data:
                Question.objects.create(survey=instance, **question_data)
        
        logger.info(f"Survey updated: {instance.id} with {len(questions_data) if questions_data else 0} questions")
        return instance


class SurveySubmissionSerializer(serializers.Serializer):
    """Serializer for survey response submission"""
    
    answers = serializers.ListField(
        child=serializers.DictField(),
        allow_empty=False
    )
    
    def validate_answers(self, value):
        """Validate submitted answers with per-question-type validation"""
        if not value:
            raise serializers.ValidationError("At least one answer is required")
        
        for answer in value:
            if 'question_id' not in answer or 'answer_text' not in answer:
                raise serializers.ValidationError(
                    "Each answer must have question_id and answer_text"
                )
            
            # Get question for validation (this will be checked again in the view)
            question_id = answer.get('question_id')
            answer_text = answer.get('answer_text')
            
            # Basic validation - detailed validation happens in the view with DB access
            if not question_id or not answer_text:
                raise serializers.ValidationError(
                    "Question ID and answer text are required"
                )
        
        return value


class ResponseSubmissionSerializer(serializers.Serializer):
    """
    Enhanced serializer for the new survey response submission endpoint.
    Supports different access levels and validation.
    """
    
    survey_id = serializers.UUIDField(required=True)
    token = serializers.CharField(required=False, allow_blank=True)
    password = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    phone = serializers.CharField(max_length=20, required=False, allow_blank=True)
    answers = serializers.ListField(
        child=serializers.DictField(),
        allow_empty=False
    )
    
    def validate_answers(self, value):
        """Validate submitted answers"""
        if not value:
            raise serializers.ValidationError("At least one answer is required")
        
        for answer in value:
            if 'question_id' not in answer or 'answer' not in answer:
                raise serializers.ValidationError(
                    "Each answer must have question_id and answer"
                )
            
            question_id = answer.get('question_id')
            answer_text = answer.get('answer')
            
            if not question_id or not answer_text:
                raise serializers.ValidationError(
                    "Question ID and answer are required"
                )
        
        return value
    
    def validate(self, data):
        """Cross-field validation based on survey access requirements"""
        survey_id = data.get('survey_id')
        token = data.get('token')
        email = data.get('email')
        phone = data.get('phone')
        
        if not survey_id:
            raise serializers.ValidationError("Survey ID is required")
        
        # Basic validation to ensure email and phone are not both provided
        if email and phone:
            raise serializers.ValidationError("Please provide either email or phone, not both")
        
        # We'll validate survey access and required contact method in the view 
        # since we need database access to check survey settings
        
        return data
