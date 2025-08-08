"""
Serializers for surveys with role-based field filtering and validation.

This module follows the established patterns from news_service and Files_Endpoints
with comprehensive validation and encryption support.
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Survey, Question, Response, Answer
import json
import logging

logger = logging.getLogger(__name__)
User = get_user_model()


class QuestionSerializer(serializers.ModelSerializer):
    """Serializer for survey questions with encrypted fields"""
    
    class Meta:
        model = Question
        fields = [
            'id', 'text', 'question_type', 'options', 
            'is_required', 'order', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def to_representation(self, instance):
        """Convert model instance to representation with proper JSON parsing"""
        data = super().to_representation(instance)
        
        # Parse options JSON string back to list for API response
        if data.get('options'):
            try:
                # If options is a JSON string, parse it to a list
                if isinstance(data['options'], str):
                    data['options'] = json.loads(data['options'])
            except (json.JSONDecodeError, TypeError):
                # If parsing fails, return empty list
                logger.warning(f"Failed to parse options for question {instance.id}")
                data['options'] = []
        else:
            # Ensure empty options is represented as empty list, not empty string
            data['options'] = []
        
        return data
    
    def validate_options(self, value):
        """Basic validation for options field"""
        if not value:
            return value
        
        # Basic JSON validation
        if isinstance(value, str):
            try:
                options_list = json.loads(value)
                if not isinstance(options_list, list):
                    raise serializers.ValidationError("Options must be a valid JSON array")
                return json.dumps(options_list)
            except (json.JSONDecodeError, TypeError):
                raise serializers.ValidationError("Options must be valid JSON array")
        elif isinstance(value, list):
            return json.dumps(value)
        
        return value
    
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
                # Parse options if it's a string
                if isinstance(options, str):
                    options_list = json.loads(options)
                else:
                    options_list = options
                
                if not isinstance(options_list, list) or len(options_list) < 2:
                    raise serializers.ValidationError(
                        "Choice questions must have at least 2 options"
                    )
                    
                # Store the properly formatted options back
                data['options'] = json.dumps(options_list)
                
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
    """Serializer for survey responses with nested answers"""
    
    answers = AnswerSerializer(many=True, read_only=True)
    respondent_email = serializers.SerializerMethodField()
    
    class Meta:
        model = Response
        fields = [
            'id', 'survey', 'respondent', 'respondent_email',
            'submitted_at', 'is_complete', 'answers'
        ]
        read_only_fields = ['id', 'submitted_at', 'respondent_email']
    
    def get_respondent_email(self, obj):
        """Get respondent email - either from user or stored email field"""
        if obj.respondent:
            return obj.respondent.email
        elif obj.respondent_email:
            return obj.respondent_email
        else:
            return "Anonymous"


class SurveySerializer(serializers.ModelSerializer):
    """
    Main survey serializer with role-based field filtering.
    Follows the same patterns as news_service serializers.
    """
    
    questions = QuestionSerializer(many=True, required=False)
    creator_email = serializers.SerializerMethodField()
    response_count = serializers.SerializerMethodField()
    shared_with_emails = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    is_currently_active = serializers.SerializerMethodField()
    
    class Meta:
        model = Survey
        fields = [
            'id', 'title', 'description', 'visibility', 'shared_with',
            'creator', 'creator_email', 'is_locked', 'is_active',
            'start_date', 'end_date', 'status', 'is_currently_active',
            'questions', 'response_count', 'shared_with_emails',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'creator', 'created_at', 'updated_at', 'status', 'is_currently_active']
    
    def get_creator_email(self, obj):
        """Get creator email"""
        return obj.creator.email if obj.creator else None
    
    def get_response_count(self, obj):
        """Get total response count"""
        return obj.responses.count()
    
    def get_shared_with_emails(self, obj):
        """Get emails of users survey is shared with"""
        return [user.email for user in obj.shared_with.all()]
    
    def get_status(self, obj):
        """Get current status of the survey"""
        return obj.get_status()
    
    def get_is_currently_active(self, obj):
        """Check if survey is currently active based on dates"""
        return obj.is_currently_active()
    
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
        
        return data
    
    def create(self, validated_data):
        """Create survey with creator set to current user and handle nested questions"""
        request = self.context.get('request')
        validated_data['creator'] = request.user
        
        # Extract questions data before creating survey
        questions_data = validated_data.pop('questions', [])
        
        # Handle shared_with separately
        shared_with = validated_data.pop('shared_with', [])
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
    email = serializers.EmailField(required=False, allow_blank=True)
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
        
        if not survey_id:
            raise serializers.ValidationError("Survey ID is required")
        
        # We'll validate survey access in the view since we need database access
        # This is just basic structure validation
        
        return data
