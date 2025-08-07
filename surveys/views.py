"""
Views for surveys with uniform responses and role-based access control.

This module follows the established patterns from news_service and Files_Endpoints
with comprehensive error handling and logging.
"""

from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.db.models import Q
from django.http import HttpResponse
from rest_framework import status, generics, filters
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from django_filters.rest_framework import DjangoFilterBackend
from django.contrib.auth import get_user_model
import logging
import json
import io
import csv

from .models import Survey, Question, Response as SurveyResponse, Answer, PublicAccessToken
from .serializers import (
    SurveySerializer, QuestionSerializer, ResponseSerializer,
    SurveySubmissionSerializer, ResponseSubmissionSerializer
)
from .permissions import (
    IsCreatorOrVisible, IsCreatorOrReadOnly, 
    CanSubmitResponse, IsCreatorOrStaff
)
import logging
import json
import csv
import io
from datetime import timedelta

logger = logging.getLogger(__name__)
User = get_user_model()


def get_arabic_status_message(survey):
    """
    Generate Arabic status messages with proper date formatting for surveys
    """
    status = survey.get_status()
    
    # Helper function to format dates in Arabic
    def format_date_arabic(date):
        if not date:
            return None
        return date.strftime('%Y-%m-%d')
    
    start_date_str = format_date_arabic(survey.start_date)
    end_date_str = format_date_arabic(survey.end_date)
    
    if status == 'scheduled':
        if start_date_str and end_date_str:
            return f"من المقرر إجراء الاستطلاع في الفترة من {start_date_str} إلى {end_date_str}"
        elif start_date_str:
            return f"من المقرر إجراء الاستطلاع بدءاً من {start_date_str}"
        else:
            return "الاستطلاع مجدول للبدء قريباً"
    
    elif status == 'expired':
        if end_date_str:
            return f"انتهت صلاحية الاستطلاع في {end_date_str}"
        else:
            return "انتهت صلاحية الاستطلاع"
    
    elif status == 'inactive':
        return "الاستطلاع غير نشط حالياً"
    
    elif status == 'deleted':
        return "الاستطلاع محذوف"
    
    elif status == 'active':
        if start_date_str and end_date_str:
            return f"الاستطلاع نشط حتى {end_date_str}"
        elif end_date_str:
            return f"الاستطلاع نشط حتى {end_date_str}"
        else:
            return "الاستطلاع نشط ومتاح للمشاركة"
    
    else:
        return f"حالة الاستطلاع: {status}"


def get_arabic_error_messages():
    """
    Return common Arabic error messages for survey access
    """
    return {
        'survey_not_found': 'الاستطلاع غير موجود',
        'access_denied': 'تم رفض الوصول إلى هذا الاستطلاع',
        'token_required': 'الرمز المميز مطلوب',
        'invalid_token': 'رمز مميز غير صحيح أو منتهي الصلاحية',
        'authentication_required': 'يتطلب تسجيل الدخول للوصول إلى هذا الاستطلاع',
        'survey_locked': 'الاستطلاع مقفل ولا يمكن التعديل عليه',
        'already_submitted': 'لقد قمت بتقديم إجابة لهذا الاستطلاع من قبل',
        'validation_completed': 'تم التحقق من صحة الوصول بنجاح',
        'access_completed': 'تم الوصول بنجاح'
    }


def uniform_response(success=True, message="", data=None, status_code=200):
    """
    Create uniform API response following established patterns.
    """
    return Response({
        'status': 'success' if success else 'error',
        'message': message,
        'data': data
    }, status=status_code)


class SurveyViewSet(ModelViewSet):
    """
    ViewSet for survey CRUD operations with role-based access.
    """
    
    queryset = Survey.objects.filter(deleted_at__isnull=True)
    serializer_class = SurveySerializer
    permission_classes = [IsAuthenticated, IsCreatorOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['visibility', 'is_active', 'creator']
    search_fields = ['title', 'description']
    ordering_fields = ['created_at', 'updated_at', 'title']
    ordering = ['-created_at']
    
    def get_queryset(self):
        """Filter surveys based on user permissions"""
        user = self.request.user
        
        if not user.is_authenticated:
            # Anonymous users only see public surveys
            return self.queryset.filter(visibility='PUBLIC', is_active=True)
        
        if user.role in ['admin', 'manager']:
            # Admin/Manager see all surveys
            return self.queryset
        
        # Regular users see their own surveys, shared surveys, public/auth surveys, and group-shared surveys
        user_groups = user.user_groups.values_list('group', flat=True)
        return self.queryset.filter(
            Q(creator=user) |
            Q(shared_with=user) |
            Q(shared_with_groups__in=user_groups) |
            Q(visibility='PUBLIC') |
            Q(visibility='AUTH')
        ).distinct()
    
    def list(self, request, *args, **kwargs):
        """List surveys with uniform response"""
        try:
            queryset = self.filter_queryset(self.get_queryset())
            page = self.paginate_queryset(queryset)
            
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)
            
            serializer = self.get_serializer(queryset, many=True)
            return uniform_response(
                success=True,
                message="Surveys retrieved successfully",
                data=serializer.data
            )
        except Exception as e:
            logger.error(f"Error listing surveys: {e}")
            return uniform_response(
                success=False,
                message="Failed to retrieve surveys",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def create(self, request, *args, **kwargs):
        """Create survey with uniform response"""
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            survey = serializer.save()
            
            return uniform_response(
                success=True,
                message="Survey created successfully",
                data=serializer.data,
                status_code=status.HTTP_201_CREATED
            )
        except Exception as e:
            logger.error(f"Error creating survey: {e}")
            return uniform_response(
                success=False,
                message=str(e),
                status_code=status.HTTP_400_BAD_REQUEST
            )
    
    def update(self, request, *args, **kwargs):
        """Update survey with support for access_level changes and public token invalidation"""
        try:
            survey = self.get_object()
            old_visibility = survey.visibility
            
            # Handle access_level field mapping to visibility
            if 'access_level' in request.data:
                access_level = request.data.pop('access_level')
                access_mapping = {
                    'public': 'PUBLIC',
                    'authenticated': 'AUTH', 
                    'private': 'PRIVATE'
                }
                
                if access_level in access_mapping:
                    request.data['visibility'] = access_mapping[access_level]
                else:
                    return uniform_response(
                        success=False,
                        message="Invalid access_level. Use 'public', 'authenticated', or 'private'",
                        status_code=status.HTTP_400_BAD_REQUEST
                    )
            
            # Continue with normal update
            serializer = self.get_serializer(survey, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            
            # Check if visibility changed from PUBLIC to AUTH or PRIVATE
            new_visibility = serializer.instance.visibility
            if (old_visibility == 'PUBLIC' and 
                new_visibility in ['AUTH', 'PRIVATE']):
                
                # Invalidate all public access tokens for this survey
                invalidated_count = PublicAccessToken.objects.filter(
                    survey=survey,
                    is_active=True
                ).update(is_active=False)
                
                logger.info(f"Survey {survey.id} visibility changed from PUBLIC to {new_visibility}. "
                           f"Invalidated {invalidated_count} public tokens.")
            
            logger.info(f"Survey {survey.id} updated by {request.user.email}")
            
            return uniform_response(
                success=True,
                message="Survey updated successfully",
                data=serializer.data
            )
            
        except Exception as e:
            logger.error(f"Error updating survey: {e}")
            return uniform_response(
                success=False,
                message=str(e),
                status_code=status.HTTP_400_BAD_REQUEST
            )
    
    def retrieve(self, request, *args, **kwargs):
        """Retrieve survey with visibility check"""
        try:
            survey = self.get_object()
            
            # Check access permissions
            if not IsCreatorOrVisible().has_object_permission(request, self, survey):
                return uniform_response(
                    success=False,
                    message="Access denied",
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
            serializer = self.get_serializer(survey)
            return uniform_response(
                success=True,
                message="Survey retrieved successfully",
                data=serializer.data
            )
        except Exception as e:
            logger.error(f"Error retrieving survey: {e}")
            return uniform_response(
                success=False,
                message="Survey not found",
                status_code=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=True, methods=['post'], permission_classes=[IsCreatorOrReadOnly])
    def audience(self, request, pk=None):
        """
        Set survey audience and sharing settings.
        
        Body examples:
        {"visibility": "AUTH"}                        # everyone with token
        {"visibility": "PUBLIC"}                      # world-readable  
        {"visibility": "PRIVATE", "user_ids":[1,2]}   # share with list
        {"visibility": "GROUPS", "group_ids":[1,2]}   # share with all users in groups
        """
        try:
            survey = self.get_object()
            
            if survey.is_locked:
                return uniform_response(
                    success=False,
                    message="Cannot modify locked survey",
                    status_code=status.HTTP_409_CONFLICT
                )
            
            visibility = request.data.get('visibility', survey.visibility)
            user_ids = request.data.get('user_ids', [])
            group_ids = request.data.get('group_ids', [])
            
            # Validate visibility
            if visibility not in ['PRIVATE', 'AUTH', 'PUBLIC', 'GROUPS']:
                return uniform_response(
                    success=False,
                    message="Invalid visibility value",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            survey.visibility = visibility
            survey.save(update_fields=['visibility', 'updated_at'])
            
            # Handle sharing for private surveys
            if visibility == 'PRIVATE':
                if user_ids:
                    # Validate user IDs
                    valid_users = User.objects.filter(id__in=user_ids)
                    survey.shared_with.set(valid_users)
                else:
                    survey.shared_with.clear()
                # Clear groups when switching to PRIVATE
                survey.shared_with_groups.clear()
            elif visibility == 'GROUPS':
                if group_ids:
                    # Import Group model
                    from authentication.models import Group
                    # Validate group IDs
                    valid_groups = Group.objects.filter(id__in=group_ids)
                    survey.shared_with_groups.set(valid_groups)
                else:
                    survey.shared_with_groups.clear()
                # Clear user sharing when switching to GROUPS
                survey.shared_with.clear()
            else:
                # Clear sharing for non-private and non-groups surveys
                survey.shared_with.clear()
                survey.shared_with_groups.clear()
            
            logger.info(f"Survey {survey.id} audience updated by {request.user.email}")
            
            response_data = {'visibility': visibility}
            if visibility == 'PRIVATE':
                response_data['shared_count'] = survey.shared_with.count()
            elif visibility == 'GROUPS':
                response_data['shared_groups_count'] = survey.shared_with_groups.count()
            
            return uniform_response(
                success=True,
                message="Survey audience updated successfully",
                data=response_data
            )
            
        except Exception as e:
            logger.error(f"Error updating survey audience: {e}")
            return uniform_response(
                success=False,
                message="Failed to update survey audience",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['post'], permission_classes=[IsCreatorOrReadOnly])
    def clone(self, request, pk=None):
        """Clone/duplicate survey"""
        try:
            original = self.get_object()
            
            # Create new survey
            new_survey = Survey.objects.create(
                title=f"{original.title} (Copy)",
                description=original.description,
                creator=request.user,
                visibility='PRIVATE',  # Always start as private
                is_active=False  # Start as inactive
            )
            
            # Clone questions
            for question in original.questions.all():
                Question.objects.create(
                    survey=new_survey,
                    text=question.text,
                    question_type=question.question_type,
                    options=question.options,
                    is_required=question.is_required,
                    order=question.order
                )
            
            serializer = self.get_serializer(new_survey)
            
            logger.info(f"Survey {original.id} cloned as {new_survey.id} by {request.user.email}")
            
            return uniform_response(
                success=True,
                message="Survey cloned successfully",
                data=serializer.data,
                status_code=status.HTTP_201_CREATED
            )
            
        except Exception as e:
            logger.error(f"Error cloning survey: {e}")
            return uniform_response(
                success=False,
                message="Failed to clone survey",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['post'], permission_classes=[IsCreatorOrReadOnly])
    def questions(self, request, pk=None):
        """
        Add a new question to the survey.
        
        POST /api/surveys/surveys/{survey_id}/questions/
        """
        try:
            survey = self.get_object()
            
            if survey.is_locked:
                return uniform_response(
                    success=False,
                    message="Cannot add questions to locked survey",
                    status_code=status.HTTP_409_CONFLICT
                )
            
            # Set the survey for the question
            data = request.data.copy()
            data['survey'] = survey.id
            
            # Auto-increment order if not provided
            if 'order' not in data:
                last_question = survey.questions.last()
                data['order'] = (last_question.order + 1) if last_question else 1
            
            serializer = QuestionSerializer(data=data)
            if serializer.is_valid():
                question = serializer.save(survey=survey)
                logger.info(f"Question added to survey {survey.id} by {request.user.email}")
                
                return uniform_response(
                    success=True,
                    message="Question added successfully",
                    data=serializer.data,
                    status_code=status.HTTP_201_CREATED
                )
            else:
                return uniform_response(
                    success=False,
                    message="Invalid question data",
                    data=serializer.errors,
                    status_code=status.HTTP_400_BAD_REQUEST
                )
                
        except Exception as e:
            logger.error(f"Error adding question to survey {pk}: {e}")
            return uniform_response(
                success=False,
                message="Failed to add question",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['patch'], url_path='questions/(?P<question_id>[^/.]+)', 
            permission_classes=[IsCreatorOrReadOnly])
    def update_question(self, request, pk=None, question_id=None):
        """
        Update a specific question in the survey.
        
        PATCH /api/surveys/surveys/{survey_id}/questions/{question_id}/
        """
        try:
            survey = self.get_object()
            
            if survey.is_locked:
                return uniform_response(
                    success=False,
                    message="Cannot update questions in locked survey",
                    status_code=status.HTTP_409_CONFLICT
                )
            
            try:
                question = survey.questions.get(id=question_id)
            except Question.DoesNotExist:
                return uniform_response(
                    success=False,
                    message="Question not found",
                    status_code=status.HTTP_404_NOT_FOUND
                )
            
            serializer = QuestionSerializer(question, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                logger.info(f"Question {question_id} updated in survey {survey.id} by {request.user.email}")
                
                return uniform_response(
                    success=True,
                    message="Question updated successfully",
                    data=serializer.data
                )
            else:
                return uniform_response(
                    success=False,
                    message="Invalid question data",
                    data=serializer.errors,
                    status_code=status.HTTP_400_BAD_REQUEST
                )
                
        except Exception as e:
            logger.error(f"Error updating question {question_id} in survey {pk}: {e}")
            return uniform_response(
                success=False,
                message="Failed to update question",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['delete'], url_path='questions/(?P<question_id>[^/.]+)', 
            permission_classes=[IsCreatorOrReadOnly])
    def delete_question(self, request, pk=None, question_id=None):
        """
        Delete a specific question from the survey.
        
        DELETE /api/surveys/surveys/{survey_id}/questions/{question_id}/
        """
        try:
            survey = self.get_object()
            
            if survey.is_locked:
                return uniform_response(
                    success=False,
                    message="Cannot delete questions from locked survey",
                    status_code=status.HTTP_409_CONFLICT
                )
            
            try:
                question = survey.questions.get(id=question_id)
            except Question.DoesNotExist:
                return uniform_response(
                    success=False,
                    message="Question not found",
                    status_code=status.HTTP_404_NOT_FOUND
                )
            
            question.delete()
            logger.info(f"Question {question_id} deleted from survey {survey.id} by {request.user.email}")
            
            return uniform_response(
                success=True,
                message="Question deleted successfully",
                status_code=status.HTTP_204_NO_CONTENT
            )
                
        except Exception as e:
            logger.error(f"Error deleting question {question_id} from survey {pk}: {e}")
            return uniform_response(
                success=False,
                message="Failed to delete question",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['get'], permission_classes=[IsCreatorOrStaff])
    def export(self, request, pk=None):
        """
        Export survey data in various formats.
        
        GET /api/surveys/surveys/{survey_id}/export/?format=csv&include_personal_data=false
        """
        try:
            survey = self.get_object()
            export_format = request.query_params.get('format', 'csv').lower()
            include_personal = request.query_params.get('include_personal_data', 'false').lower() == 'true'
            
            if export_format not in ['csv', 'json']:
                return uniform_response(
                    success=False,
                    message="Unsupported export format. Use 'csv' or 'json'",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            # Get all responses for the survey
            responses = survey.responses.all().prefetch_related('answers', 'respondent')
            
            if export_format == 'csv':
                return self._export_csv(survey, responses, include_personal)
            else:  # json
                return self._export_json(survey, responses, include_personal)
                
        except Exception as e:
            logger.error(f"Error exporting survey {pk}: {e}")
            return uniform_response(
                success=False,
                message="Failed to export survey data",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _export_csv(self, survey, responses, include_personal):
        """Export survey responses as CSV"""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Build headers
        headers = ['Response ID', 'Submitted At', 'Is Complete']
        if include_personal:
            headers.append('Respondent Email')
        
        # Add question headers
        questions = survey.questions.all().order_by('order')
        for question in questions:
            headers.append(f"Q{question.order}: {question.text[:50]}")
        
        writer.writerow(headers)
        
        # Write data rows
        for response in responses:
            row = [
                str(response.id),
                response.submitted_at.strftime('%Y-%m-%d %H:%M:%S'),
                'Yes' if response.is_complete else 'No'
            ]
            
            if include_personal:
                row.append(response.respondent.email if response.respondent else 'Anonymous')
            
            # Add answers
            answers_dict = {answer.question.id: answer.answer_text for answer in response.answers.all()}
            for question in questions:
                row.append(answers_dict.get(question.id, ''))
            
            writer.writerow(row)
        
        # Create HTTP response
        response = HttpResponse(
            output.getvalue(),
            content_type='text/csv'
        )
        response['Content-Disposition'] = f'attachment; filename="survey_{survey.id}_responses.csv"'
        
        logger.info(f"Survey {survey.id} exported as CSV by {self.request.user.email}")
        return response
    
    def _export_json(self, survey, responses, include_personal):
        """Export survey responses as JSON"""
        export_data = {
            'survey': {
                'id': str(survey.id),
                'title': survey.title,
                'description': survey.description,
                'exported_at': timezone.now().isoformat(),
                'total_responses': responses.count()
            },
            'responses': []
        }
        
        for response in responses:
            response_data = {
                'id': str(response.id),
                'submitted_at': response.submitted_at.isoformat(),
                'is_complete': response.is_complete,
                'answers': []
            }
            
            if include_personal and response.respondent:
                response_data['respondent_email'] = response.respondent.email
            
            for answer in response.answers.all():
                response_data['answers'].append({
                    'question_id': str(answer.question.id),
                    'question_text': answer.question.text,
                    'question_type': answer.question.question_type,
                    'answer_text': answer.answer_text
                })
            
            export_data['responses'].append(response_data)
        
        # Create HTTP response
        response = HttpResponse(
            json.dumps(export_data, indent=2),
            content_type='application/json'
        )
        response['Content-Disposition'] = f'attachment; filename="survey_{survey.id}_responses.json"'
        
        logger.info(f"Survey {survey.id} exported as JSON by {self.request.user.email}")
        return response
    
    @action(detail=True, methods=['post'], permission_classes=[IsCreatorOrReadOnly], url_path='generate-link')
    def generate_link(self, request, pk=None):
        """
        Generate a public access link for the survey.
        
        POST /api/surveys/surveys/{survey_id}/generate-link/
        """
        try:
            survey = self.get_object()
            
            # Generate unique token
            token = PublicAccessToken.generate_token()
            
            # Set expiration (default 30 days from now)
            days_to_expire = request.data.get('days_to_expire', 30)
            expires_at = timezone.now() + timedelta(days=days_to_expire)
            
            # Deactivate any existing tokens for this survey
            PublicAccessToken.objects.filter(
                survey=survey,
                is_active=True
            ).update(is_active=False)
            
            # Create the new token record
            public_token = PublicAccessToken.objects.create(
                survey=survey,
                token=token,
                expires_at=expires_at,
                created_by=request.user
            )
            
            logger.info(f"Public link generated for survey {survey.id} by {request.user.email}")
            
            return uniform_response(
                success=True,
                message="Public link generated successfully",
                data={
                    'token': token,
                    'expires_at': expires_at.isoformat()
                },
                status_code=status.HTTP_201_CREATED
            )
            
        except Exception as e:
            logger.error(f"Error generating public link for survey {pk}: {e}")
            return uniform_response(
                success=False,
                message="Failed to generate public link",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['get', 'delete'], permission_classes=[IsCreatorOrReadOnly], url_path='public-link')
    def public_link(self, request, pk=None):
        """
        Get existing public links for the survey or revoke them.
        
        GET /api/surveys/surveys/{survey_id}/public-link/
        DELETE /api/surveys/surveys/{survey_id}/public-link/
        """
        try:
            survey = self.get_object()
            
            if request.method == 'GET':
                # Get all active public tokens for this survey
                active_tokens = PublicAccessToken.objects.filter(
                    survey=survey,
                    is_active=True
                ).order_by('-created_at')
                
                links_data = []
                base_url = request.build_absolute_uri('/').rstrip('/')
                
                for token_obj in active_tokens:
                    if token_obj.is_valid():
                        links_data.append({
                            'id': str(token_obj.id),
                            'link': f"{base_url}/survey/public/{token_obj.token}",
                            'token': token_obj.token,
                            'created_at': token_obj.created_at.isoformat(),
                            'expires_at': token_obj.expires_at.isoformat(),
                            'is_expired': token_obj.is_expired(),
                            'created_by': token_obj.created_by.email if token_obj.created_by else None
                        })
                
                if not links_data:
                    return uniform_response(
                        success=False,
                        message="No public link found for this survey",
                        data=None,
                        status_code=status.HTTP_404_NOT_FOUND
                    )
                
                # Return single token for API compatibility
                latest_token = links_data[0]
                return uniform_response(
                    success=True,
                    message="Public link retrieved successfully",
                    data={
                        'token': latest_token['token'],
                        'expires_at': latest_token['expires_at']
                    }
                )
            
            elif request.method == 'DELETE':
                # Revoke public link for survey
                revoked_count = PublicAccessToken.objects.filter(
                    survey=survey,
                    is_active=True
                ).update(is_active=False)
                
                logger.info(f"Public links revoked for survey {survey.id} by {request.user.email}")
                
                return uniform_response(
                    success=True,
                    message="Public link revoked successfully",
                    data={'revoked': True}
                )
            
        except Exception as e:
            logger.error(f"Error handling public links for survey {pk}: {e}")
            return uniform_response(
                success=False,
                message="Failed to handle public links",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['get'], permission_classes=[AllowAny])
    def access(self, request, pk=None):
        """
        Validate public access to a survey.
        
        GET /api/surveys/surveys/{survey_id}/access/?token={token}
        """
        try:
            survey = self.get_object()
            token = request.query_params.get('token')
            
            # First check if survey is currently active based on dates
            if not survey.is_currently_active():
                arabic_message = get_arabic_status_message(survey)
                return uniform_response(
                    success=False,
                    message=arabic_message,
                    data={
                        'has_access': False,
                        'survey_status': survey.get_status(),
                        'start_date': survey.start_date.isoformat() if survey.start_date else None,
                        'end_date': survey.end_date.isoformat() if survey.end_date else None
                    },
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
            has_access = False
            survey_data = None
            
            if token:
                # Check if token is valid
                try:
                    access_token = PublicAccessToken.objects.get(
                        token=token,
                        survey=survey,
                        is_active=True
                    )
                    
                    if access_token.is_valid():
                        has_access = True
                except PublicAccessToken.DoesNotExist:
                    pass
            
            # If no token or invalid token, check other access methods
            if not has_access:
                if survey.visibility == 'PUBLIC':
                    has_access = True
                elif survey.visibility == 'AUTH' and request.user.is_authenticated:
                    has_access = True
                elif survey.visibility == 'PRIVATE' and request.user.is_authenticated:
                    if (request.user == survey.creator or 
                        request.user in survey.shared_with.all()):
                        has_access = True
            
            if has_access:
                # Get first 3-5 questions for preview
                questions = survey.questions.all().order_by('order')[:5]
                question_data = []
                
                for question in questions:
                    question_data.append({
                        'id': str(question.id),
                        'text': question.text,
                        'question_type': question.question_type,
                        'is_required': question.is_required,
                        'order': question.order
                    })
                
                survey_data = {
                    'id': str(survey.id),
                    'title': survey.title,
                    'description': survey.description,
                    'visibility': survey.visibility,
                    'status': survey.get_status(),
                    'is_currently_active': survey.is_currently_active(),
                    'start_date': survey.start_date.isoformat() if survey.start_date else None,
                    'end_date': survey.end_date.isoformat() if survey.end_date else None,
                    'estimated_time': max(len(survey.questions.all()) * 2, 5),  # 2 min per question, min 5 min
                    'questions_count': survey.questions.count(),
                    'questions': question_data
                }
            
            return uniform_response(
                success=True,
                message=get_arabic_error_messages()['validation_completed'],
                data={
                    'has_access': has_access,
                    'survey': survey_data
                }
            )
            
        except Survey.DoesNotExist:
            return uniform_response(
                success=False,
                message=get_arabic_error_messages()['survey_not_found'],
                status_code=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error validating access to survey {pk}: {e}")
            return uniform_response(
                success=False,
                message="Failed to validate access",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['get'], permission_classes=[AllowAny], url_path='access')
    def public_access(self, request):
        """
        Validate public access token without survey ID.
        
        GET /api/surveys/surveys/access/?token={token}
        """
        try:
            token = request.query_params.get('token')
            
            if not token:
                return uniform_response(
                    success=False,
                    message=get_arabic_error_messages()['token_required'],
                    data={'has_access': False, 'survey': None},
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                # Find active, non-expired token
                access_token = PublicAccessToken.objects.select_related('survey').get(
                    token=token,
                    is_active=True
                )
                
                if not access_token.is_valid():
                    raise PublicAccessToken.DoesNotExist
                
                survey = access_token.survey
                
                # Check if survey is active and in valid date period
                if not survey.is_active or survey.deleted_at is not None:
                    raise PublicAccessToken.DoesNotExist
                
                # Check if survey is currently active based on dates
                if not survey.is_currently_active():
                    arabic_message = get_arabic_status_message(survey)
                    return uniform_response(
                        success=False,
                        message=arabic_message,
                        data={
                            'has_access': False,
                            'survey_status': survey.get_status(),
                            'start_date': survey.start_date.isoformat() if survey.start_date else None,
                            'end_date': survey.end_date.isoformat() if survey.end_date else None
                        },
                        status_code=status.HTTP_403_FORBIDDEN
                    )
                
                # Get all questions with complete data using serializer
                questions = survey.questions.all().order_by('order')
                question_serializer = QuestionSerializer(questions, many=True)
                
                survey_data = {
                    'id': str(survey.id),
                    'title': survey.title,
                    'description': survey.description,
                    'estimated_time': max(survey.questions.count() * 1, 5),  # 1 min per question, min 5 min
                    'questions_count': survey.questions.count(),
                    'questions': question_serializer.data
                }
                
                return uniform_response(
                    success=True,
                    message=get_arabic_error_messages()['validation_completed'],
                    data={
                        'has_access': True,
                        'survey': survey_data
                    }
                )
                
            except PublicAccessToken.DoesNotExist:
                return uniform_response(
                    success=False,
                    message=get_arabic_error_messages()['invalid_token'],
                    data={
                        'has_access': False,
                        'survey': None
                    },
                    status_code=status.HTTP_404_NOT_FOUND
                )
                
        except Exception as e:
            logger.error(f"Error validating public access token: {e}")
            return uniform_response(
                success=False,
                message="Failed to validate access",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['get'], permission_classes=[IsAuthenticated], url_path='auth-access')
    def authenticated_access(self, request, pk=None):
        """
        Get survey details for authenticated users with Bearer token.
        
        GET /api/surveys/surveys/{survey_id}/auth-access/
        Headers: Authorization: Bearer <token>
        """
        try:
            survey = self.get_object()
            user = request.user
            
            # Check if survey is currently active based on dates
            if not survey.is_currently_active():
                arabic_message = get_arabic_status_message(survey)
                return uniform_response(
                    success=False,
                    message=arabic_message,
                    data={
                        'survey_status': survey.get_status(),
                        'start_date': survey.start_date.isoformat() if survey.start_date else None,
                        'end_date': survey.end_date.isoformat() if survey.end_date else None
                    },
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
            # Check access permissions based on survey visibility
            has_access = False
            
            if survey.visibility == 'PUBLIC':
                has_access = True
            elif survey.visibility == 'AUTH':
                has_access = True  # All authenticated users can access
            elif survey.visibility == 'PRIVATE':
                # Check if user is creator or explicitly shared
                has_access = (user == survey.creator or 
                             user in survey.shared_with.all())
            
            if not has_access:
                return uniform_response(
                    success=False,
                    message=get_arabic_error_messages()['access_denied'],
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
            # Get all questions with complete data using serializer
            questions = survey.questions.all().order_by('order')
            question_serializer = QuestionSerializer(questions, many=True)
            
            survey_data = {
                'id': str(survey.id),
                'title': survey.title,
                'description': survey.description,
                'visibility': survey.visibility,
                'status': survey.get_status(),
                'is_currently_active': survey.is_currently_active(),
                'start_date': survey.start_date.isoformat() if survey.start_date else None,
                'end_date': survey.end_date.isoformat() if survey.end_date else None,
                'estimated_time': max(survey.questions.count() * 1, 5),  # 1 min per question, min 5 min
                'questions_count': survey.questions.count(),
                'questions': question_serializer.data
            }
            
            return uniform_response(
                success=True,
                message=get_arabic_error_messages()['access_completed'],
                data={
                    'survey': survey_data
                }
            )
            
        except Survey.DoesNotExist:
            return uniform_response(
                success=False,
                message=get_arabic_error_messages()['survey_not_found'],
                status_code=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error accessing survey {pk} for user {request.user.email}: {e}")
            return uniform_response(
                success=False,
                message="Failed to access survey",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['post'], permission_classes=[IsCreatorOrReadOnly])
    def share(self, request, pk=None):
        """
        Share survey with specific users.
        
        POST /api/surveys/surveys/{survey_id}/share/
        """
        try:
            survey = self.get_object()
            
            user_ids = request.data.get('user_ids', [])
            emails = request.data.get('emails', [])
            
            shared_users = []
            
            # Add users by ID
            if user_ids:
                users = User.objects.filter(id__in=user_ids)
                for user in users:
                    survey.shared_with.add(user)
                    shared_users.append({
                        'id': user.id,
                        'email': user.email,
                        'name': user.full_name
                    })
            
            # Add users by email
            if emails:
                for email in emails:
                    try:
                        user = User.objects.get(email=email)
                        survey.shared_with.add(user)
                        shared_users.append({
                            'id': user.id,
                            'email': user.email,
                            'name': user.full_name
                        })
                    except User.DoesNotExist:
                        # Log that user doesn't exist but don't fail the request
                        logger.warning(f"User with email {email} not found for sharing survey {survey.id}")
            
            # Set survey to private if not already
            if survey.visibility != 'PRIVATE':
                survey.visibility = 'PRIVATE'
                survey.save(update_fields=['visibility'])
            
            logger.info(f"Survey {survey.id} shared with {len(shared_users)} users by {request.user.email}")
            
            return uniform_response(
                success=True,
                message="Survey shared successfully",
                data={
                    'shared_users': shared_users,
                    'total_shared': survey.shared_with.count()
                }
            )
            
        except Exception as e:
            logger.error(f"Error sharing survey {pk}: {e}")
            return uniform_response(
                success=False,
                message="Failed to share survey",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class MySharedSurveysView(generics.ListAPIView):
    """
    Get all surveys accessible to the authenticated user based on sharing rules.
    
    This includes:
    - ALL surveys with visibility "PUBLIC" (accessible to everyone, including anonymous users)
    - ALL surveys with visibility "AUTH" (accessible to all authenticated users, including own surveys)
    - Surveys with visibility "PRIVATE" where the user is explicitly shared (excluding own private surveys)
    
    GET /api/surveys/my-shared/
    Access: Authenticated users only
    """
    
    serializer_class = SurveySerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['visibility', 'is_active', 'is_locked']
    search_fields = ['title', 'description']
    ordering_fields = ['created_at', 'updated_at', 'title']
    ordering = ['-updated_at']
    
    def get_queryset(self):
        """Get surveys shared with the authenticated user"""
        user = self.request.user
        
        # Build query for surveys accessible to this user
        # 1. PUBLIC surveys (accessible to everyone) - include ALL PUBLIC surveys
        # 2. AUTH surveys (accessible to all authenticated users) - include ALL AUTH surveys
        # 3. Private surveys where user is explicitly shared (exclude own private surveys)
        # 4. Group surveys where user is in the shared groups (exclude own group surveys)
        
        public_surveys = Q(visibility='PUBLIC')
        auth_surveys = Q(visibility='AUTH')
        private_shared_surveys = Q(visibility='PRIVATE', shared_with=user) & ~Q(creator=user)
        user_groups = user.user_groups.values_list('group', flat=True)
        group_shared_surveys = Q(visibility='GROUPS', shared_with_groups__in=user_groups) & ~Q(creator=user)
        
        return Survey.objects.filter(
            public_surveys | auth_surveys | private_shared_surveys | group_shared_surveys,
            deleted_at__isnull=True,
            is_active=True  # Only show active surveys
        ).distinct().select_related(
            'creator'
        ).prefetch_related(
            'questions', 'shared_with', 'shared_with_groups'
        )
    
    def list(self, request, *args, **kwargs):
        """List shared surveys with uniform response format"""
        try:
            queryset = self.filter_queryset(self.get_queryset())
            page = self.paginate_queryset(queryset)
            
            # Prepare enhanced response data
            surveys_data = []
            surveys_to_process = page if page is not None else queryset
            
            for survey in surveys_to_process:
                # Check if user has already submitted a response
                has_submitted = SurveyResponse.objects.filter(
                    survey=survey,
                    respondent=request.user
                ).exists()
                
                # Determine the reason for access
                access_reason = survey.visibility  # Default to visibility
                if survey.visibility == 'PRIVATE':
                    # User has access because they are explicitly shared
                    access_reason = 'PRIVATE'
                elif survey.visibility == 'GROUPS':
                    # User has access because they are in a shared group
                    access_reason = 'GROUPS'
                elif survey.visibility == 'AUTH':
                    # User has access because they are authenticated
                    access_reason = 'AUTH'
                elif survey.visibility == 'PUBLIC':
                    # User has access because it's public
                    access_reason = 'PUBLIC'
                
                survey_data = {
                    'id': str(survey.id),
                    'title': survey.title,
                    'description': survey.description,
                    'visibility': survey.visibility,
                    'reason': access_reason,
                    'is_active': survey.is_active,
                    'is_locked': survey.is_locked,
                    'status': survey.get_status(),
                    'is_currently_active': survey.is_currently_active(),
                    'start_date': survey.start_date.isoformat() if survey.start_date else None,
                    'end_date': survey.end_date.isoformat() if survey.end_date else None,
                    'created_at': survey.created_at.isoformat(),
                    'updated_at': survey.updated_at.isoformat(),
                    'creator': {
                        'id': survey.creator.id,
                        'email': survey.creator.email,
                        'name': survey.creator.full_name
                    },
                    'questions_count': survey.questions.count(),
                    'estimated_time': max(survey.questions.count() * 1, 5),
                    'access_info': {
                        'access_type': survey.visibility,
                        'can_submit': not has_submitted and survey.is_currently_active() and not survey.is_locked,
                        'has_submitted': has_submitted,
                        'is_shared_explicitly': survey.visibility == 'PRIVATE',
                        'is_shared_via_group': survey.visibility == 'GROUPS',
                        'is_creator': survey.creator == request.user
                    }
                }
                
                surveys_data.append(survey_data)
            
            if page is not None:
                # Return paginated response
                paginated_response = self.get_paginated_response(surveys_data)
                return paginated_response
            
            return uniform_response(
                success=True,
                message="Shared surveys retrieved successfully",
                data={
                    'surveys': surveys_data,
                    'total_count': queryset.count(),
                    'access_summary': {
                        'public_surveys': queryset.filter(visibility='PUBLIC').count(),
                        'auth_surveys': queryset.filter(visibility='AUTH').count(),
                        'private_shared': queryset.filter(visibility='PRIVATE').count(),
                        'group_shared': queryset.filter(visibility='GROUPS').count()
                    }
                }
            )
            
        except Exception as e:
            logger.error(f"Error retrieving shared surveys for user {request.user.email}: {e}")
            return uniform_response(
                success=False,
                message="Failed to retrieve shared surveys",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UserSearchView(generics.ListAPIView):
    """
    Search users for survey sharing.
    """
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        """
        Search users by email or name.
        
        GET /api/users/search/?query={search_term}
        """
        try:
            query = request.query_params.get('query', '').strip()
            
            if not query or len(query) < 2:
                return uniform_response(
                    success=False,
                    message="Query must be at least 2 characters long",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            # Search users by email, first_name, or last_name
            users = User.objects.filter(
                Q(email__icontains=query) |
                Q(first_name__icontains=query) |
                Q(last_name__icontains=query),
                is_active=True
            ).exclude(id=request.user.id)[:10]  # Limit to 10 results
            
            user_data = []
            for user in users:
                user_data.append({
                    'id': user.id,
                    'email': user.email,
                    'name': user.full_name,
                    'avatar': None  # You can add avatar logic here if needed
                })
            
            return uniform_response(
                success=True,
                message="Users retrieved successfully",
                data={
                    'users': user_data
                }
            )
            
        except Exception as e:
            logger.error(f"Error searching users: {e}")
            return uniform_response(
                success=False,
                message="Failed to search users",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class MyAdminGroupsView(APIView):
    """
    Get all groups where the current user is an Administrator or Super Administrator.
    This is used for survey sharing with groups.
    """
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get groups where user is admin or super admin"""
        try:
            user = request.user
            
            # Import Group and UserGroup models
            from authentication.models import Group, UserGroup
            
            # If user is super_admin, they can see all groups
            if user.role == 'super_admin':
                groups = Group.objects.all().order_by('name')
                groups_data = [
                    {
                        'id': group.id,
                        'name': group.name,
                        'description': group.description or '',
                        'user_count': group.user_count,
                        'admin_level': 'super_admin'
                    }
                    for group in groups
                ]
            else:
                # Get groups where user is a group administrator
                admin_groups = UserGroup.objects.filter(
                    user=user,
                    is_group_admin=True
                ).select_related('group')
                
                groups_data = [
                    {
                        'id': ug.group.id,
                        'name': ug.group.name,
                        'description': ug.group.description or '',
                        'user_count': ug.group.user_count,
                        'admin_level': 'group_admin'
                    }
                    for ug in admin_groups.order_by('group__name')
                ]
            
            return uniform_response(
                success=True,
                message="Admin groups retrieved successfully",
                data={
                    'groups': groups_data,
                    'total_count': len(groups_data),
                    'user_role': user.role
                }
            )
            
        except Exception as e:
            logger.error(f"Error retrieving admin groups for user {request.user.email}: {e}")
            return uniform_response(
                success=False,
                message="Failed to retrieve admin groups",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AuthenticatedSurveyResponseView(APIView):
    """
    Handle authenticated survey response submissions using Bearer token.
    No email required since user is identified from the token.
    
    POST /api/surveys/auth-responses/
    Headers: Authorization: Bearer <token>
    """
    
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Submit survey response using authenticated user from Bearer token"""
        try:
            # Get authenticated user from token
            user = request.user
            
            # Validate required fields
            survey_id = request.data.get('survey_id')
            answers_data = request.data.get('answers', [])
            
            if not survey_id:
                return uniform_response(
                    success=False,
                    message="survey_id is required",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            if not answers_data:
                return uniform_response(
                    success=False,
                    message="answers are required",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            # Get survey
            try:
                survey = Survey.objects.get(id=survey_id, deleted_at__isnull=True)
            except Survey.DoesNotExist:
                return uniform_response(
                    success=False,
                    message="Survey not found",
                    status_code=status.HTTP_404_NOT_FOUND
                )
            
            # Check if survey is currently active based on dates
            if not survey.is_currently_active():
                status_message = f"Survey is {survey.get_status()}"
                return uniform_response(
                    success=False,
                    message=status_message,
                    data={
                        'survey_status': survey.get_status(),
                        'start_date': survey.start_date.isoformat() if survey.start_date else None,
                        'end_date': survey.end_date.isoformat() if survey.end_date else None
                    },
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            # Check access permissions based on survey visibility
            has_access = False
            
            if survey.visibility == 'PUBLIC':
                has_access = True
            elif survey.visibility == 'AUTH':
                has_access = True  # All authenticated users can access
            elif survey.visibility == 'PRIVATE':
                # Check if user is creator or explicitly shared
                has_access = (user == survey.creator or 
                             user in survey.shared_with.all())
            
            if not has_access:
                return uniform_response(
                    success=False,
                    message="Access denied to this survey",
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
            # Check for duplicate submissions
            existing_response = SurveyResponse.objects.filter(
                survey=survey,
                respondent=user
            ).first()
            
            if existing_response:
                return uniform_response(
                    success=False,
                    message="You have already submitted a response to this survey",
                    data={
                        'existing_response_id': str(existing_response.id),
                        'submitted_at': existing_response.submitted_at.isoformat()
                    },
                    status_code=status.HTTP_409_CONFLICT
                )
            
            # Create survey response
            survey_response = SurveyResponse.objects.create(
                survey=survey,
                respondent=user,
                ip_address=request.META.get('REMOTE_ADDR'),
                is_complete=True  # Assume complete submission for authenticated users
            )
            
            # Create answers
            created_answers = []
            for answer_data in answers_data:
                question_id = answer_data.get('question_id')
                answer_text = answer_data.get('answer_text', '')
                
                if not question_id:
                    continue
                
                try:
                    question = Question.objects.get(id=question_id, survey=survey)
                    answer = Answer.objects.create(
                        response=survey_response,
                        question=question,
                        answer_text=str(answer_text)
                    )
                    created_answers.append(answer)
                except Question.DoesNotExist:
                    logger.warning(f"Question {question_id} not found in survey {survey.id}")
                    continue
            
            # Log the submission
            logger.info(f"Authenticated survey response submitted: {survey_response.id} for survey {survey.id} by {user.email}")
            
            return uniform_response(
                success=True,
                message="Response submitted successfully",
                data={
                    'response_id': str(survey_response.id),
                    'survey_id': str(survey.id),
                    'submitted_at': survey_response.submitted_at.isoformat(),
                    'answer_count': len(created_answers),
                    'respondent_email': user.email
                },
                status_code=status.HTTP_201_CREATED
            )
            
        except Exception as e:
            logger.error(f"Error submitting authenticated survey response: {e}")
            return uniform_response(
                success=False,
                message="Failed to submit response",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class SurveyResponseSubmissionView(APIView):
    """
    Handle survey response submissions at /api/surveys/responses/
    with support for different access levels and email validation.
    """
    
    permission_classes = [AllowAny]  # Handle permissions manually
    
    def _validate_survey_access(self, request, survey, token=None, email=None):
        """
        Validate access to survey based on visibility and provided credentials
        Returns tuple: (has_access, user_or_email, error_message)
        """
        # Check if survey is currently active based on dates
        if not survey.is_currently_active():
            status_message = f"Survey is {survey.get_status()}"
            return False, None, status_message
        
        # Handle public token access first
        if token:
            try:
                access_token = PublicAccessToken.objects.get(
                    token=token,
                    survey=survey,
                    is_active=True
                )
                if access_token.is_valid():
                    # Token is valid, determine user
                    if request.user.is_authenticated:
                        return True, request.user, None
                    elif email:
                        return True, email, None
                    else:
                        return False, None, "Email is required for anonymous access with token"
            except PublicAccessToken.DoesNotExist:
                return False, None, "Invalid or expired token"
        
        # Handle different visibility levels
        if survey.visibility == "PUBLIC":
            # Public surveys require email for anonymous users
            if request.user.is_authenticated:
                return True, request.user, None
            elif email:
                return True, email, None
            else:
                return False, None, "Email is required for public survey responses"
        
        elif survey.visibility == "AUTH":
            # Authentication required
            if not request.user.is_authenticated:
                return False, None, "Authentication required for this survey"
            return True, request.user, None
        
        elif survey.visibility == "PRIVATE":
            # Private survey - must be authenticated and have permission
            if not request.user.is_authenticated:
                return False, None, "Authentication required for private survey"
            
            if (request.user == survey.creator or 
                request.user in survey.shared_with.all()):
                return True, request.user, None
            else:
                return False, None, "Access denied to private survey"
        
        return False, None, "Invalid survey access configuration"
    
    def post(self, request):
        """Submit survey response using the new format"""
        try:
            # Validate input data
            serializer = ResponseSubmissionSerializer(data=request.data)
            if not serializer.is_valid():
                return uniform_response(
                    success=False,
                    message="Invalid submission data",
                    data=serializer.errors,
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            validated_data = serializer.validated_data
            survey_id = validated_data['survey_id']
            token = validated_data.get('token')
            email = validated_data.get('email')
            answers_data = validated_data['answers']
            
            # Get survey
            try:
                survey = Survey.objects.get(id=survey_id, deleted_at__isnull=True)
            except Survey.DoesNotExist:
                return uniform_response(
                    success=False,
                    message="Survey not found",
                    status_code=status.HTTP_404_NOT_FOUND
                )
            
            # Validate access
            has_access, user_or_email, error_msg = self._validate_survey_access(
                request, survey, token, email
            )
            
            if not has_access:
                return uniform_response(
                    success=False,
                    message=error_msg or "Access denied",
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
            # Determine respondent details for duplicate check
            respondent = user_or_email if isinstance(user_or_email, User) else None
            respondent_email = email if isinstance(user_or_email, str) else None
            
            # Check for duplicate submissions
            existing_response = None
            if respondent:
                # Check by authenticated user
                existing_response = SurveyResponse.objects.filter(
                    survey=survey,
                    respondent=respondent
                ).first()
            elif respondent_email:
                # Check by email for anonymous users
                existing_response = SurveyResponse.objects.filter(
                    survey=survey,
                    respondent_email=respondent_email
                ).first()
                
                # Also check if this email belongs to an authenticated user who already responded
                try:
                    user_with_email = User.objects.get(email=respondent_email)
                    user_response = SurveyResponse.objects.filter(
                        survey=survey,
                        respondent=user_with_email
                    ).first()
                    if user_response:
                        existing_response = user_response
                except User.DoesNotExist:
                    pass
            
            if existing_response:
                return uniform_response(
                    success=False,
                    message="You have already submitted a response to this survey",
                    data={
                        'existing_response_id': str(existing_response.id),
                        'submitted_at': existing_response.submitted_at.isoformat()
                    },
                    status_code=status.HTTP_409_CONFLICT
                )
            
            # Create survey response
            survey_response = SurveyResponse.objects.create(
                survey=survey,
                respondent=respondent,
                ip_address=request.META.get('REMOTE_ADDR'),
                respondent_email=respondent_email  # Store email for anonymous responses
            )
            
            # Create answers
            created_answers = []
            for answer_data in answers_data:
                try:
                    question = Question.objects.get(
                        id=answer_data['question_id'], 
                        survey=survey
                    )
                except Question.DoesNotExist:
                    # Delete the response if any question is invalid
                    survey_response.delete()
                    return uniform_response(
                        success=False,
                        message=f"Question {answer_data['question_id']} not found in survey",
                        status_code=status.HTTP_400_BAD_REQUEST
                    )
                
                answer = Answer.objects.create(
                    response=survey_response,
                    question=question,
                    answer_text=answer_data['answer']
                )
                created_answers.append(answer)
            
            # Log the submission
            user_info = f"user {respondent.email}" if respondent else f"email {respondent_email}"
            logger.info(f"Survey response submitted: {survey_response.id} for survey {survey.id} by {user_info}")
            
            return uniform_response(
                success=True,
                message="Response submitted successfully",
                data={
                    'response_id': str(survey_response.id),
                    'survey_id': str(survey.id),
                    'submitted_at': survey_response.submitted_at.isoformat(),
                    'answer_count': len(created_answers),
                    'respondent_type': 'authenticated' if respondent else 'anonymous'
                },
                status_code=status.HTTP_201_CREATED
            )
            
        except Exception as e:
            logger.error(f"Error submitting survey response: {e}")
            return uniform_response(
                success=False,
                message="Failed to submit response",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class SurveySubmissionView(APIView):
    """
    Handle survey response submissions with visibility checks.
    """
    
    permission_classes = [AllowAny]  # Handle permissions manually
    
    def _user_can_access(self, request, survey):
        """Check if user can access survey for submission"""
        # Check for public token access first
        token = request.data.get('token') or request.query_params.get('token')
        if token:
            try:
                access_token = PublicAccessToken.objects.get(
                    token=token,
                    survey=survey,
                    is_active=True
                )
                if access_token.is_valid():
                    return True
            except PublicAccessToken.DoesNotExist:
                pass
        
        # Check normal visibility rules
        if survey.visibility == "PUBLIC":
            return True
        
        if survey.visibility == "AUTH":
            return request.user.is_authenticated
        
        # Private survey
        if not request.user.is_authenticated:
            return False
        
        return (
            request.user == survey.creator or
            request.user in survey.shared_with.all()
        )
    
    def post(self, request, survey_id):
        """Submit survey response"""
        try:
            survey = get_object_or_404(Survey, id=survey_id, deleted_at__isnull=True)
            
            # Check if survey is currently active based on dates
            if not survey.is_currently_active():
                status_message = f"Survey is {survey.get_status()}"
                return uniform_response(
                    success=False,
                    message=status_message,
                    data={
                        'survey_status': survey.get_status(),
                        'start_date': survey.start_date.isoformat() if survey.start_date else None,
                        'end_date': survey.end_date.isoformat() if survey.end_date else None
                    },
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            # Check access permissions
            if not self._user_can_access(request, survey):
                return uniform_response(
                    success=False,
                    message="Access denied",
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
            # Check for duplicate submissions
            if request.user.is_authenticated:
                existing_response = SurveyResponse.objects.filter(
                    survey=survey,
                    respondent=request.user
                ).first()
                
                if existing_response:
                    return uniform_response(
                        success=False,
                        message="You have already submitted a response to this survey",
                        data={
                            'existing_response_id': str(existing_response.id),
                            'submitted_at': existing_response.submitted_at.isoformat()
                        },
                        status_code=status.HTTP_409_CONFLICT
                    )
            
            # Validate submission data
            serializer = SurveySubmissionSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            
            answers_data = serializer.validated_data['answers']
            
            # Create response
            survey_response = SurveyResponse.objects.create(
                survey=survey,
                respondent=request.user if request.user.is_authenticated else None,
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            # Create answers
            created_answers = []
            for answer_data in answers_data:
                question = get_object_or_404(
                    Question, 
                    id=answer_data['question_id'], 
                    survey=survey
                )
                
                answer = Answer.objects.create(
                    response=survey_response,
                    question=question,
                    answer_text=answer_data['answer_text']
                )
                created_answers.append(answer)
            
            logger.info(f"Survey response submitted: {survey_response.id} for survey {survey.id}")
            
            return uniform_response(
                success=True,
                message="Response submitted successfully",
                data={
                    'response_id': str(survey_response.id),
                    'submitted_at': survey_response.submitted_at,
                    'answer_count': len(created_answers)
                },
                status_code=status.HTTP_201_CREATED
            )
            
        except Exception as e:
            logger.error(f"Error submitting survey response: {e}")
            return uniform_response(
                success=False,
                message="Failed to submit response",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class SurveyResponsesView(generics.ListAPIView):
    """
    List survey responses - only accessible by survey creator or staff.
    """
    
    serializer_class = ResponseSerializer
    permission_classes = [IsAuthenticated, IsCreatorOrStaff]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['is_complete', 'respondent']
    ordering_fields = ['submitted_at']
    ordering = ['-submitted_at']
    
    def get_queryset(self):
        """Get responses for specific survey"""
        survey_id = self.kwargs.get('survey_id')
        survey = get_object_or_404(Survey, id=survey_id, deleted_at__isnull=True)
        
        # Check permissions
        if not IsCreatorOrStaff().has_object_permission(self.request, self, survey):
            return SurveyResponse.objects.none()
        
        return survey.responses.all()
    
    def list(self, request, *args, **kwargs):
        """List responses with uniform response format"""
        try:
            queryset = self.filter_queryset(self.get_queryset())
            page = self.paginate_queryset(queryset)
            
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)
            
            serializer = self.get_serializer(queryset, many=True)
            return uniform_response(
                success=True,
                message="Survey responses retrieved successfully",
                data=serializer.data
            )
        except Exception as e:
            logger.error(f"Error listing survey responses: {e}")
            return uniform_response(
                success=False,
                message="Failed to retrieve responses",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def bulk_operations(request):
    """
    Perform bulk operations on multiple surveys.
    
    POST /api/surveys/bulk-operations/
    
    Body:
    {
        "operation": "activate|deactivate|lock|unlock|delete",
        "survey_ids": ["uuid1", "uuid2", "uuid3"]
    }
    """
    try:
        operation = request.data.get('operation')
        survey_ids = request.data.get('survey_ids', [])
        
        if not operation or not survey_ids:
            return uniform_response(
                success=False,
                message="Operation and survey_ids are required",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        if operation not in ['activate', 'deactivate', 'lock', 'unlock', 'delete']:
            return uniform_response(
                success=False,
                message="Invalid operation. Use: activate, deactivate, lock, unlock, delete",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if user is admin (only admins can perform bulk operations)
        if request.user.role not in ['admin']:
            return uniform_response(
                success=False,
                message="Only administrators can perform bulk operations",
                status_code=status.HTTP_403_FORBIDDEN
            )
        
        # Get surveys that user can modify
        surveys = Survey.objects.filter(
            id__in=survey_ids,
            deleted_at__isnull=True
        )
        
        # Filter to only surveys user can modify (creator or admin)
        if request.user.role != 'admin':
            surveys = surveys.filter(creator=request.user)
        
        successful = 0
        failed = 0
        errors = []
        
        for survey in surveys:
            try:
                if operation == 'activate':
                    survey.is_active = True
                elif operation == 'deactivate':
                    survey.is_active = False
                elif operation == 'lock':
                    survey.is_locked = True
                elif operation == 'unlock':
                    survey.is_locked = False
                elif operation == 'delete':
                    survey.soft_delete()
                    successful += 1
                    continue
                
                survey.save(update_fields=['is_active', 'is_locked', 'updated_at'])
                successful += 1
                
            except Exception as e:
                failed += 1
                errors.append(f"Survey {survey.id}: {str(e)}")
        
        logger.info(f"Bulk operation '{operation}' performed by {request.user.email}: {successful} successful, {failed} failed")
        
        return uniform_response(
            success=True,
            message="Bulk operation completed",
            data={
                'operation': operation,
                'successful': successful,
                'failed': failed,
                'errors': errors
            }
        )
        
    except Exception as e:
        logger.error(f"Error in bulk operations: {e}")
        return uniform_response(
            success=False,
            message="Failed to perform bulk operation",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """Health check endpoint for surveys service"""
    return uniform_response(
        success=True,
        message="Surveys service is healthy",
        data={
            'timestamp': timezone.now(),
            'version': '1.0.0',
            'encryption': 'active'
        }
    )


# Admin APIs - Survey Response Management
class AdminResponsesView(generics.ListAPIView):
    """
    Admin API to return all survey responses across the system with full details.
    
    GET /api/surveys/admin/responses/
    Access: Admin only
    """
    
    serializer_class = ResponseSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['survey', 'is_complete', 'respondent']
    search_fields = ['respondent__email', 'respondent_email']
    ordering_fields = ['submitted_at', 'survey__title']
    ordering = ['-submitted_at']
    
    def get_queryset(self):
        """Get all responses - admin only"""
        user = self.request.user
        
        if not user.is_authenticated or user.role not in ['admin']:
            return SurveyResponse.objects.none()
        
        queryset = SurveyResponse.objects.all().select_related(
            'survey', 'respondent'
        ).prefetch_related('answers__question')
        
        # Date range filtering
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        
        if start_date:
            try:
                start_dt = timezone.datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                queryset = queryset.filter(submitted_at__gte=start_dt)
            except ValueError:
                pass
        
        if end_date:
            try:
                end_dt = timezone.datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                queryset = queryset.filter(submitted_at__lte=end_dt)
            except ValueError:
                pass
        
        return queryset
    
    def list(self, request, *args, **kwargs):
        """List all responses with export options"""
        try:
            # Check admin permission
            if not request.user.is_authenticated or request.user.role not in ['admin']:
                return uniform_response(
                    success=False,
                    message="Admin access required",
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
            # Handle export requests
            export_format = request.query_params.get('export')
            if export_format in ['csv', 'json']:
                return self._export_responses(export_format)
            
            # Regular list response
            queryset = self.filter_queryset(self.get_queryset())
            page = self.paginate_queryset(queryset)
            
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)
            
            serializer = self.get_serializer(queryset, many=True)
            return uniform_response(
                success=True,
                message="All survey responses retrieved successfully",
                data={
                    'responses': serializer.data,
                    'total_count': queryset.count()
                }
            )
            
        except Exception as e:
            logger.error(f"Error listing admin responses: {e}")
            return uniform_response(
                success=False,
                message="Failed to retrieve responses",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _export_responses(self, format_type):
        """Export all responses in specified format"""
        try:
            queryset = self.filter_queryset(self.get_queryset())
            
            if format_type == 'csv':
                return self._export_csv_all_responses(queryset)
            else:  # json
                return self._export_json_all_responses(queryset)
                
        except Exception as e:
            logger.error(f"Error exporting admin responses: {e}")
            return uniform_response(
                success=False,
                message="Failed to export responses",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _export_csv_all_responses(self, queryset):
        """Export all responses as CSV"""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Headers
        headers = [
            'Response ID', 'Survey Title', 'Survey ID', 'Respondent Email', 
            'Respondent Type', 'Submitted At', 'Is Complete', 'IP Address'
        ]
        writer.writerow(headers)
        
        # Data rows
        for response in queryset:
            respondent_email = (
                response.respondent.email if response.respondent 
                else response.respondent_email or 'Anonymous'
            )
            respondent_type = 'Authenticated' if response.respondent else 'Anonymous'
            
            row = [
                str(response.id),
                response.survey.title,
                str(response.survey.id),
                respondent_email,
                respondent_type,
                response.submitted_at.strftime('%Y-%m-%d %H:%M:%S'),
                'Yes' if response.is_complete else 'No',
                response.ip_address or 'N/A'
            ]
            writer.writerow(row)
        
        # Create HTTP response
        http_response = HttpResponse(
            output.getvalue(),
            content_type='text/csv'
        )
        http_response['Content-Disposition'] = 'attachment; filename="all_survey_responses.csv"'
        
        logger.info(f"Admin responses exported as CSV by {self.request.user.email}")
        return http_response
    
    def _export_json_all_responses(self, queryset):
        """Export all responses as JSON"""
        import json
        
        export_data = {
            'exported_at': timezone.now().isoformat(),
            'total_responses': queryset.count(),
            'exported_by': self.request.user.email,
            'responses': []
        }
        
        for response in queryset:
            response_data = {
                'id': str(response.id),
                'survey': {
                    'id': str(response.survey.id),
                    'title': response.survey.title,
                    'description': response.survey.description
                },
                'respondent': {
                    'email': (
                        response.respondent.email if response.respondent 
                        else response.respondent_email
                    ),
                    'type': 'authenticated' if response.respondent else 'anonymous',
                    'user_id': str(response.respondent.id) if response.respondent else None
                },
                'submitted_at': response.submitted_at.isoformat(),
                'is_complete': response.is_complete,
                'ip_address': response.ip_address,
                'answers': []
            }
            
            for answer in response.answers.all():
                response_data['answers'].append({
                    'question_id': str(answer.question.id),
                    'question_text': answer.question.text,
                    'question_type': answer.question.question_type,
                    'question_order': answer.question.order,
                    'answer_text': answer.answer_text
                })
            
            export_data['responses'].append(response_data)
        
        # Create HTTP response
        http_response = HttpResponse(
            json.dumps(export_data, indent=2),
            content_type='application/json'
        )
        http_response['Content-Disposition'] = 'attachment; filename="all_survey_responses.json"'
        
        logger.info(f"Admin responses exported as JSON by {self.request.user.email}")
        return http_response


class AdminSurveyResponsesView(generics.ListAPIView):
    """
    Admin API to get all responses for a specific survey with answers.
    
    GET /api/surveys/admin/surveys/{survey_id}/responses/
    Access: Admin only
    """
    
    serializer_class = ResponseSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['is_complete', 'respondent']
    ordering_fields = ['submitted_at']
    ordering = ['-submitted_at']
    
    def get_queryset(self):
        """Get responses for specific survey - admin only"""
        user = self.request.user
        
        if not user.is_authenticated or user.role not in ['admin']:
            return SurveyResponse.objects.none()
        
        survey_id = self.kwargs.get('survey_id')
        survey = get_object_or_404(Survey, id=survey_id, deleted_at__isnull=True)
        
        return survey.responses.all().select_related(
            'respondent'
        ).prefetch_related('answers__question')
    
    def list(self, request, *args, **kwargs):
        """List responses for specific survey with detailed answers"""
        try:
            # Check admin permission
            if not request.user.is_authenticated or request.user.role not in ['admin']:
                return uniform_response(
                    success=False,
                    message="Admin access required",
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
            survey_id = self.kwargs.get('survey_id')
            survey = get_object_or_404(Survey, id=survey_id, deleted_at__isnull=True)
            
            queryset = self.filter_queryset(self.get_queryset())
            page = self.paginate_queryset(queryset)
            
            # Prepare detailed response data
            response_data = []
            responses_to_process = page if page is not None else queryset
            
            for response in responses_to_process:
                respondent_info = {}
                if response.respondent:
                    respondent_info = {
                        'id': response.respondent.id,
                        'email': response.respondent.email,
                        'name': response.respondent.full_name,
                        'type': 'authenticated'
                    }
                else:
                    respondent_info = {
                        'email': response.respondent_email or 'Anonymous',
                        'type': 'anonymous'
                    }
                
                # Get all answers with question context
                answers_with_context = []
                for answer in response.answers.all():
                    answer_data = {
                        'question_id': str(answer.question.id),
                        'question_text': answer.question.text,
                        'question_type': answer.question.question_type,
                        'question_order': answer.question.order,
                        'is_required': answer.question.is_required,
                        'answer_text': answer.answer_text
                    }
                    
                    # Add options for choice questions
                    if answer.question.question_type in ['single_choice', 'multiple_choice', 'rating']:
                        try:
                            options = json.loads(answer.question.options) if answer.question.options else []
                            answer_data['question_options'] = options
                        except (json.JSONDecodeError, TypeError):
                            answer_data['question_options'] = []
                    
                    answers_with_context.append(answer_data)
                
                response_item = {
                    'id': str(response.id),
                    'submitted_at': response.submitted_at.isoformat(),
                    'is_complete': response.is_complete,
                    'ip_address': response.ip_address,
                    'respondent': respondent_info,
                    'answers': answers_with_context,
                    'answer_count': len(answers_with_context)
                }
                
                response_data.append(response_item)
            
            # Survey context information
            survey_context = {
                'id': str(survey.id),
                'title': survey.title,
                'description': survey.description,
                'visibility': survey.visibility,
                'is_active': survey.is_active,
                'created_at': survey.created_at.isoformat(),
                'creator_email': survey.creator.email,
                'total_questions': survey.questions.count(),
                'total_responses': survey.responses.count()
            }
            
            if page is not None:
                # Return paginated response
                paginated_data = self.get_paginated_response(response_data)
                paginated_data.data['survey'] = survey_context
                return paginated_data
            
            return uniform_response(
                success=True,
                message="Survey responses retrieved successfully",
                data={
                    'survey': survey_context,
                    'responses': response_data,
                    'total_count': queryset.count()
                }
            )
            
        except Exception as e:
            logger.error(f"Error listing admin survey responses: {e}")
            return uniform_response(
                success=False,
                message="Failed to retrieve survey responses",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# Token-Based Access APIs
class TokenSurveysView(APIView):
    """
    Retrieve a list of surveys accessible by a specific token.
    
    GET /api/surveys/token/surveys/
    Access: Requires token validation via Authorization: Bearer <token> header
    """
    
    permission_classes = [AllowAny]  # Handle token validation manually
    
    def _validate_token(self, request):
        """Validate bearer token and return associated surveys"""
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None, "Authorization header with Bearer token is required"
        
        token = auth_header.split(' ')[1]
        
        try:
            access_token = PublicAccessToken.objects.select_related('survey').get(
                token=token,
                is_active=True
            )
            
            if not access_token.is_valid():
                return None, "Token has expired"
            
            if not access_token.survey.is_active or access_token.survey.deleted_at is not None:
                return None, "Associated survey is not active"
            
            if not access_token.survey.is_currently_active():
                return None, get_arabic_status_message(access_token.survey)
            
            return access_token, None
            
        except PublicAccessToken.DoesNotExist:
            return None, "Invalid token"
    
    def get(self, request):
        """Get surveys accessible by token"""
        try:
            access_token, error_msg = self._validate_token(request)
            
            if error_msg:
                return uniform_response(
                    success=False,
                    message=error_msg,
                    status_code=status.HTTP_401_UNAUTHORIZED
                )
            
            # Get the survey associated with this token
            survey = access_token.survey
            
            survey_data = {
                'id': str(survey.id),
                'title': survey.title,
                'description': survey.description,
                'estimated_time': max(survey.questions.count() * 1, 5),
                'questions_count': survey.questions.count(),
                'visibility': survey.visibility,
                'is_active': survey.is_active,
                'created_at': survey.created_at.isoformat(),
                'creator_email': survey.creator.email,
                'access_permissions': {
                    'can_submit': True,
                    'can_view_results': False,
                    'access_type': 'token'
                },
                'token_info': {
                    'expires_at': access_token.expires_at.isoformat(),
                    'is_expired': access_token.is_expired(),
                    'created_at': access_token.created_at.isoformat()
                }
            }
            
            return uniform_response(
                success=True,
                message="Token-accessible surveys retrieved successfully",
                data={
                    'surveys': [survey_data],
                    'total_count': 1
                }
            )
            
        except Exception as e:
            logger.error(f"Error retrieving token surveys: {e}")
            return uniform_response(
                success=False,
                message="Failed to retrieve surveys",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class TokenSurveyDetailView(APIView):
    """
    Retrieve full survey details for user participation via token.
    
    GET /api/surveys/token/surveys/{survey_id}/
    Access: Requires token validation via Authorization: Bearer <token> header + survey access check
    """
    
    permission_classes = [AllowAny]  # Handle token validation manually
    
    def _validate_token_access(self, request, survey_id):
        """Validate token and survey access"""
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None, None, "Authorization header with Bearer token is required"
        
        token = auth_header.split(' ')[1]
        
        try:
            # Get survey first
            survey = Survey.objects.get(id=survey_id, deleted_at__isnull=True)
            
            # Validate token access to this specific survey
            access_token = PublicAccessToken.objects.get(
                token=token,
                survey=survey,
                is_active=True
            )
            
            if not access_token.is_valid():
                return None, None, "Token has expired"
            
            if not survey.is_active:
                return None, None, "Survey is not active"
            
            if not survey.is_currently_active():
                return None, None, get_arabic_status_message(survey)
            
            return access_token, survey, None
            
        except Survey.DoesNotExist:
            return None, None, "Survey not found"
        except PublicAccessToken.DoesNotExist:
            return None, None, "Token does not have access to this survey"
    
    def get(self, request, survey_id):
        """Get full survey details for token access"""
        try:
            access_token, survey, error_msg = self._validate_token_access(request, survey_id)
            
            if error_msg:
                return uniform_response(
                    success=False,
                    message=error_msg,
                    status_code=status.HTTP_401_UNAUTHORIZED if "Token" in error_msg else status.HTTP_404_NOT_FOUND
                )
            
            # Get all questions with complete data
            questions = survey.questions.all().order_by('order')
            question_serializer = QuestionSerializer(questions, many=True)
            
            # Check if user has already submitted a response
            has_submitted = False
            if request.user.is_authenticated:
                has_submitted = SurveyResponse.objects.filter(
                    survey=survey,
                    respondent=request.user
                ).exists()
            
            survey_data = {
                'id': str(survey.id),
                'title': survey.title,
                'description': survey.description,
                'visibility': survey.visibility,
                'is_active': survey.is_active,
                'is_locked': survey.is_locked,
                'estimated_time': max(survey.questions.count() * 1, 5),
                'questions_count': survey.questions.count(),
                'created_at': survey.created_at.isoformat(),
                'updated_at': survey.updated_at.isoformat(),
                'creator_email': survey.creator.email,
                'questions': question_serializer.data,
                'access_info': {
                    'access_type': 'token',
                    'token_expires_at': access_token.expires_at.isoformat(),
                    'can_submit': not has_submitted,
                    'has_submitted': has_submitted,
                    'submission_instructions': {
                        'endpoint': '/api/surveys/responses/',
                        'method': 'POST',
                        'required_fields': ['survey_id', 'token', 'answers'],
                        'optional_fields': ['email']
                    }
                },
                'submission_guidelines': {
                    'email_required': survey.visibility == 'PUBLIC' and not request.user.is_authenticated,
                    'authentication_required': survey.visibility in ['AUTH', 'PRIVATE'],
                    'answer_format': {
                        'question_id': 'UUID of the question',
                        'answer': 'Your answer text/value'
                    }
                }
            }
            
            return uniform_response(
                success=True,
                message="Survey details retrieved successfully",
                data=survey_data
            )
            
        except Exception as e:
            logger.error(f"Error retrieving token survey details: {e}")
            return uniform_response(
                success=False,
                message="Failed to retrieve survey details",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
