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
    Generate Arabic status messages with proper date and time formatting for surveys
    """
    status = survey.get_status()
    
    # Helper function to format dates and times in Arabic
    def format_datetime_arabic(date):
        if not date:
            return None
        # Format as: YYYY-MM-DD HH:MM (24-hour format)
        return date.strftime('%Y-%m-%d %H:%M')
    
    def format_date_only_arabic(date):
        if not date:
            return None
        return date.strftime('%Y-%m-%d')
    
    start_datetime_str = format_datetime_arabic(survey.start_date)
    end_datetime_str = format_datetime_arabic(survey.end_date)
    start_date_str = format_date_only_arabic(survey.start_date)
    end_date_str = format_date_only_arabic(survey.end_date)
    
    if status == 'scheduled':
        if start_datetime_str and end_datetime_str:
            return f"من المقرر إجراء الاستطلاع في الفترة من {start_datetime_str} إلى {end_datetime_str}"
        elif start_datetime_str:
            return f"من المقرر إجراء الاستطلاع بدءاً من {start_datetime_str}"
        elif start_date_str and end_date_str:
            return f"من المقرر إجراء الاستطلاع في الفترة من {start_date_str} إلى {end_date_str}"
        elif start_date_str:
            return f"من المقرر إجراء الاستطلاع بدءاً من {start_date_str}"
        else:
            return "الاستطلاع مجدول للبدء قريباً"
    
    elif status == 'expired':
        if end_datetime_str:
            return f"انتهت صلاحية الاستطلاع في {end_datetime_str}"
        elif end_date_str:
            return f"انتهت صلاحية الاستطلاع في {end_date_str}"
        else:
            return "انتهت صلاحية الاستطلاع"
    
    elif status == 'inactive':
        return "الاستطلاع غير نشط حالياً"
    
    elif status == 'deleted':
        return "الاستطلاع محذوف"
    
    elif status == 'active':
        if end_datetime_str:
            return f"الاستطلاع نشط حتى {end_datetime_str}"
        elif end_date_str:
            return f"الاستطلاع نشط حتى {end_date_str}"
        elif start_datetime_str and end_datetime_str:
            return f"الاستطلاع نشط من {start_datetime_str} حتى {end_datetime_str}"
        elif start_date_str and end_date_str:
            return f"الاستطلاع نشط من {start_date_str} حتى {end_date_str}"
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
        'access_completed': 'تم الوصول بنجاح',
        'link_switched_to_public': 'تم إلغاء الرابط المحمي بكلمة مرور وتفعيل الرابط العام للاستطلاع',
        'link_switched_to_password': 'تم إلغاء الرابط العام وتفعيل الرابط المحمي بكلمة مرور للاستطلاع'
    }


def check_link_switch_reason(token):
    """
    Check if a token was deactivated due to link type switching.
    
    Args:
        token: The token string to check
    
    Returns:
        dict: Information about why the token is inactive
    """
    try:
        # Find the token regardless of active status
        access_token = PublicAccessToken.objects.select_related('survey').filter(
            token=token
        ).first()
        
        if not access_token:
            return {'is_switched': False, 'message': get_arabic_error_messages()['invalid_token']}
        
        if access_token.is_active:
            return {'is_switched': False, 'message': None}
        
        # Check if token was deactivated and there are active tokens of opposite type
        survey = access_token.survey
        
        # Check if this was a password-protected token and there are now public tokens
        if access_token.is_password_protected():
            active_public_tokens = PublicAccessToken.objects.filter(
                survey=survey,
                is_active=True,
                password__isnull=True
            ).exists()
            
            if active_public_tokens:
                return {
                    'is_switched': True,
                    'message': 'تم إلغاء الرابط المحمي بكلمة مرور وتفعيل رابط عام جديد للاستطلاع. يرجى طلب الرابط الجديد من منشئ الاستطلاع.'
                }
        
        # Check if this was a public token and there are now password-protected tokens
        else:
            active_password_tokens = PublicAccessToken.objects.filter(
                survey=survey,
                is_active=True,
                password__isnull=False
            ).exists()
            
            if active_password_tokens:
                return {
                    'is_switched': True,
                    'message': 'تم إلغاء الرابط العام وتفعيل رابط محمي بكلمة مرور للاستطلاع. يرجى طلب الرابط الجديد وكلمة المرور من منشئ الاستطلاع.'
                }
        
        # Token was deactivated for other reasons
        return {'is_switched': False, 'message': get_arabic_error_messages()['invalid_token']}
        
    except Exception as e:
        logger.error(f"Error checking link switch reason for token {token}: {e}")
        return {'is_switched': False, 'message': get_arabic_error_messages()['invalid_token']}


def close_all_existing_tokens(survey, user):
    """
    Close ALL existing active tokens for a survey to ensure only one token is valid at a time.
    
    Args:
        survey: The Survey instance
        user: The user performing the action
    
    Returns:
        dict: Information about closed links
    """
    try:
        # Close ALL active tokens for this survey
        closed_tokens = PublicAccessToken.objects.filter(
            survey=survey,
            is_active=True
        )
        
        # Get counts and types before closing
        password_count = closed_tokens.filter(password__isnull=False).count()
        public_count = closed_tokens.filter(password__isnull=True).count()
        total_closed = closed_tokens.count()
        
        # Close all tokens
        closed_tokens.update(is_active=False)
        
        closed_info = {
            'closed_links': total_closed,
            'password_links_closed': password_count,
            'public_links_closed': public_count,
            'message': None
        }
        
        if password_count > 0 and public_count > 0:
            closed_info['message'] = "تم إلغاء جميع الروابط السابقة (عامة ومحمية بكلمة مرور)"
        elif password_count > 0:
            closed_info['message'] = "تم إلغاء الروابط المحمية بكلمة مرور السابقة"
        elif public_count > 0:
            closed_info['message'] = "تم إلغاء الروابط العامة السابقة"
        
        if total_closed > 0:
            logger.info(f"Closed {total_closed} tokens for survey {survey.id} by {getattr(user, 'email', 'anonymous')}: {password_count} password, {public_count} public")
        
        return closed_info
        
    except Exception as e:
        logger.error(f"Error closing tokens for survey {survey.id}: {e}")
        return {'closed_links': 0, 'password_links_closed': 0, 'public_links_closed': 0, 'message': None}


def close_opposite_link_type(survey, link_type, user):
    """
    Close the opposite link type when a new link is generated.
    
    Args:
        survey: The Survey instance
        link_type: 'public' or 'password' - the type being generated
        user: The user generating the link
    
    Returns:
        dict: Information about closed links
    """
    try:
        closed_info = {
            'closed_links': 0,
            'closed_type': None,
            'message': None
        }
        
        if link_type == 'public':
            # Close password-protected links
            closed_count = PublicAccessToken.objects.filter(
                survey=survey,
                is_active=True,
                password__isnull=False
            ).update(is_active=False)
            
            if closed_count > 0:
                closed_info.update({
                    'closed_links': closed_count,
                    'closed_type': 'password',
                    'message': get_arabic_error_messages()['link_switched_to_public']
                })
                logger.info(f"Closed {closed_count} password-protected links for survey {survey.id} when generating public link by {getattr(user, 'email', 'anonymous')}")
        
        elif link_type == 'password':
            # Close public (non-password) links
            closed_count = PublicAccessToken.objects.filter(
                survey=survey,
                is_active=True,
                password__isnull=True
            ).update(is_active=False)
            
            if closed_count > 0:
                closed_info.update({
                    'closed_links': closed_count,
                    'closed_type': 'public',
                    'message': get_arabic_error_messages()['link_switched_to_password']
                })
                logger.info(f"Closed {closed_count} public links for survey {survey.id} when generating password-protected link by {getattr(user, 'email', 'anonymous')}")
        
        return closed_info
        
    except Exception as e:
        logger.error(f"Error closing opposite link type for survey {survey.id}: {e}")
        return {'closed_links': 0, 'closed_type': None, 'message': None}


    """
    Close the opposite link type when a new link is generated.
    
    Args:
        survey: The Survey instance
        link_type: 'public' or 'password' - the type being generated
        user: The user generating the link
    
    Returns:
        dict: Information about closed links
    """
    try:
        closed_info = {
            'closed_links': 0,
            'closed_type': None,
            'message': None
        }
        
        if link_type == 'public':
            # Close password-protected links
            closed_count = PublicAccessToken.objects.filter(
                survey=survey,
                is_active=True,
                password__isnull=False
            ).update(is_active=False)
            
            if closed_count > 0:
                closed_info.update({
                    'closed_links': closed_count,
                    'closed_type': 'password',
                    'message': get_arabic_error_messages()['link_switched_to_public']
                })
                logger.info(f"Closed {closed_count} password-protected links for survey {survey.id} when generating public link by {user.email}")
        
        elif link_type == 'password':
            # Close public (non-password) links
            closed_count = PublicAccessToken.objects.filter(
                survey=survey,
                is_active=True,
                password__isnull=True
            ).update(is_active=False)
            
            if closed_count > 0:
                closed_info.update({
                    'closed_links': closed_count,
                    'closed_type': 'public',
                    'message': get_arabic_error_messages()['link_switched_to_password']
                })
                logger.info(f"Closed {closed_count} public links for survey {survey.id} when generating password-protected link by {user.email}")
        
        return closed_info
        
    except Exception as e:
        logger.error(f"Error closing opposite link type for survey {survey.id}: {e}")
        return {'closed_links': 0, 'closed_type': None, 'message': None}


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
        
        if user.role == 'super_admin':
            # Super admin sees all surveys
            return self.queryset
        
        if user.role in ['admin', 'manager']:
            # Admin/Manager see only their own surveys
            return self.queryset.filter(creator=user)
        
        # Regular users see their own surveys, shared surveys, public/auth surveys, and group-shared surveys
        user_groups = user.user_groups.values_list('group', flat=True)
        # Oracle fix: defer NCLOB fields when using distinct() to avoid ORA-00932 error
        return self.queryset.filter(
            Q(creator=user) |
            Q(shared_with=user) |
            Q(shared_with_groups__in=user_groups) |
            Q(visibility='PUBLIC') |
            Q(visibility='AUTH')
        ).distinct().defer('description')
    
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
        """Update survey with comprehensive access token management on visibility changes"""
        try:
            survey = self.get_object()
            user = request.user
            
            # Check if user can update the survey
            if user.role == 'super_admin':
                # Super admin can update any survey
                pass
            elif user.role in ['admin', 'manager']:
                # Admin/Manager can only update their own surveys
                if survey.creator != user:
                    return uniform_response(
                        success=False,
                        message="You can only update surveys you created",
                        status_code=status.HTTP_403_FORBIDDEN
                    )
            else:
                # Regular users can only update their own surveys
                if survey.creator != user:
                    return uniform_response(
                        success=False,
                        message="You can only update surveys you created",
                        status_code=status.HTTP_403_FORBIDDEN
                    )
            
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
            
            # Handle public access token management based on visibility changes
            new_visibility = serializer.instance.visibility
            tokens_message = ""
            
            if old_visibility != new_visibility:
                if old_visibility == 'PUBLIC':
                    # When changing FROM PUBLIC to any other visibility:
                    # Invalidate ALL public access tokens (including password-protected ones)
                    if new_visibility in ['AUTH', 'PRIVATE', 'GROUPS']:
                        invalidated_count = PublicAccessToken.objects.filter(
                            survey=survey,
                            is_active=True
                        ).update(is_active=False)
                        
                        tokens_message = f" Invalidated {invalidated_count} public access tokens."
                        logger.info(f"Survey {survey.id} visibility changed from PUBLIC to {new_visibility}. "
                                   f"Invalidated {invalidated_count} public tokens.")
                
                elif new_visibility != 'PUBLIC' and old_visibility in ['AUTH', 'PRIVATE', 'GROUPS']:
                    # When changing between non-PUBLIC visibilities:
                    # Invalidate public access tokens but keep password-protected ones if they exist
                    invalidated_count = PublicAccessToken.objects.filter(
                        survey=survey,
                        is_active=True,
                        password__isnull=True  # Only invalidate non-password-protected tokens
                    ).update(is_active=False)
                    
                    if invalidated_count > 0:
                        tokens_message = f" Invalidated {invalidated_count} non-password-protected tokens."
                        logger.info(f"Survey {survey.id} visibility changed from {old_visibility} to {new_visibility}. "
                                   f"Invalidated {invalidated_count} non-password-protected tokens.")
                
                # Special handling when changing TO PUBLIC
                elif new_visibility == 'PUBLIC':
                    # When changing TO PUBLIC, we might want to keep existing tokens active
                    # or create new ones - this depends on business logic
                    logger.info(f"Survey {survey.id} visibility changed to PUBLIC from {old_visibility}. "
                               f"Existing tokens remain active.")
                    tokens_message = " Survey is now publicly accessible."
            
            success_message = "Survey updated successfully"
            if tokens_message:
                success_message += tokens_message
            
            logger.info(f"Survey {survey.id} updated by {user.email} (role: {user.role})")
            
            return uniform_response(
                success=True,
                message=success_message,
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
    
    def destroy(self, request, *args, **kwargs):
        """Delete survey with role-based access control"""
        try:
            survey = self.get_object()
            user = request.user
            
            # Check if user can delete the survey
            if user.role == 'super_admin':
                # Super admin can delete any survey
                pass
            elif user.role in ['admin', 'manager']:
                # Admin/Manager can only delete their own surveys
                if survey.creator != user:
                    return uniform_response(
                        success=False,
                        message="You can only delete surveys you created",
                        status_code=status.HTTP_403_FORBIDDEN
                    )
            else:
                # Regular users can only delete their own surveys
                if survey.creator != user:
                    return uniform_response(
                        success=False,
                        message="You can only delete surveys you created",
                        status_code=status.HTTP_403_FORBIDDEN
                    )
            
            # Perform soft delete
            survey.soft_delete()
            
            logger.info(f"Survey {survey.id} deleted by {user.email} (role: {user.role})")
            
            return uniform_response(
                success=True,
                message="Survey deleted successfully",
                status_code=status.HTTP_204_NO_CONTENT
            )
            
        except Exception as e:
            logger.error(f"Error deleting survey: {e}")
            return uniform_response(
                success=False,
                message="Failed to delete survey",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['post'], permission_classes=[IsCreatorOrReadOnly])
    def audience(self, request, pk=None):
        """
        Set survey audience and sharing settings with comprehensive token management.
        
        Body examples:
        {"visibility": "AUTH"}                        # everyone with token
        {"visibility": "PUBLIC"}                      # world-readable  
        {"visibility": "PRIVATE", "user_ids":[1,2]}   # share with list
        {"visibility": "GROUPS", "group_ids":[1,2]}   # share with all users in groups
        """
        try:
            survey = self.get_object()
            user = request.user
            
            # Check if user can modify the survey audience
            if user.role == 'super_admin':
                # Super admin can modify any survey
                pass
            elif user.role in ['admin', 'manager']:
                # Admin/Manager can only modify their own surveys
                if survey.creator != user:
                    return uniform_response(
                        success=False,
                        message="You can only modify surveys you created",
                        status_code=status.HTTP_403_FORBIDDEN
                    )
            else:
                # Regular users can only modify their own surveys
                if survey.creator != user:
                    return uniform_response(
                        success=False,
                        message="You can only modify surveys you created",
                        status_code=status.HTTP_403_FORBIDDEN
                    )
            
            old_visibility = survey.visibility
            
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
            
            # Handle public access token management based on visibility changes
            tokens_message = ""
            if old_visibility != visibility:
                if old_visibility == 'PUBLIC':
                    # When changing FROM PUBLIC to any other visibility:
                    # Invalidate ALL public access tokens
                    if visibility in ['AUTH', 'PRIVATE', 'GROUPS']:
                        invalidated_count = PublicAccessToken.objects.filter(
                            survey=survey,
                            is_active=True
                        ).update(is_active=False)
                        
                        tokens_message = f" Invalidated {invalidated_count} public access tokens."
                        logger.info(f"Survey {survey.id} visibility changed from PUBLIC to {visibility}. "
                                   f"Invalidated {invalidated_count} public tokens.")
                
                elif visibility != 'PUBLIC' and old_visibility in ['AUTH', 'PRIVATE', 'GROUPS']:
                    # When changing between non-PUBLIC visibilities:
                    # Invalidate non-password-protected public access tokens
                    invalidated_count = PublicAccessToken.objects.filter(
                        survey=survey,
                        is_active=True,
                        password__isnull=True  # Only invalidate non-password-protected tokens
                    ).update(is_active=False)
                    
                    if invalidated_count > 0:
                        tokens_message = f" Invalidated {invalidated_count} non-password-protected tokens."
                        logger.info(f"Survey {survey.id} visibility changed from {old_visibility} to {visibility}. "
                                   f"Invalidated {invalidated_count} non-password-protected tokens.")
                
                # Special handling when changing TO PUBLIC
                elif visibility == 'PUBLIC':
                    logger.info(f"Survey {survey.id} visibility changed to PUBLIC from {old_visibility}. "
                               f"Existing tokens remain active.")
                    tokens_message = " Survey is now publicly accessible."
            
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
            
            success_message = "Survey audience updated successfully"
            if tokens_message:
                success_message += tokens_message
            
            logger.info(f"Survey {survey.id} audience updated by {request.user.email}")
            
            response_data = {'visibility': visibility}
            if visibility == 'PRIVATE':
                response_data['shared_count'] = survey.shared_with.count()
            elif visibility == 'GROUPS':
                response_data['shared_groups_count'] = survey.shared_with_groups.count()
            
            return uniform_response(
                success=True,
                message=success_message,
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
            user = request.user
            
            # Check if user can add questions to the survey
            if user.role == 'super_admin':
                # Super admin can add questions to any survey
                pass
            elif user.role in ['admin', 'manager']:
                # Admin/Manager can only add questions to their own surveys
                if survey.creator != user:
                    return uniform_response(
                        success=False,
                        message="You can only add questions to surveys you created",
                        status_code=status.HTTP_403_FORBIDDEN
                    )
            else:
                # Regular users can only add questions to their own surveys
                if survey.creator != user:
                    return uniform_response(
                        success=False,
                        message="You can only add questions to surveys you created",
                        status_code=status.HTTP_403_FORBIDDEN
                    )
            
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
                logger.info(f"Question added to survey {survey.id} by {user.email} (role: {user.role})")
                
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
            user = request.user
            
            # Check if user can update the question
            if user.role == 'super_admin':
                # Super admin can update any question
                pass
            elif user.role in ['admin', 'manager']:
                # Admin/Manager can only update questions from their own surveys
                if survey.creator != user:
                    return uniform_response(
                        success=False,
                        message="You can only update questions from surveys you created",
                        status_code=status.HTTP_403_FORBIDDEN
                    )
            else:
                # Regular users can only update questions from their own surveys
                if survey.creator != user:
                    return uniform_response(
                        success=False,
                        message="You can only update questions from surveys you created",
                        status_code=status.HTTP_403_FORBIDDEN
                    )
            
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
                logger.info(f"Question {question_id} updated in survey {survey.id} by {user.email} (role: {user.role})")
                
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
            user = request.user
            
            # Check if user can delete the question
            if user.role == 'super_admin':
                # Super admin can delete any question
                pass
            elif user.role in ['admin', 'manager']:
                # Admin/Manager can only delete questions from their own surveys
                if survey.creator != user:
                    return uniform_response(
                        success=False,
                        message="You can only delete questions from surveys you created",
                        status_code=status.HTTP_403_FORBIDDEN
                    )
            else:
                # Regular users can only delete questions from their own surveys
                if survey.creator != user:
                    return uniform_response(
                        success=False,
                        message="You can only delete questions from surveys you created",
                        status_code=status.HTTP_403_FORBIDDEN
                    )
            
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
            logger.info(f"Question {question_id} deleted from survey {survey.id} by {user.email} (role: {user.role})")
            
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
        Only works for surveys with PUBLIC or AUTH visibility.
        
        POST /api/surveys/surveys/{survey_id}/generate-link/
        """
        try:
            survey = self.get_object()
            
            # Check if survey visibility allows public access
            if survey.visibility not in ['PUBLIC', 'AUTH']:
                return uniform_response(
                    success=False,
                    message=f"Cannot generate public link for {survey.visibility} survey. "
                           f"Change visibility to PUBLIC or AUTH first.",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            # Check if survey is active
            if not survey.is_active:
                return uniform_response(
                    success=False,
                    message="Cannot generate public link for inactive survey.",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            # Generate unique token
            token = PublicAccessToken.generate_token()
            
            # Set expiration (default 30 days from now)
            days_to_expire = request.data.get('days_to_expire', 30)
            expires_at = timezone.now() + timedelta(days=days_to_expire)
            
            # Deactivate any existing non-password-protected tokens for this survey
            PublicAccessToken.objects.filter(
                survey=survey,
                is_active=True,
                password__isnull=True  # Only deactivate non-password-protected tokens
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
                    'expires_at': expires_at.isoformat(),
                    'survey_visibility': survey.visibility,
                    'note': 'This link will become invalid if survey visibility changes from PUBLIC/AUTH'
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

    @action(detail=True, methods=['post'], permission_classes=[IsCreatorOrReadOnly], url_path='generate-password-link')
    def generate_password_link(self, request, pk=None):
        """
        Generate a password-protected public access link for the survey.
        Works for any survey visibility - password protection allows access control.
        
        POST /api/surveys/surveys/{survey_id}/generate-password-link/
        Body:
        {
            "days_to_expire": 30,  // optional, default 30
            "restricted_email": ["user1@example.com", "user2@example.com"],  // optional, restrict to these emails
            "restricted_phone": ["+1234567890", "+0987654321"]  // optional, restrict to these phones
        }
        """
        try:
            survey = self.get_object()
            
            # Check if survey is active
            if not survey.is_active:
                return uniform_response(
                    success=False,
                    message="Cannot generate password-protected link for inactive survey.",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate input
            restricted_email = request.data.get('restricted_email', [])
            restricted_phone = request.data.get('restricted_phone', [])
            
            # Ensure they are lists
            if not isinstance(restricted_email, list):
                restricted_email = [restricted_email] if restricted_email else []
            if not isinstance(restricted_phone, list):
                restricted_phone = [restricted_phone] if restricted_phone else []
            
            # Validate email formats
            if restricted_email:
                from django.core.validators import validate_email
                from django.core.exceptions import ValidationError
                for email in restricted_email:
                    try:
                        validate_email(email)
                    except ValidationError:
                        return uniform_response(
                            success=False,
                            message=f"Invalid email format: {email}",
                            status_code=status.HTTP_400_BAD_REQUEST
                        )
            
            # Generate unique token and password
            token = PublicAccessToken.generate_token()
            password = PublicAccessToken.generate_password()
            
            # Set expiration (default 30 days from now)
            days_to_expire = request.data.get('days_to_expire', 30)
            expires_at = timezone.now() + timedelta(days=days_to_expire)
            
            # Close ALL existing tokens to ensure only one is active at a time
            closed_info = close_all_existing_tokens(survey, request.user)
            
            # Create the new password-protected token record
            public_token = PublicAccessToken.objects.create(
                survey=survey,
                token=token,
                password=password,
                expires_at=expires_at,
                created_by=request.user
            )
            
            # Set the restricted contacts using helper methods
            public_token.set_restricted_emails(restricted_email)
            public_token.set_restricted_phones(restricted_phone)
            public_token.save()
            
            logger.info(f"Password-protected link generated for survey {survey.id} by {request.user.email}")
            
            response_data = {
                'token': token,
                'password': password,
                'expires_at': expires_at.isoformat(),
                'is_password_protected': True,
                'is_contact_restricted': bool(restricted_email or restricted_phone),
                'survey_visibility': survey.visibility,
                'note': 'Password-protected links work regardless of survey visibility changes'
            }
            
            if restricted_email:
                response_data['restricted_email'] = restricted_email
            if restricted_phone:
                response_data['restricted_phone'] = restricted_phone
            
            # Add information about closed links
            if closed_info['closed_links'] > 0:
                closed_type = []
                if closed_info['password_links_closed'] > 0:
                    closed_type.append('password')
                if closed_info['public_links_closed'] > 0:
                    closed_type.append('public')
                
                response_data['closed_links_info'] = {
                    'closed_count': closed_info['closed_links'],
                    'closed_type': ', '.join(closed_type) if closed_type else 'unknown',
                    'message': closed_info['message']
                }
            
            message = "Password-protected link generated successfully"
            if closed_info['message']:
                message += f". {closed_info['message']}"
            
            return uniform_response(
                success=True,
                message=message,
                data=response_data,
                status_code=status.HTTP_201_CREATED
            )
            
        except Exception as e:
            logger.error(f"Error generating password-protected link for survey {pk}: {e}")
            return uniform_response(
                success=False,
                message="Failed to generate password-protected link",
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
                # Don't automatically close tokens on GET - just retrieve existing ones
                # Only close tokens when we're actually creating new ones
                
                # Get all active public tokens for this survey (excluding password-protected ones)
                active_tokens = PublicAccessToken.objects.filter(
                    survey=survey,
                    is_active=True,
                    password__isnull=True  # Only get public (non-password) tokens
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
                    # Check if we can auto-generate a public link
                    if survey.visibility not in ['PUBLIC', 'AUTH']:
                        return uniform_response(
                            success=False,
                            message=f"No public links found. Cannot auto-generate for {survey.visibility} survey. "
                                   f"Change visibility to PUBLIC or AUTH first, or use password-protected links.",
                            status_code=status.HTTP_404_NOT_FOUND
                        )
                    
                    if not survey.is_active:
                        return uniform_response(
                            success=False,
                            message="No public links found for inactive survey.",
                            status_code=status.HTTP_404_NOT_FOUND
                        )
                    
                    # Auto-generate a public link if none exists (for user convenience)
                    try:
                        # Close ALL existing tokens to ensure only one is active at a time
                        closed_info = close_all_existing_tokens(survey, request.user)
                        
                        # Generate unique token
                        token = PublicAccessToken.generate_token()
                        
                        # Set expiration (default 30 days from now)
                        expires_at = timezone.now() + timedelta(days=30)
                        
                        # Create the new token record
                        public_token = PublicAccessToken.objects.create(
                            survey=survey,
                            token=token,
                            expires_at=expires_at,
                            created_by=request.user
                        )
                        
                        logger.info(f"Auto-generated public link for survey {survey.id} by {request.user.email}")
                        
                        response_data = {
                            'token': token,
                            'expires_at': expires_at.isoformat(),
                            'auto_generated': True,
                            'survey_visibility': survey.visibility,
                            'note': 'This link will become invalid if survey visibility changes from PUBLIC/AUTH'
                        }
                        
                        # Add information about closed links
                        if closed_info['closed_links'] > 0:
                            closed_type = []
                            if closed_info['password_links_closed'] > 0:
                                closed_type.append('password')
                            if closed_info['public_links_closed'] > 0:
                                closed_type.append('public')
                            
                            response_data['closed_links_info'] = {
                                'closed_count': closed_info['closed_links'],
                                'closed_type': ', '.join(closed_type) if closed_type else 'unknown',
                                'message': closed_info['message']
                            }
                        
                        message = "Public link auto-generated successfully"
                        if closed_info['message']:
                            message += f". {closed_info['message']}"
                        
                        return uniform_response(
                            success=True,
                            message=message,
                            data=response_data
                        )
                        
                    except Exception as e:
                        logger.error(f"Error auto-generating public link for survey {pk}: {e}")
                        return uniform_response(
                            success=False,
                            message="No public link found for this survey",
                            data=None,
                            status_code=status.HTTP_404_NOT_FOUND
                        )

                # Return single token for API compatibility
                latest_token = links_data[0]
                
                response_data = {
                    'token': latest_token['token'],
                    'expires_at': latest_token['expires_at']
                }
                
                # Add information about closed links
                if closed_info['closed_links'] > 0:
                    closed_type = []
                    if closed_info['password_links_closed'] > 0:
                        closed_type.append('password')
                    if closed_info['public_links_closed'] > 0:
                        closed_type.append('public')
                    
                    response_data['closed_links_info'] = {
                        'closed_count': closed_info['closed_links'],
                        'closed_type': ', '.join(closed_type) if closed_type else 'unknown',
                        'message': closed_info['message']
                    }
                
                message = "Public link retrieved successfully"
                if closed_info['message']:
                    message += f". {closed_info['message']}"
                
                return uniform_response(
                    success=True,
                    message=message,
                    data=response_data
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
    
    @action(detail=True, methods=['get'], permission_classes=[AllowAny], url_path='current-link')
    def get_current_link(self, request, pk=None):
        """
        Get the current active link (public or password-protected) for the survey.
        
        GET /api/surveys/surveys/{survey_id}/current-link/
        
        Returns the currently active link with type information:
        - Public link: for surveys with PUBLIC/AUTH visibility without password
        - Password-protected link: for any survey with password protection
        """
        try:
            survey = self.get_object()
            
            # Check permissions - allow access if:
            # 1. User is authenticated AND (is creator OR survey is public/auth)
            # 2. Survey is public (for unauthenticated users)
            if request.user.is_authenticated:
                if not (survey.creator == request.user or survey.visibility in ['PUBLIC', 'AUTH'] or request.user.role in ['super_admin', 'admin']):
                    return uniform_response(
                        success=False,
                        message="You don't have permission to access this survey's links.",
                        status_code=status.HTTP_403_FORBIDDEN
                    )
            else:
                # Unauthenticated users can only access public surveys
                if survey.visibility != 'PUBLIC':
                    return uniform_response(
                        success=False,
                        message="Authentication required to access this survey's links.",
                        status_code=status.HTTP_401_UNAUTHORIZED
                    )
            
            # Get all active tokens for this survey
            active_tokens = PublicAccessToken.objects.filter(
                survey=survey,
                is_active=True
            ).order_by('-created_at')
            
            # Check for valid tokens only
            valid_tokens = [token for token in active_tokens if token.is_valid()]
            
            if not valid_tokens:
                return uniform_response(
                    success=False,
                    message="No active link found for this survey.",
                    data={
                        'has_link': False,
                        'survey_visibility': survey.visibility,
                        'survey_status': survey.get_status()
                    },
                    status_code=status.HTTP_404_NOT_FOUND
                )
            
            # Get the most recent valid token
            current_token = valid_tokens[0]
            
            # Determine link type and prepare response
            if current_token.is_password_protected():
                # Password-protected link - match the exact format from your example
                response_data = {
                    'token': current_token.token,
                    'password': current_token.password,
                    'expires_at': current_token.expires_at.isoformat(),
                    'is_password_protected': True,
                    'is_contact_restricted': current_token.is_contact_restricted(),
                    'survey_visibility': survey.visibility,
                    'note': 'Password-protected links work regardless of survey visibility changes'
                }
                
                # Add restricted contact info if present
                if current_token.is_contact_restricted():
                    restricted_emails = current_token.get_restricted_emails()
                    restricted_phones = current_token.get_restricted_phones()
                    if restricted_emails:
                        response_data['restricted_email'] = restricted_emails
                    if restricted_phones:
                        response_data['restricted_phone'] = restricted_phones
                
                # Add closed links info if this token replaced another one
                # Check if this password-protected link was created after a public link
                earlier_public_tokens = PublicAccessToken.objects.filter(
                    survey=survey,
                    password__isnull=True,  # Public tokens have no password
                    created_at__lt=current_token.created_at
                ).count()
                
                if earlier_public_tokens > 0:
                    response_data['closed_links_info'] = {
                        'closed_count': earlier_public_tokens,
                        'closed_type': 'public',
                        'message': 'تم إلغاء الرابط العام وتفعيل الرابط المحمي بكلمة مرور للاستطلاع'
                    }
                
                message = "Password-protected link generated successfully. تم إلغاء الرابط العام وتفعيل الرابط المحمي بكلمة مرور للاستطلاع"
                
            else:
                # Public link - match the exact format from your example
                response_data = {
                    'token': current_token.token,
                    'expires_at': current_token.expires_at.isoformat(),
                    'survey_visibility': survey.visibility,
                    'note': 'This link will become invalid if survey visibility changes from PUBLIC/AUTH'
                }
                
                # Check if this is an auto-generated link (you may need to add this field to the model)
                # For now, we'll assume it's auto-generated if no password is set
                response_data['auto_generated'] = True
                
                message = "Public link auto-generated successfully"
            
            user_identifier = getattr(request.user, 'email', 'anonymous user') if request.user.is_authenticated else 'anonymous user'
            logger.info(f"Current link retrieved for survey {survey.id} by {user_identifier}")
            
            return uniform_response(
                success=True,
                message=message,
                data=response_data
            )
            
        except Exception as e:
            logger.error(f"Error retrieving current link for survey {pk}: {e}")
            return uniform_response(
                success=False,
                message="Failed to retrieve current link",
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
            token_error_message = None
            
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
                    # Check if token was deactivated due to link type switching
                    switch_reason = check_link_switch_reason(token)
                    token_error_message = switch_reason['message']
            
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
                    'public_contact_method': survey.public_contact_method,
                    'status': survey.get_status(),
                    'is_currently_active': survey.is_currently_active(),
                    'start_date': survey.start_date.isoformat() if survey.start_date else None,
                    'end_date': survey.end_date.isoformat() if survey.end_date else None,
                    'estimated_time': max(len(survey.questions.all()) * 2, 5),  # 2 min per question, min 5 min
                    'questions_count': survey.questions.count(),
                    'questions': question_data
                }
            
            # Determine the appropriate message
            response_message = get_arabic_error_messages()['validation_completed']
            if not has_access and token_error_message:
                response_message = token_error_message
            elif not has_access:
                response_message = get_arabic_error_messages()['access_denied']
            
            response_data = {
                'has_access': has_access,
                'survey': survey_data
            }
            
            # Add token error info if applicable
            if not has_access and token_error_message:
                response_data['reason'] = 'link_switched' if 'تم إلغاء' in token_error_message else 'access_denied'
            
            return uniform_response(
                success=has_access,
                message=response_message,
                data=response_data,
                status_code=status.HTTP_200_OK if has_access else status.HTTP_403_FORBIDDEN
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
                    'public_contact_method': survey.public_contact_method,
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
                # Check if token was deactivated due to link type switching
                switch_reason = check_link_switch_reason(token)
                
                return uniform_response(
                    success=False,
                    message=switch_reason['message'],
                    data={
                        'has_access': False,
                        'survey': None,
                        'reason': 'link_switched' if switch_reason['is_switched'] else 'invalid_token'
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
                        user = User.objects.get_by_email(email)
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
        # 1. PUBLIC surveys (accessible to everyone)
        # 2. AUTH surveys (accessible to all authenticated users) 
        # 3. Private surveys where user is explicitly shared (exclude own private surveys)
        
        try:
            logger.info(f"Building queryset for user {user.email}")
            
            public_surveys = Q(visibility='PUBLIC')
            auth_surveys = Q(visibility='AUTH')
            
            # Start with basic query that should always work
            base_query = public_surveys | auth_surveys
            
            # Try to add private shared surveys
            try:
                private_shared_surveys = Q(visibility='PRIVATE', shared_with=user) & ~Q(creator=user)
                base_query = base_query | private_shared_surveys
                logger.debug(f"Added private shared surveys for {user.email}")
            except Exception as e:
                logger.warning(f"Could not query private shared surveys for {user.email}: {e}")
            
            # Try to add group surveys if user has groups
            try:
                user_groups = user.user_groups.values_list('group', flat=True)
                if user_groups.exists():
                    group_shared_surveys = Q(visibility='GROUPS', shared_with_groups__in=user_groups) & ~Q(creator=user)
                    base_query = base_query | group_shared_surveys
                    logger.debug(f"Added group shared surveys for {user.email}")
                else:
                    logger.debug(f"User {user.email} has no groups")
            except Exception as e:
                logger.warning(f"Could not query user groups for {user.email}: {e}")
            
            # Build the final queryset with minimal prefetch to avoid table issues
            # Oracle fix: defer NCLOB fields when using distinct() to avoid ORA-00932 error
            queryset = Survey.objects.filter(
                base_query,
                deleted_at__isnull=True,
                is_active=True  # Only show active surveys
            ).distinct().select_related('creator').defer('description')
            
            # Try to add prefetch_related safely
            try:
                queryset = queryset.prefetch_related('questions')
                logger.debug(f"Added questions prefetch for {user.email}")
            except Exception as e:
                logger.warning(f"Could not prefetch questions for {user.email}: {e}")
            
            # Try to add shared_with prefetch safely
            try:
                queryset = queryset.prefetch_related('shared_with')
                logger.debug(f"Added shared_with prefetch for {user.email}")
            except Exception as e:
                logger.warning(f"Could not prefetch shared_with for {user.email}: {e}")
            
            logger.info(f"Successfully built queryset for user {user.email}")
            return queryset
            
        except Exception as e:
            logger.error(f"Error building survey queryset for {user.email}: {e}")
            # Fallback to minimal safe query
            try:
                # Oracle fix: defer NCLOB fields when using distinct() to avoid ORA-00932 error
                return Survey.objects.filter(
                    Q(visibility='PUBLIC') | Q(visibility='AUTH'),
                    deleted_at__isnull=True,
                    is_active=True
                ).distinct().select_related('creator').defer('description')
            except Exception as fallback_error:
                logger.error(f"Even fallback query failed for {user.email}: {fallback_error}")
                # Return empty queryset to prevent 500 errors
                return Survey.objects.none()
    
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
                arabic_messages = get_arabic_error_messages()
                return uniform_response(
                    success=False,
                    message=arabic_messages['already_submitted'],
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
    
    def _validate_survey_access(self, request, survey, token=None, password=None, email=None, phone=None):
        """
        Validate access to survey based on visibility and provided credentials
        Returns tuple: (has_access, user_or_email_or_phone, error_message)
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
                    # Check if token is password-protected
                    if access_token.is_password_protected():
                        # Password is required for password-protected tokens
                        if not password:
                            return False, None, "Password is required for this token"
                        if not access_token.validate_password(password):
                            return False, None, "Invalid password"
                        
                        # Validate contact restrictions if any
                        if not access_token.validate_contact(email, phone):
                            restricted_emails = access_token.get_restricted_emails()
                            restricted_phones = access_token.get_restricted_phones()
                            if restricted_emails:
                                return False, None, f"This token is restricted to emails: {', '.join(restricted_emails)}"
                            elif restricted_phones:
                                return False, None, f"This token is restricted to phones: {', '.join(restricted_phones)}"
                    
                    # Token is valid, determine user
                    if request.user.is_authenticated:
                        return True, request.user, None
                    else:
                        # For anonymous users, check if token has contact restrictions first
                        restricted_emails = access_token.get_restricted_emails()
                        restricted_phones = access_token.get_restricted_phones()
                        if restricted_emails:
                            if email and email.lower() in [e.lower() for e in restricted_emails]:
                                return True, email, None
                            else:
                                return False, None, f"This token requires one of these emails: {', '.join(restricted_emails)}"
                        elif restricted_phones:
                            if phone and phone in restricted_phones:
                                return True, phone, None
                            else:
                                return False, None, f"This token requires one of these phones: {', '.join(restricted_phones)}"
                        else:
                            # No contact restrictions, use survey's default requirement
                            required_method = getattr(survey, 'public_contact_method', 'email')
                            if required_method == 'email' and email:
                                return True, email, None
                            elif required_method == 'phone' and phone:
                                return True, phone, None
                            elif email:
                                return True, email, None
                            elif phone:
                                return True, phone, None
                            else:
                                return False, None, "Email or phone is required for anonymous access"
            except PublicAccessToken.DoesNotExist:
                return False, None, "Invalid or expired token"
        
        # Handle different visibility levels
        if survey.visibility == "PUBLIC":
            # Public surveys require email or phone for anonymous users based on survey settings
            if request.user.is_authenticated:
                return True, request.user, None
            else:
                required_method = survey.public_contact_method
                if required_method == 'email' and email:
                    return True, email, None
                elif required_method == 'phone' and phone:
                    return True, phone, None
                else:
                    contact_type = "Email" if required_method == 'email' else "Phone"
                    return False, None, f"{contact_type} is required for public survey responses"
        
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
            password = validated_data.get('password')
            email = validated_data.get('email')
            phone = validated_data.get('phone')
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
            has_access, user_or_contact, error_msg = self._validate_survey_access(
                request, survey, token, password, email, phone
            )
            
            if not has_access:
                return uniform_response(
                    success=False,
                    message=error_msg or "Access denied",
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
            # Determine respondent details for duplicate check
            respondent = user_or_contact if isinstance(user_or_contact, User) else None
            respondent_email = user_or_contact if isinstance(user_or_contact, str) and '@' in user_or_contact else None
            respondent_phone = user_or_contact if isinstance(user_or_contact, str) and '@' not in user_or_contact else None
            
            # Check for duplicate submissions
            existing_response = None
            if respondent:
                # Check by authenticated user only
                existing_response = SurveyResponse.objects.filter(
                    survey=survey,
                    respondent=respondent
                ).first()
            elif respondent_email:
                # Check by email for anonymous users only (don't cross-check with authenticated users)
                existing_response = SurveyResponse.objects.filter(
                    survey=survey,
                    respondent__isnull=True,  # Only check anonymous responses
                    respondent_email=respondent_email
                ).first()
            elif respondent_phone:
                # Check by phone for anonymous users only
                existing_response = SurveyResponse.objects.filter(
                    survey=survey,
                    respondent__isnull=True,  # Only check anonymous responses
                    respondent_phone=respondent_phone
                ).first()
            
            if existing_response:
                arabic_messages = get_arabic_error_messages()
                return uniform_response(
                    success=False,
                    message=arabic_messages['already_submitted'],
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
                respondent_email=respondent_email,  # Store email for anonymous responses
                respondent_phone=respondent_phone   # Store phone for anonymous responses
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
                    arabic_messages = get_arabic_error_messages()
                    return uniform_response(
                        success=False,
                        message=arabic_messages['already_submitted'],
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
        
        # Check if user is admin or super_admin (only these roles can perform bulk operations)
        if request.user.role not in ['admin', 'super_admin']:
            return uniform_response(
                success=False,
                message="Only administrators or super administrators can perform bulk operations",
                status_code=status.HTTP_403_FORBIDDEN
            )
        
        # Get surveys that user can modify
        surveys = Survey.objects.filter(
            id__in=survey_ids,
            deleted_at__isnull=True
        )
        
        # Filter to only surveys user can modify (creator or admin/super_admin)
        if request.user.role not in ['admin', 'super_admin']:
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
    Access: Admin or Super Admin only
    """
    
    serializer_class = ResponseSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['survey', 'is_complete', 'respondent']
    search_fields = ['respondent__email', 'respondent_email']
    ordering_fields = ['submitted_at', 'survey__title']
    ordering = ['-submitted_at']
    
    def get_queryset(self):
        """Get all responses - admin or super_admin only"""
        user = self.request.user
        
        if not user.is_authenticated or user.role not in ['admin', 'super_admin']:
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
            # Check admin or super_admin permission
            if not request.user.is_authenticated or request.user.role not in ['admin', 'super_admin']:
                return uniform_response(
                    success=False,
                    message="Admin or Super Admin access required",
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
                        else (response.respondent_phone or response.respondent_email or 'Anonymous')
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
    API to get all responses for a specific survey with answers.
    
    GET /api/surveys/admin/surveys/{survey_id}/responses/
    Access: Admin, Super Admin, or Survey Creator only
    """
    
    serializer_class = ResponseSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['is_complete', 'respondent']
    ordering_fields = ['submitted_at']
    ordering = ['-submitted_at']
    
    def get_queryset(self):
        """Get responses for specific survey - admin, super_admin, or survey creator"""
        user = self.request.user
        
        if not user.is_authenticated:
            return SurveyResponse.objects.none()
        
        survey_id = self.kwargs.get('survey_id')
        survey = get_object_or_404(Survey, id=survey_id, deleted_at__isnull=True)
        
        # Allow access if user is admin, super_admin, or the survey creator
        if user.role in ['admin', 'super_admin'] or user == survey.creator:
            return survey.responses.all().select_related(
                'respondent'
            ).prefetch_related('answers__question')
        
        return SurveyResponse.objects.none()
    
    def list(self, request, *args, **kwargs):
        """List responses for specific survey with detailed answers"""
        try:
            # Check permission (admin, super_admin, or survey creator)
            if not request.user.is_authenticated:
                return uniform_response(
                    success=False,
                    message="Authentication required",
                    status_code=status.HTTP_401_UNAUTHORIZED
                )
            
            survey_id = self.kwargs.get('survey_id')
            survey = get_object_or_404(Survey, id=survey_id, deleted_at__isnull=True)
            
            # Check if user has permission to view responses
            if not (request.user.role in ['admin', 'super_admin'] or request.user == survey.creator):
                return uniform_response(
                    success=False,
                    message="Access denied. Only admins, super admins, or survey creators can view responses.",
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
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
                    # For anonymous users, prefer phone over email, or show email if available
                    contact_info = response.respondent_phone or response.respondent_email or 'Anonymous'
                    respondent_info = {
                        'email': contact_info,
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
                'public_contact_method': survey.public_contact_method,
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
                'public_contact_method': survey.public_contact_method,
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


class PasswordAccessValidationView(APIView):
    """
    Validate password-protected token and return survey information.
    
    POST /api/surveys/password-access/{token}/
    Access: Public endpoint for token validation
    """
    
    permission_classes = [AllowAny]
    
    def post(self, request, token):
        """Validate token and password, return survey info"""
        try:
            password = request.data.get('password')
            
            if not password:
                return uniform_response(
                    success=False,
                    message="Password is required",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            # Find the token
            try:
                access_token = PublicAccessToken.objects.get(
                    token=token,
                    is_active=True,
                    password__isnull=False  # Must be password-protected
                )
            except PublicAccessToken.DoesNotExist:
                return uniform_response(
                    success=False,
                    message="Invalid or non-password-protected token",
                    status_code=status.HTTP_404_NOT_FOUND
                )
            
            # Check if token is expired
            if not access_token.is_valid():
                return uniform_response(
                    success=False,
                    message="Token has expired",
                    status_code=status.HTTP_401_UNAUTHORIZED
                )
            
            # Validate password
            if not access_token.validate_password(password):
                return uniform_response(
                    success=False,
                    message="Invalid password",
                    status_code=status.HTTP_401_UNAUTHORIZED
                )
            
            # Get survey and check if it's active
            survey = access_token.survey
            
            if not survey.is_active:
                return uniform_response(
                    success=False,
                    message="Survey is not active",
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
            if not survey.is_currently_active():
                return uniform_response(
                    success=False,
                    message=get_arabic_status_message(survey),
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
            # Return survey information
            survey_data = {
                'survey_id': str(survey.id),
                'survey_title': survey.title,
                'survey_description': survey.description,
                'has_access': True,
                'is_password_protected': True,
                'is_contact_restricted': access_token.is_contact_restricted(),
                'token_expires_at': access_token.expires_at.isoformat(),
                'access_instructions': {
                    'survey_endpoint': f'/api/surveys/password-surveys/{survey.id}/',
                    'submission_endpoint': '/api/surveys/password-responses/',
                    'required_headers': {
                        'Authorization': f'Bearer {token}'
                    },
                    'required_fields': ['password']
                }
            }
            
            # Add contact restrictions if any
            restricted_emails = access_token.get_restricted_emails()
            restricted_phones = access_token.get_restricted_phones()
            if restricted_emails:
                survey_data['restricted_email'] = restricted_emails
                survey_data['access_instructions']['required_fields'].append('email')
            if restricted_phones:
                survey_data['restricted_phone'] = restricted_phones  
                survey_data['access_instructions']['required_fields'].append('phone')
            
            return uniform_response(
                success=True,
                message="Token and password validated successfully",
                data=survey_data
            )
            
        except Exception as e:
            logger.error(f"Error validating password access: {e}")
            return uniform_response(
                success=False,
                message="Failed to validate access",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PasswordProtectedSurveyView(APIView):
    """
    Retrieve survey details for password-protected public access.
    
    GET /api/surveys/password-surveys/{survey_id}/
    Access: Requires token and password via Authorization: Bearer <token> and password in body
    """
    
    permission_classes = [AllowAny]  # Handle validation manually
    
    def _validate_password_token_access(self, request, survey_id, password, email=None, phone=None):
        """Validate token and password only (no contact restrictions)"""
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
                is_active=True,
                password__isnull=False  # Must be a password-protected token
            )
            
            if not access_token.is_valid():
                return None, None, "Token has expired"
            
            # Validate password
            if not access_token.validate_password(password):
                return None, None, "Invalid password"
            
            # No contact restrictions validation - handled in separate API
            
            if not survey.is_active:
                return None, None, "Survey is not active"
            
            if not survey.is_currently_active():
                return None, None, get_arabic_status_message(survey)
            
            return access_token, survey, None
            
        except Survey.DoesNotExist:
            return None, None, "Survey not found"
        except PublicAccessToken.DoesNotExist:
            return None, None, "Token does not have password-protected access to this survey"
    
    def post(self, request, survey_id):
        """Get survey details with password validation"""
        try:
            password = request.data.get('password')
            email = request.data.get('email')
            phone = request.data.get('phone')
            
            if not password:
                return uniform_response(
                    success=False,
                    message="Password is required",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            access_token, survey, error_msg = self._validate_password_token_access(
                request, survey_id, password, email, phone
            )
            
            if error_msg:
                return uniform_response(
                    success=False,
                    message=error_msg,
                    status_code=status.HTTP_401_UNAUTHORIZED if "password" in error_msg.lower() or "token" in error_msg.lower() else status.HTTP_404_NOT_FOUND
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
            elif email:
                # Check by email for anonymous users
                has_submitted = SurveyResponse.objects.filter(
                    survey=survey,
                    respondent_email=email
                ).exists()
            elif phone:
                # Check by phone for anonymous users
                has_submitted = SurveyResponse.objects.filter(
                    survey=survey,
                    respondent_phone=phone
                ).exists()
            
            survey_data = {
                'id': str(survey.id),
                'title': survey.title,
                'description': survey.description,
                'visibility': survey.visibility,
                'is_active': survey.is_active,
                'is_locked': survey.is_locked,
                'public_contact_method': survey.public_contact_method,
                'estimated_time': max(survey.questions.count() * 1, 5),
                'questions_count': survey.questions.count(),
                'created_at': survey.created_at.isoformat(),
                'updated_at': survey.updated_at.isoformat(),
                'creator_email': survey.creator.email,
                'questions': question_serializer.data,
                'access_info': {
                    'access_type': 'password_token',
                    'token_expires_at': access_token.expires_at.isoformat(),
                    'is_password_protected': True,
                    'can_submit': not has_submitted,
                    'has_submitted': has_submitted,
                    'submission_instructions': {
                        'endpoint': '/api/surveys/password-responses/',
                        'method': 'POST',
                        'required_fields': ['survey_id', 'token', 'password', 'answers'],
                        'optional_fields': {
                            'email': 'For anonymous tracking',
                            'phone': 'For anonymous tracking'
                        }
                    }
                },
                'submission_guidelines': {
                    'password_required': True,
                    'authentication_required': False,  # Password replaces authentication requirement
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
            logger.error(f"Error retrieving password-protected survey details: {e}")
            return uniform_response(
                success=False,
                message="Failed to retrieve survey details",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PasswordProtectedSurveyResponseView(APIView):
    """
    Handle password-protected survey response submissions.
    
    POST /api/surveys/password-responses/
    Access: Requires token, password, and optionally email/phone
    """
    
    permission_classes = [AllowAny]  # Handle validation manually
    
    def _validate_password_survey_access(self, request, survey, token, password, email=None, phone=None):
        """
        Validate password-protected access to survey
        Returns tuple: (has_access, user_or_contact, error_message)
        """
        # Check if survey is currently active based on dates
        if not survey.is_currently_active():
            status_message = f"Survey is {survey.get_status()}"
            return False, None, status_message
        
        # Validate password-protected token access
        try:
            access_token = PublicAccessToken.objects.get(
                token=token,
                survey=survey,
                is_active=True,
                password__isnull=False  # Must be password-protected
            )
            
            if not access_token.is_valid():
                return False, None, "Token has expired"
            
            # Validate password
            if not access_token.validate_password(password):
                return False, None, "Invalid password"
            
            # Validate contact restrictions
            if not access_token.validate_contact(email, phone):
                restricted_emails = access_token.get_restricted_emails()
                restricted_phones = access_token.get_restricted_phones()
                if restricted_emails:
                    return False, None, "This token is restricted"
                elif restricted_phones:
                    return False, None, "This token is restricted"
                else:
                    return False, None, "Contact validation failed"
            
            # Determine the user/contact for response tracking
            if request.user.is_authenticated:
                return True, request.user, None
            else:
                # For anonymous users, require email or phone
                restricted_emails = access_token.get_restricted_emails()
                restricted_phones = access_token.get_restricted_phones()
                if restricted_emails:
                    return True, email, None  # Use the provided email (already validated above)
                elif restricted_phones:
                    return True, phone, None  # Use the provided phone (already validated above)
                elif email:
                    return True, email, None
                elif phone:
                    return True, phone, None
                else:
                    return False, None, "Email or phone number is required for anonymous access"
            
        except PublicAccessToken.DoesNotExist:
            return False, None, "Invalid or unauthorized token for password-protected access"
    
    def post(self, request):
        """Submit response for password-protected survey"""
        try:
            # Extract required fields
            survey_id = request.data.get('survey_id')
            token = request.data.get('token')
            password = request.data.get('password')
            email = request.data.get('email')
            phone = request.data.get('phone')
            answers_data = request.data.get('answers', [])
            
            # Validate required fields
            if not survey_id:
                return uniform_response(
                    success=False,
                    message="Survey ID is required",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            if not token:
                return uniform_response(
                    success=False,
                    message="Token is required",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            if not password:
                return uniform_response(
                    success=False,
                    message="Password is required",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            if not answers_data:
                return uniform_response(
                    success=False,
                    message="Answers are required",
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
            
            # Validate password-protected access
            has_access, user_or_contact, error_msg = self._validate_password_survey_access(
                request, survey, token, password, email, phone
            )
            
            if not has_access:
                return uniform_response(
                    success=False,
                    message=error_msg or "Access denied",
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
            # Determine respondent details for duplicate check
            respondent = user_or_contact if isinstance(user_or_contact, User) else None
            respondent_email = user_or_contact if isinstance(user_or_contact, str) and '@' in user_or_contact else None
            respondent_phone = user_or_contact if isinstance(user_or_contact, str) and '@' not in user_or_contact else None
            
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
            elif respondent_phone:
                # Check by phone for anonymous users
                existing_response = SurveyResponse.objects.filter(
                    survey=survey,
                    respondent_phone=respondent_phone
                ).first()
            
            if existing_response:
                arabic_messages = get_arabic_error_messages()
                return uniform_response(
                    success=False,
                    message=arabic_messages['already_submitted'],
                    status_code=status.HTTP_409_CONFLICT
                )
            
            # Create response
            response = SurveyResponse.objects.create(
                survey=survey,
                respondent=respondent,
                respondent_email=respondent_email,
                respondent_phone=respondent_phone
            )
            
            # Process answers
            created_answers = []
            for answer_data in answers_data:
                question_id = answer_data.get('question_id')
                answer_text = answer_data.get('answer')
                
                if not question_id or answer_text is None:
                    response.delete()  # Clean up
                    return uniform_response(
                        success=False,
                        message="Each answer must include question_id and answer",
                        status_code=status.HTTP_400_BAD_REQUEST
                    )
                
                try:
                    question = Question.objects.get(id=question_id, survey=survey)
                    
                    # Validate required questions
                    if question.is_required and not str(answer_text).strip():
                        response.delete()  # Clean up
                        return uniform_response(
                            success=False,
                            message=f"Question '{question.text}' is required",
                            status_code=status.HTTP_400_BAD_REQUEST
                        )
                    
                    # Create answer
                    answer = Answer.objects.create(
                        question=question,
                        response=response,
                        answer_text=str(answer_text)
                    )
                    created_answers.append(answer)
                    
                except Question.DoesNotExist:
                    response.delete()  # Clean up
                    return uniform_response(
                        success=False,
                        message=f"Question {question_id} not found in this survey",
                        status_code=status.HTTP_400_BAD_REQUEST
                    )
            
            logger.info(f"Password-protected survey response submitted for survey {survey.id}")
            
            return uniform_response(
                success=True,
                message="Survey response submitted successfully",
                data={
                    'response_id': str(response.id),
                    'survey_id': str(survey.id),
                    'submitted_at': response.submitted_at.isoformat(),
                    'answers_count': len(created_answers),
                    'access_type': 'password_token'
                },
                status_code=status.HTTP_201_CREATED
            )
            
        except Exception as e:
            logger.error(f"Error submitting password-protected survey response: {e}")
            return uniform_response(
                success=False,
                message="Failed to submit response",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
