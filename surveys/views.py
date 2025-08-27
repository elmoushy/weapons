"""
Views for surveys with uniform responses and role-based access control.

This module follows the established patterns from the authentication system
with comprehensive error handling and logging.
"""

from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.db.models import Q, Count, Avg
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
import csv
import io
import math
from datetime import timedelta
from collections import defaultdict, Counter
from statistics import median, mean
from dateutil.parser import parse as parse_datetime
import pytz

from .models import Survey, Question, Response as SurveyResponse, Answer, PublicAccessToken
from .pagination import SurveyPagination, ResponsePagination
from .serializers import (
    SurveySerializer, QuestionSerializer, ResponseSerializer,
    SurveySubmissionSerializer, ResponseSubmissionSerializer
)
from .permissions import (
    IsCreatorOrVisible, IsCreatorOrReadOnly, 
    CanSubmitResponse, IsCreatorOrStaff
)
from .timezone_utils import (
    format_uae_datetime, format_uae_date_only, get_status_uae, 
    is_currently_active_uae, serialize_datetime_uae
)
from notifications.services import SurveyNotificationService

logger = logging.getLogger(__name__)
User = get_user_model()


def safe_get_query_params(request, key, default=None):
    """
    Safely get query parameters from either DRF request.query_params or Django request.GET
    """
    try:
        if hasattr(request, 'query_params'):
            return request.query_params.get(key, default)
        else:
            return request.GET.get(key, default)
    except Exception:
        return default


def can_user_manage_survey(user, survey):
    """
    Check if a user can manage (update/delete) a survey.
    
    Rules:
    - Super admin can manage any survey (including orphaned ones)
    - Admin/Manager can manage surveys they created AND orphaned surveys
    - Regular users can only manage surveys they created
    - If survey.creator is None (orphaned), super admin/admin/manager can manage it
    """
    if user.role == 'super_admin':
        return True
    
    # If survey is orphaned (creator deleted), admin and manager can manage it
    if survey.creator is None:
        return user.role in ['admin', 'manager']
    
    # For all roles, they can manage their own surveys
    return survey.creator == user


def can_user_access_survey(user, survey):
    """
    Check if a user can access (view/respond to) a survey.
    
    Rules:
    - Super admin can access any survey
    - Admin/Manager can access any survey (including orphaned ones)
    - Regular users follow normal visibility rules + orphaned surveys are accessible to admins/managers
    """
    if user.role in ['super_admin', 'admin', 'manager']:
        return True
    
    # Normal visibility rules for regular users
    if survey.visibility == 'PUBLIC':
        return True
    elif survey.visibility == 'AUTH':
        return True  # Any authenticated user
    elif survey.visibility == 'PRIVATE':
        # Check if user is the creator or in shared_with list
        return (survey.creator == user or 
                user in survey.shared_with.all())
    elif survey.visibility == 'GROUPS':
        # Check if user is in any of the shared groups
        user_groups = user.user_groups.all()
        shared_groups = survey.shared_with_groups.all()
        return any(ug.group in shared_groups for ug in user_groups)
    
    return False


def can_user_access_survey(user, survey):
    """
    Check if a user can access (view/respond to) a survey.
    
    Rules:
    - Super admin can access any survey (including orphaned ones)
    - Admin can access any survey
    - Users can access surveys they created (even if orphaned - they still have access to data)
    - Users can access surveys based on visibility rules
    """
    if user.role in ['super_admin', 'admin']:
        return True
    
    # Check if user created the survey (even if creator is now null, they still have access to their data)
    # This is checked through other relationships like responses
    if survey.creator == user:
        return True
    
    # For orphaned surveys, regular users can only access based on visibility
    # Check visibility rules
    if survey.visibility == 'PUBLIC':
        return True
    elif survey.visibility == 'AUTH':
        return True  # Any authenticated user
    elif survey.visibility == 'PRIVATE':
        return survey.shared_with.filter(id=user.id).exists()
    elif survey.visibility == 'GROUPS':
        user_groups = user.user_groups.values_list('group_id', flat=True)
        return survey.shared_with_groups.filter(id__in=user_groups).exists()
    
    return False


def get_arabic_status_message(survey):
    """
    Generate Arabic status messages with proper date and time formatting for surveys in UAE timezone
    """
    status = get_status_uae(survey)
    
    # Use UAE timezone utilities for consistent formatting
    start_datetime_str = format_uae_datetime(survey.start_date)
    end_datetime_str = format_uae_datetime(survey.end_date)
    start_date_str = format_uae_date_only(survey.start_date)
    end_date_str = format_uae_date_only(survey.end_date)
    
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
    pagination_class = SurveyPagination
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['visibility', 'is_active', 'creator', 'status']
    search_fields = ['title', 'description']
    ordering_fields = ['created_at', 'updated_at', 'title', 'response_count']
    ordering = ['-created_at']
    
    @classmethod
    def get_oracle_safe_fields(cls):
        """
        Get the list of fields safe to use with distinct() in Oracle.
        Excludes NCLOB fields (EncryptedTextField) to prevent ORA-00932 error.
        """
        return [
            'id', 'title_hash', 'creator', 'visibility', 
            'start_date', 'end_date', 'is_locked', 'is_active', 
            'public_contact_method', 'per_device_access', 'status',
            'created_at', 'updated_at'
        ]
    
    def get_object(self):
        """
        Override get_object to handle cases where request doesn't have query_params.
        This can happen when the request is not properly wrapped by DRF.
        """
        try:
            # Try the standard DRF approach first
            return super().get_object()
        except AttributeError as e:
            if "'WSGIRequest' object has no attribute 'query_params'" in str(e):
                # Fallback: get object directly by primary key without filters
                pk = self.kwargs.get(self.lookup_field)
                if not pk:
                    raise
                
                # Apply the same base queryset logic as get_queryset but without filters
                user = getattr(self.request, 'user', None)
                
                if not user or not user.is_authenticated:
                    # Anonymous users only see submitted public surveys
                    base_queryset = self.queryset.filter(visibility='PUBLIC', is_active=True, status='submitted')
                elif user.role == 'super_admin':
                    # Super admin sees all surveys
                    base_queryset = self.queryset
                elif user.role in ['admin', 'manager']:
                    # Admin/Manager see only their own surveys
                    base_queryset = self.queryset.filter(creator=user)
                else:
                    # Regular users see their own surveys, shared surveys, public/auth surveys, and group-shared surveys
                    try:
                        user_groups = user.user_groups.values_list('group', flat=True)
                        base_queryset = self.queryset.filter(
                            Q(creator=user) |  # Own surveys (including drafts)
                            (Q(shared_with=user) & Q(status='submitted')) |  # Shared surveys (submitted only)
                            (Q(shared_with_groups__in=user_groups) & Q(status='submitted')) |  # Group shared (submitted only)
                            (Q(visibility='PUBLIC') & Q(status='submitted')) |  # Public surveys (submitted only)
                            (Q(visibility='AUTH') & Q(status='submitted'))  # Auth surveys (submitted only)
                        ).distinct().only(*self.get_oracle_safe_fields())
                    except Exception:
                        # Fallback to basic access if user_groups fails
                        base_queryset = self.queryset.filter(
                            Q(creator=user) |
                            (Q(visibility='PUBLIC') & Q(status='submitted')) |
                            (Q(visibility='AUTH') & Q(status='submitted'))
                        ).distinct().only(*self.get_oracle_safe_fields())
                
                return base_queryset.get(pk=pk)
            else:
                raise
    
    def get_queryset(self):
        """Filter surveys based on user permissions with enhanced filtering"""
        user = self.request.user
        
        # Base queryset based on user permissions
        if not user.is_authenticated:
            # Anonymous users only see submitted public surveys
            base_queryset = self.queryset.filter(visibility='PUBLIC', is_active=True, status='submitted')
        elif user.role == 'super_admin':
            # Super admin sees all surveys
            base_queryset = self.queryset
        elif user.role in ['admin', 'manager']:
            # Admin/Manager see only their own surveys
            base_queryset = self.queryset.filter(creator=user)
        else:
            # Regular users see their own surveys (including drafts), shared surveys (submitted only), public/auth surveys (submitted only), and group-shared surveys (submitted only)
            user_groups = user.user_groups.values_list('group', flat=True)
            # Oracle fix: use only() to exclude NCLOB fields when using distinct() to avoid ORA-00932 error
            base_queryset = self.queryset.filter(
                Q(creator=user) |  # Own surveys (including drafts)
                (Q(shared_with=user) & Q(status='submitted')) |  # Shared surveys (submitted only)
                (Q(shared_with_groups__in=user_groups) & Q(status='submitted')) |  # Group shared (submitted only)
                (Q(visibility='PUBLIC') & Q(status='submitted')) |  # Public surveys (submitted only)
                (Q(visibility='AUTH') & Q(status='submitted'))  # Auth surveys (submitted only)
            ).distinct().only(*SurveyViewSet.get_oracle_safe_fields())
        
        # Apply additional filters
        queryset = self._apply_custom_filters(base_queryset)
        
        # Apply custom ordering
        queryset = self._apply_custom_ordering(queryset)
        
        return queryset
    
    def _apply_custom_filters(self, queryset):
        """Apply custom filters for survey status"""
        survey_status_filter = safe_get_query_params(self.request, 'survey_status')
        
        if survey_status_filter:
            if survey_status_filter == 'active':
                # النشطة - Active surveys
                queryset = queryset.filter(is_active=True)
            elif survey_status_filter == 'inactive':
                # غير النشطة - Inactive surveys
                queryset = queryset.filter(is_active=False)
            elif survey_status_filter == 'private':
                # الخاصة - Private surveys
                queryset = queryset.filter(visibility='PRIVATE')
            elif survey_status_filter == 'auth_required':
                # تتطلب تسجيل دخول - Require authentication
                queryset = queryset.filter(visibility='AUTH')
            elif survey_status_filter == 'public':
                # العامة - Public surveys
                queryset = queryset.filter(visibility='PUBLIC')
            # 'all' or any other value returns all surveys (no additional filter)
        
        return queryset
    
    def _apply_custom_ordering(self, queryset):
        """Apply custom ordering based on Arabic filter options"""
        sort_by = safe_get_query_params(self.request, 'sort_by')
        
        if sort_by:
            if sort_by == 'newest':
                # الأحدث - Newest first
                queryset = queryset.order_by('-created_at')
            elif sort_by == 'oldest':
                # الأقدم - Oldest first
                queryset = queryset.order_by('created_at')
            elif sort_by == 'title_asc':
                # العنوان أ-ي - Title A-Z
                queryset = queryset.order_by('title')
            elif sort_by == 'title_desc':
                # العنوان ي-أ - Title Z-A
                queryset = queryset.order_by('-title')
            elif sort_by == 'most_responses':
                # الأكثر رداً - Most responses
                from django.db.models import Count
                queryset = queryset.annotate(
                    response_count=Count('responses')
                ).order_by('-response_count', '-created_at')
        else:
            # Default ordering
            queryset = queryset.order_by('-created_at')
        
        return queryset
    
    def list(self, request, *args, **kwargs):
        """List surveys with uniform response and enhanced filtering"""
        try:
            queryset = self.filter_queryset(self.get_queryset())
            page = self.paginate_queryset(queryset)
            
            # Get filter information for response
            applied_filters = self._get_applied_filters_info()
            
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                response_data = self.get_paginated_response(serializer.data)
                
                # Add filter information to paginated response
                if hasattr(response_data, 'data') and isinstance(response_data.data, dict):
                    response_data.data['applied_filters'] = applied_filters
                
                return response_data
            
            serializer = self.get_serializer(queryset, many=True)
            return uniform_response(
                success=True,
                message="Surveys retrieved successfully",
                data={
                    'results': serializer.data,
                    'applied_filters': applied_filters
                }
            )
        except Exception as e:
            logger.error(f"Error listing surveys: {e}")
            return uniform_response(
                success=False,
                message="Failed to retrieve surveys",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _get_applied_filters_info(self):
        """Get information about currently applied filters"""
        filters_info = {
            'search': safe_get_query_params(self.request, 'search', ''),
            'survey_status': safe_get_query_params(self.request, 'survey_status', 'all'),
            'sort_by': safe_get_query_params(self.request, 'sort_by', 'newest'),
            'visibility': safe_get_query_params(self.request, 'visibility', ''),
            'is_active': safe_get_query_params(self.request, 'is_active', ''),
            'status': safe_get_query_params(self.request, 'status', ''),
        }
        return filters_info
    
    def create(self, request, *args, **kwargs):
        """Create survey as draft with uniform response"""
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            
            # Debug: Log the validated data to see what's being passed
            validated_data = serializer.validated_data
            logger.info(f"Validated data for survey creation: {validated_data}")
            logger.info(f"per_device_access value: {validated_data.get('per_device_access', 'NOT FOUND')}")
            
            # Always create new surveys as drafts
            survey = serializer.save(creator=request.user, status='draft')
            
            return uniform_response(
                success=True,
                message="Survey draft created successfully",
                data=serializer.data,
                status_code=status.HTTP_201_CREATED
            )
        except Exception as e:
            logger.error(f"Error creating survey draft: {e}")
            return uniform_response(
                success=False,
                message=str(e),
                status_code=status.HTTP_400_BAD_REQUEST
            )
    
    def update(self, request, *args, **kwargs):
        """Update survey with comprehensive access token management on visibility changes"""
        try:
            # Check for valid survey ID
            survey_id = kwargs.get('pk')
            if not survey_id or survey_id == 'undefined' or survey_id == 'null':
                return uniform_response(
                    success=False,
                    message="Survey ID is required and cannot be undefined",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            survey = self.get_object()
            user = request.user
            
            # Check if survey can be edited (drafts + submitted non-PUBLIC surveys)
            if not survey.can_be_edited():
                if survey.status == 'submitted' and survey.visibility == 'PUBLIC':
                    return uniform_response(
                        success=False,
                        message="Cannot update submitted PUBLIC surveys as they may have public responses.",
                        status_code=status.HTTP_403_FORBIDDEN
                    )
                else:
                    return uniform_response(
                        success=False,
                        message="This survey cannot be edited.",
                        status_code=status.HTTP_403_FORBIDDEN
                    )
            
            # Check if user can update the survey
            if not can_user_manage_survey(user, survey):
                return uniform_response(
                    success=False,
                    message="You can only update surveys you created" + (" (orphaned surveys can be managed by admin/manager/super admin)" if survey.creator is None else ""),
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
            old_visibility = survey.visibility
            old_is_active = survey.is_active
            old_status = survey.status
            
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
            new_is_active = serializer.instance.is_active
            new_status = serializer.instance.status
            tokens_message = ""
            
            # Check for survey activation/deactivation changes
            if old_is_active != new_is_active:
                if not old_is_active and new_is_active and new_status == 'submitted':
                    # Survey was activated
                    # Check if notifications should be sent (default: False to prevent spam)
                    send_notifications = request.data.get('send_notifications', False)
                    
                    if send_notifications:
                        try:
                            # Use force_send=True when explicitly requested to send notifications
                            force_send = survey.visibility in ['PUBLIC', 'AUTH']
                            SurveyNotificationService.notify_users_of_new_survey(survey, request, force_send=force_send)
                            logger.info(f"Sent survey activation notifications for survey {survey.id}")
                            tokens_message += " Survey activation notifications sent."
                        except Exception as e:
                            logger.error(f"Failed to send survey activation notifications for survey {survey.id}: {e}")
                    else:
                        logger.info(f"Skipped sending activation notifications for survey {survey.id} as send_notifications was not requested")
                        
                elif old_is_active and not new_is_active:
                    # Survey was deactivated
                    try:
                        SurveyNotificationService.notify_users_of_survey_deactivation(survey, user, request)
                        logger.info(f"Sent survey deactivation notifications for survey {survey.id}")
                        tokens_message += " Survey deactivation notifications sent."
                    except Exception as e:
                        logger.error(f"Failed to send survey deactivation notifications for survey {survey.id}: {e}")
            
            # Check for status changes (draft to submitted)
            elif old_status == 'draft' and new_status == 'submitted' and new_is_active:
                # Check if notifications should be sent (default: False to prevent spam)
                send_notifications = request.data.get('send_notifications', False)
                
                if send_notifications:
                    try:
                        # Use force_send=True when explicitly requested to send notifications
                        force_send = survey.visibility in ['PUBLIC', 'AUTH']
                        SurveyNotificationService.notify_users_of_new_survey(survey, request, force_send=force_send)
                        logger.info(f"Sent survey publication notifications for survey {survey.id}")
                        tokens_message += " Survey publication notifications sent."
                    except Exception as e:
                        logger.error(f"Failed to send survey publication notifications for survey {survey.id}: {e}")
                else:
                    logger.info(f"Skipped sending notifications for survey {survey.id} as send_notifications was not requested")
            
            # Handle token management based on visibility changes
            
            # Handle visibility changes
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
        survey_id = kwargs.get('pk')
        try:
            # Check for valid survey ID
            if not survey_id or survey_id == 'undefined' or survey_id == 'null':
                logger.warning(f"Invalid survey ID provided: {survey_id}")
                return uniform_response(
                    success=False,
                    message="Survey ID is required and cannot be undefined",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                survey = self.get_object()
                logger.info(f"Successfully retrieved survey {survey_id}: {survey.title}")
            except Exception as get_obj_error:
                logger.error(f"Error getting survey object {survey_id}: {get_obj_error}")
                return uniform_response(
                    success=False,
                    message="Error accessing survey",
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            # Check access permissions
            try:
                if not IsCreatorOrVisible().has_object_permission(request, self, survey):
                    logger.warning(f"Access denied to survey {survey_id} for user {request.user}")
                    return uniform_response(
                        success=False,
                        message="Access denied",
                        status_code=status.HTTP_403_FORBIDDEN
                    )
            except Exception as perm_error:
                logger.error(f"Error checking permissions for survey {survey_id}: {perm_error}")
                return uniform_response(
                    success=False,
                    message="Permission check failed",
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            try:
                serializer = self.get_serializer(survey)
                logger.info(f"Successfully serialized survey {survey_id}")
                return uniform_response(
                    success=True,
                    message="Survey retrieved successfully",
                    data=serializer.data
                )
            except Exception as serialize_error:
                logger.error(f"Error serializing survey {survey_id}: {serialize_error}")
                return uniform_response(
                    success=False,
                    message="Error preparing survey data",
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
                
        except Exception as e:
            logger.error(f"Unexpected error retrieving survey {survey_id}: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return uniform_response(
                success=False,
                message="Survey not found",
                status_code=status.HTTP_404_NOT_FOUND
            )
    
    def destroy(self, request, *args, **kwargs):
        """Delete survey with role-based access control"""
        try:
            # Check for valid survey ID
            survey_id = kwargs.get('pk')
            if not survey_id or survey_id == 'undefined' or survey_id == 'null':
                return uniform_response(
                    success=False,
                    message="Survey ID is required and cannot be undefined",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            survey = self.get_object()
            user = request.user
            
            # Check if user can delete the survey
            if not can_user_manage_survey(user, survey):
                return uniform_response(
                    success=False,
                    message="You can only delete surveys you created" + (" (orphaned surveys can be managed by admin/manager/super admin)" if survey.creator is None else ""),
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
    def activate(self, request, pk=None):
        """
        Activate a survey - makes it available for responses.
        
        POST /api/surveys/{id}/activate/
        """
        try:
            survey = self.get_object()
            user = request.user
            
            # Check permissions
            if not can_user_manage_survey(user, survey):
                return uniform_response(
                    success=False,
                    message="You can only activate surveys you created" + (" (orphaned surveys can be managed by admin/manager/super admin)" if survey.creator is None else ""),
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
            # Check if survey can be activated (must be submitted)
            if survey.status != 'submitted':
                return uniform_response(
                    success=False,
                    message="Only submitted surveys can be activated",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            if survey.is_active:
                return uniform_response(
                    success=False,
                    message="Survey is already active",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            # Activate the survey
            old_is_active = survey.is_active
            survey.is_active = True
            survey.save()
            
            # Send notifications to eligible users if this wasn't already active
            if not old_is_active:
                # Check if notifications should be sent (default: False to prevent spam)
                send_notifications = request.data.get('send_notifications', False)
                
                if send_notifications:
                    try:
                        # Use force_send=True when explicitly requested to send notifications
                        force_send = survey.visibility in ['PUBLIC', 'AUTH']
                        SurveyNotificationService.notify_users_of_new_survey(survey, request, force_send=force_send)
                        logger.info(f"Sent survey activation notifications for survey {survey.id}")
                    except Exception as e:
                        logger.error(f"Failed to send survey activation notifications for survey {survey.id}: {e}")
                else:
                    logger.info(f"Skipped sending activation notifications for survey {survey.id} as send_notifications was not requested")
            
            return uniform_response(
                success=True,
                message="Survey activated successfully",
                data=SurveySerializer(survey, context={'request': request}).data
            )
            
        except Exception as e:
            logger.error(f"Error activating survey: {e}")
            return uniform_response(
                success=False,
                message="Failed to activate survey",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['post'], permission_classes=[IsCreatorOrReadOnly])
    def deactivate(self, request, pk=None):
        """
        Deactivate a survey - stops accepting responses.
        
        POST /api/surveys/{id}/deactivate/
        """
        try:
            survey = self.get_object()
            user = request.user
            
            # Check permissions
            if not can_user_manage_survey(user, survey):
                return uniform_response(
                    success=False,
                    message="You can only deactivate surveys you created" + (" (orphaned surveys can be managed by admin/manager/super admin)" if survey.creator is None else ""),
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
            if not survey.is_active:
                return uniform_response(
                    success=False,
                    message="Survey is already inactive",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            # Deactivate the survey
            old_is_active = survey.is_active
            survey.is_active = False
            survey.save()
            
            # Send notifications to users about deactivation
            if old_is_active:
                try:
                    SurveyNotificationService.notify_users_of_survey_deactivation(survey, user, request)
                    logger.info(f"Sent survey deactivation notifications for survey {survey.id}")
                except Exception as e:
                    logger.error(f"Failed to send survey deactivation notifications for survey {survey.id}: {e}")
            
            return uniform_response(
                success=True,
                message="Survey deactivated successfully",
                data=SurveySerializer(survey, context={'request': request}).data
            )
            
        except Exception as e:
            logger.error(f"Error deactivating survey: {e}")
            return uniform_response(
                success=False,
                message="Failed to deactivate survey",
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
            if not can_user_manage_survey(user, survey):
                return uniform_response(
                    success=False,
                    message="You can only modify surveys you created" + (" (orphaned surveys can be managed by admin/manager/super admin)" if survey.creator is None else ""),
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
            # Check if user can add questions to the survey
            if not can_user_manage_survey(user, survey):
                return uniform_response(
                    success=False,
                    message="You can only add questions to surveys you created" + (" (orphaned surveys can only be managed by super admin)" if survey.creator is None else ""),
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
            if not can_user_manage_survey(user, survey):
                return uniform_response(
                    success=False,
                    message="You can only update questions from surveys you created" + (" (orphaned surveys can only be managed by super admin)" if survey.creator is None else ""),
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
            if not can_user_manage_survey(user, survey):
                return uniform_response(
                    success=False,
                    message="You can only delete questions from surveys you created" + (" (orphaned surveys can only be managed by super admin)" if survey.creator is None else ""),
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
            export_format = safe_get_query_params(request, 'format', 'csv').lower()
            include_personal = safe_get_query_params(request, 'include_personal_data', 'false').lower() == 'true'
            
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
                if not can_user_access_survey(request.user, survey):
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
            # Get survey manually to avoid permission issues
            try:
                survey = Survey.objects.get(id=pk)
            except Survey.DoesNotExist:
                return uniform_response(
                    success=False,
                    message="Survey not found",
                    status_code=status.HTTP_404_NOT_FOUND
                )
            
            token = safe_get_query_params(request, 'token')
            
            # Check if survey is submitted (not draft) - draft surveys should not be publicly accessible
            if survey.status != 'submitted':
                return uniform_response(
                    success=False,
                    message="This survey is not yet available for public access. Please contact the survey creator.",
                    data={
                        'has_access': False,
                        'survey_status': 'draft',
                        'reason': 'survey_not_submitted'
                    },
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
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
                    'per_device_access': survey.per_device_access,
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
            token = safe_get_query_params(request, 'token')
            
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
                
                # Check if survey is submitted (not draft) - draft surveys should not be publicly accessible
                if survey.status != 'submitted':
                    return uniform_response(
                        success=False,
                        message="This survey is not yet available for public access. Please contact the survey creator.",
                        data={
                            'has_access': False,
                            'survey_status': 'draft',
                            'reason': 'survey_not_submitted'
                        },
                        status_code=status.HTTP_403_FORBIDDEN
                    )
                
                # Check if survey is currently active based on dates using UAE timezone
                if not is_currently_active_uae(survey):
                    arabic_message = get_arabic_status_message(survey)
                    return uniform_response(
                        success=False,
                        message=arabic_message,
                        data={
                            'has_access': False,
                            'survey_status': get_status_uae(survey),
                            'start_date': serialize_datetime_uae(survey.start_date),
                            'end_date': serialize_datetime_uae(survey.end_date)
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
                    'per_device_access': survey.per_device_access,
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
            
            # Check if survey is currently active based on dates using UAE timezone
            if not is_currently_active_uae(survey):
                arabic_message = get_arabic_status_message(survey)
                return uniform_response(
                    success=False,
                    message=arabic_message,
                    data={
                        'survey_status': get_status_uae(survey),
                        'start_date': serialize_datetime_uae(survey.start_date),
                        'end_date': serialize_datetime_uae(survey.end_date)
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
                'status': get_status_uae(survey),
                'is_currently_active': is_currently_active_uae(survey),
                'start_date': serialize_datetime_uae(survey.start_date),
                'end_date': serialize_datetime_uae(survey.end_date),
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

    @action(detail=True, methods=['post'], permission_classes=[IsCreatorOrReadOnly], url_path='send-notifications')
    def send_notifications(self, request, pk=None):
        """
        Manually send notifications to users about this survey.
        
        POST /api/surveys/surveys/{survey_id}/send-notifications/
        
        Body:
        {
            "force_send": false  // Optional: Set to true to send to all users even for PUBLIC/AUTH surveys (default: false)
        }
        
        This endpoint allows survey creators to manually send notifications after creating/updating surveys.
        By default, it will not send notifications to all users for PUBLIC surveys to prevent spam.
        Set force_send=true to override this safety check.
        """
        try:
            survey = self.get_object()
            
            # Check if survey is in a state that can receive notifications
            if survey.status != 'submitted' or not survey.is_active:
                return uniform_response(
                    success=False,
                    message="Notifications can only be sent for active, submitted surveys",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            # Get force_send parameter
            force_send = request.data.get('force_send', False)
            
            try:
                notifications = SurveyNotificationService.notify_users_of_new_survey(
                    survey, request, force_send=force_send
                )
                
                if notifications is None or len(notifications) == 0:
                    if survey.visibility == 'PUBLIC' and not force_send:
                        message = "Notifications not sent to prevent spam to all users. Use force_send=true to override."
                    elif survey.visibility == 'AUTH' and not force_send:
                        message = "Notifications not sent to prevent spam to all authenticated users. Use force_send=true to override."
                    else:
                        message = "No eligible users to notify for this survey."
                else:
                    message = f"Successfully sent {len(notifications)} notifications."
                
                logger.info(f"Manual notification sending for survey {survey.id} by {request.user.email}: {message}")
                
                return uniform_response(
                    success=True,
                    message=message,
                    data={
                        'notifications_sent': len(notifications) if notifications else 0,
                        'survey_visibility': survey.visibility,
                        'force_send_used': force_send
                    }
                )
                
            except Exception as e:
                logger.error(f"Failed to send notifications for survey {survey.id}: {e}")
                return uniform_response(
                    success=False,
                    message="Failed to send notifications",
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
        except Exception as e:
            logger.error(f"Error in send_notifications for survey {pk}: {e}")
            return uniform_response(
                success=False,
                message="Failed to process notification request",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated], 
            url_path='(?P<survey_id>[^/.]+)/analytics/questions/(?P<question_id>[^/.]+)')
    def question_analytics(self, request, survey_id=None, question_id=None):
        """
        Get detailed question-level analytics for surveys.
        
        GET /api/surveys/surveys/{survey_id}/analytics/questions/{question_id}/
        Access: Survey Creator, Admin, Super Admin, or Staff only
        
        Query Parameters:
        - start_date (ISO datetime): Filter responses from this date
        - end_date (ISO datetime): Filter responses until this date  
        - include_demographics (boolean, default: false): Include demographic breakdowns
        """
        try:
            # Get survey without permission filtering first
            try:
                survey = Survey.objects.get(id=survey_id, deleted_at__isnull=True)
            except Survey.DoesNotExist:
                return uniform_response(
                    success=False,
                    message="Survey not found",
                    status_code=status.HTTP_404_NOT_FOUND
                )
            
            # Check permission for analytics access
            user = request.user
            if not (user.role in ['admin', 'super_admin'] or user == survey.creator):
                return uniform_response(
                    success=False,
                    message="Access denied. Only admins, super admins, or survey creators can view question analytics.",
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
            # Get question
            try:
                question = survey.questions.get(id=question_id)
            except Question.DoesNotExist:
                return uniform_response(
                    success=False,
                    message="Question not found in this survey",
                    status_code=status.HTTP_404_NOT_FOUND
                )
            
            # Parse query parameters
            params = self._parse_analytics_params(request)
            
            # Get filtered responses
            responses = self._get_filtered_responses_for_analytics(survey, params)
            
            # Get answers for this question from filtered responses
            question_answers = Answer.objects.filter(
                question=question,
                response__in=responses
            ).select_related('response', 'response__respondent')
            
            # Build analytics data
            analytics_data = {
                'question': self._get_question_info_detailed(question),
                'summary': self._calculate_question_summary(responses.count(), question_answers, params),
                'distributions': self._calculate_question_distributions(question, question_answers, responses, params),
                'statistics': self._calculate_question_statistics(question, question_answers),
                'recent_responses': self._get_recent_responses(question_answers, params.get('include_demographics', False)),
                'insights': self._generate_question_insights(question, question_answers, responses.count())
            }
            
            return uniform_response(
                success=True,
                message="Question analytics retrieved successfully",
                data=analytics_data
            )
            
        except Exception as e:
            logger.error(f"Error generating question analytics for question {question_id} in survey {survey_id}: {e}")
            return uniform_response(
                success=False,
                message="Failed to generate question analytics",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _parse_analytics_params(self, request):
        """Parse analytics query parameters"""
        params = {
            'start_date': None,
            'end_date': None,
            'include_demographics': False
        }
        
        # Parse start_date
        start_date_str = safe_get_query_params(request, 'start_date')
        if start_date_str:
            try:
                params['start_date'] = parse_datetime(start_date_str)
            except (ValueError, TypeError):
                pass
        
        # Parse end_date
        end_date_str = safe_get_query_params(request, 'end_date')
        if end_date_str:
            try:
                params['end_date'] = parse_datetime(end_date_str)
            except (ValueError, TypeError):
                pass
        
        # Parse include_demographics
        include_demographics = safe_get_query_params(request, 'include_demographics', 'false').lower()
        params['include_demographics'] = include_demographics in ['true', '1', 'yes']
        
        return params
    
    def _get_filtered_responses_for_analytics(self, survey, params):
        """Get responses with date filtering for analytics"""
        queryset = survey.responses.all()
        
        # Apply date filters
        if params['start_date']:
            queryset = queryset.filter(submitted_at__gte=params['start_date'])
        if params['end_date']:
            queryset = queryset.filter(submitted_at__lte=params['end_date'])
        
        return queryset
    
    def _get_question_info_detailed(self, question):
        """Get detailed question information"""
        question_info = {
            'id': str(question.id),
            'survey_id': str(question.survey.id),
            'order': question.order,
            'type': question.question_type,
            'question_text': question.text,
            'description': '',  # Add description field if needed
            'is_required': question.is_required
        }
        
        # Add options for choice questions
        if question.question_type in ['single_choice', 'multiple_choice'] and question.options:
            try:
                options = json.loads(question.options)
                question_info['options'] = [
                    {
                        'id': opt.get('value', opt) if isinstance(opt, dict) else str(i),
                        'label': opt.get('label', opt) if isinstance(opt, dict) else opt,
                        'order': i + 1
                    }
                    for i, opt in enumerate(options)
                ]
            except (json.JSONDecodeError, TypeError):
                question_info['options'] = []
        
        return question_info
    
    def _calculate_question_summary(self, total_responses, question_answers, params):
        """Calculate question summary statistics"""
        answered_count = question_answers.count()
        skipped_count = total_responses - answered_count
        answer_rate = answered_count / total_responses if total_responses > 0 else 0.0
        skip_rate = skipped_count / total_responses if total_responses > 0 else 0.0
        
        # Get response timestamps
        response_times = question_answers.values_list('response__submitted_at', flat=True)
        
        summary = {
            'total_responses': total_responses,
            'answered_count': answered_count,
            'skipped_count': skipped_count,
            'answer_rate': round(answer_rate, 3),
            'skip_rate': round(skip_rate, 3),
            'last_response_at': None,
            'first_response_at': None
        }
        
        if response_times:
            summary['last_response_at'] = serialize_datetime_uae(max(response_times))
            summary['first_response_at'] = serialize_datetime_uae(min(response_times))
        
        return summary
    
    def _calculate_question_distributions(self, question, question_answers, all_responses, params):
        """Calculate question distributions"""
        distributions = {}
        
        # Option distribution (for choice questions)
        if question.question_type in ['single_choice', 'multiple_choice']:
            distributions['by_option'] = self._get_option_distribution(question, question_answers)
        elif question.question_type == 'rating':
            distributions['by_rating'] = self._get_rating_distribution(question_answers)
        elif question.question_type == 'yes_no':
            distributions['by_choice'] = self._get_yes_no_distribution(question_answers)
        elif question.question_type in ['text', 'textarea']:
            distributions['textual_analysis'] = self._get_textual_analysis(question_answers, params.get('include_demographics', False))
        
        # Time distribution
        distributions['by_time'] = self._get_time_distribution(question_answers)
        
        # Auth status distribution
        distributions['by_auth_status'] = self._get_auth_status_distribution(question_answers, all_responses)
        
        return distributions
    
    def _get_option_distribution(self, question, question_answers):
        """Get distribution for choice questions"""
        try:
            options = json.loads(question.options) if question.options else []
        except (json.JSONDecodeError, TypeError):
            options = []
        
        answer_texts = [answer.answer_text for answer in question_answers]
        total_answered = len(answer_texts)
        
        option_counts = Counter()
        
        # For multiple choice, parse JSON arrays
        if question.question_type == 'multiple_choice':
            for answer_text in answer_texts:
                try:
                    if answer_text.startswith('['):
                        selections = json.loads(answer_text)
                    else:
                        selections = [s.strip() for s in answer_text.split(',')]
                    
                    for selection in selections:
                        if selection:
                            option_counts[selection] += 1
                except (json.JSONDecodeError, AttributeError):
                    if answer_text:
                        option_counts[answer_text] += 1
        else:
            # Single choice
            option_counts = Counter(answer_texts)
        
        # Build distribution
        option_distribution = []
        for i, option in enumerate(options):
            option_key = option.get('value', option) if isinstance(option, dict) else option
            option_label = option.get('label', option) if isinstance(option, dict) else option
            
            count = option_counts.get(option_key, 0)
            percentage = count / total_answered if total_answered > 0 else 0
            
            option_distribution.append({
                'option_id': str(i),
                'option_label': option_label,
                'count': count,
                'percentage': round(percentage, 3),
                'rank': 0  # Will be set after sorting
            })
        
        # Add "other" responses not in predefined options
        predefined_values = {option.get('value', option) if isinstance(option, dict) else option for option in options}
        for answer_text, count in option_counts.items():
            if answer_text not in predefined_values:
                percentage = count / total_answered if total_answered > 0 else 0
                option_distribution.append({
                    'option_id': f'other_{len(option_distribution)}',
                    'option_label': f'Other: {answer_text}',
                    'count': count,
                    'percentage': round(percentage, 3),
                    'rank': 0
                })
        
        # Sort by count and assign ranks
        option_distribution.sort(key=lambda x: x['count'], reverse=True)
        for i, option in enumerate(option_distribution):
            option['rank'] = i + 1
        
        return option_distribution
    
    def _get_rating_distribution(self, question_answers):
        """Get distribution for rating questions"""
        answer_texts = [answer.answer_text for answer in question_answers]
        rating_counts = defaultdict(int)
        
        for answer_text in answer_texts:
            try:
                rating = int(float(answer_text))
                rating_counts[rating] += 1
            except (ValueError, TypeError):
                pass
        
        distribution = []
        total_ratings = sum(rating_counts.values())
        
        for rating in sorted(rating_counts.keys()):
            count = rating_counts[rating]
            percentage = count / total_ratings if total_ratings > 0 else 0
            
            distribution.append({
                'rating': rating,
                'count': count,
                'percentage': round(percentage, 3)
            })
        
        return distribution
    
    def _get_yes_no_distribution(self, question_answers):
        """Get distribution for yes/no questions"""
        answer_texts = [answer.answer_text for answer in question_answers]
        total_answers = len(answer_texts)
        
        yes_count = sum(1 for text in answer_texts if text.lower() in ['yes', 'true', '1', 'نعم'])
        no_count = sum(1 for text in answer_texts if text.lower() in ['no', 'false', '0', 'لا'])
        
        return [
            {
                'value': 'yes',
                'label': 'نعم',
                'count': yes_count,
                'percentage': round(yes_count / total_answers, 3) if total_answers > 0 else 0
            },
            {
                'value': 'no',
                'label': 'لا',
                'count': no_count,
                'percentage': round(no_count / total_answers, 3) if total_answers > 0 else 0
            }
        ]
    
    def _get_textual_analysis(self, question_answers, include_demographics):
        """Get textual analysis for text questions"""
        answer_texts = [answer.answer_text for answer in question_answers if answer.answer_text and answer.answer_text.strip()]
        
        if not answer_texts:
            return {
                'total_words': 0,
                'average_words': 0,
                'median_words': 0,
                'max_words': 0,
                'min_words': 0,
                'common_keywords': []
            }
        
        # Calculate word statistics
        word_counts = [len(text.split()) for text in answer_texts]
        total_words = sum(word_counts)
        
        analysis = {
            'total_words': total_words,
            'average_words': round(total_words / len(answer_texts), 2),
            'median_words': int(median(word_counts)),
            'max_words': max(word_counts),
            'min_words': min(word_counts),
            'common_keywords': []
        }
        
        # Add keyword analysis if demographics are included
        if include_demographics:
            word_freq = defaultdict(int)
            for text in answer_texts:
                words = text.lower().split()
                for word in words:
                    clean_word = ''.join(c for c in word if c.isalnum())
                    if len(clean_word) > 2:  # Only words longer than 2 characters
                        word_freq[clean_word] += 1
            
            # Get top keywords
            top_keywords = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:10]
            analysis['common_keywords'] = [
                {
                    'word': word,
                    'count': count,
                    'percentage': round(count / len(answer_texts), 3)
                }
                for word, count in top_keywords if count > 1
            ]
        
        return analysis
    
    def _get_time_distribution(self, question_answers):
        """Get time-based distribution"""
        responses_by_date = defaultdict(lambda: {'responses': 0, 'answered': 0, 'skipped': 0})
        
        for answer in question_answers:
            date_str = format_uae_date_only(answer.response.submitted_at)
            responses_by_date[date_str]['answered'] += 1
        
        # Convert to list format
        time_distribution = []
        for date_str in sorted(responses_by_date.keys()):
            data = responses_by_date[date_str]
            time_distribution.append({
                'period': date_str,
                'period_label': format_uae_date_only(parse_datetime(date_str + 'T00:00:00+04:00')),
                'responses': data['answered'],  # For now, same as answered
                'answered': data['answered'],
                'skipped': data['skipped']
            })
        
        return time_distribution
    
    def _get_auth_status_distribution(self, question_answers, all_responses):
        """Get distribution by authentication status"""
        authenticated_answers = question_answers.filter(response__respondent__isnull=False).count()
        anonymous_answers = question_answers.filter(response__respondent__isnull=True).count()
        
        total_authenticated = all_responses.filter(respondent__isnull=False).count()
        total_anonymous = all_responses.filter(respondent__isnull=True).count()
        
        total_responses = total_authenticated + total_anonymous
        
        return [
            {
                'type': 'authenticated',
                'count': total_authenticated,
                'percentage': round(total_authenticated / total_responses, 3) if total_responses > 0 else 0,
                'answered': authenticated_answers,
                'skipped': total_authenticated - authenticated_answers
            },
            {
                'type': 'anonymous', 
                'count': total_anonymous,
                'percentage': round(total_anonymous / total_responses, 3) if total_responses > 0 else 0,
                'answered': anonymous_answers,
                'skipped': total_anonymous - anonymous_answers
            }
        ]
    
    def _calculate_question_statistics(self, question, question_answers):
        """Calculate question statistics"""
        statistics = {}
        
        if question.question_type in ['single_choice', 'multiple_choice']:
            # Find the mode (most popular choice)
            answer_texts = [answer.answer_text for answer in question_answers]
            if answer_texts:
                most_common = Counter(answer_texts).most_common(1)[0]
                statistics['mode'] = {
                    'option_id': 'opt1',  # Simplified
                    'option_label': most_common[0],
                    'count': most_common[1],
                    'percentage': round(most_common[1] / len(answer_texts), 3)
                }
                
                # Calculate entropy (measure of diversity)
                counts = list(Counter(answer_texts).values())
                total = sum(counts)
                entropy = -sum((c/total) * math.log2(c/total) for c in counts if c > 0)
                statistics['entropy'] = round(entropy, 2)
                
                # Response consistency (simplified)
                statistics['response_consistency'] = round(most_common[1] / len(answer_texts), 2)
        
        elif question.question_type == 'rating':
            # Calculate rating statistics
            numeric_values = []
            for answer in question_answers:
                try:
                    value = float(answer.answer_text)
                    numeric_values.append(value)
                except (ValueError, TypeError):
                    pass
            
            if numeric_values:
                import statistics as stats_module
                statistics['average'] = round(stats_module.mean(numeric_values), 2)
                statistics['median'] = stats_module.median(numeric_values)
                statistics['mode'] = stats_module.mode(numeric_values) if len(set(numeric_values)) < len(numeric_values) else numeric_values[0]
                statistics['standard_deviation'] = round(stats_module.stdev(numeric_values) if len(numeric_values) > 1 else 0, 2)
                statistics['min'] = min(numeric_values)
                statistics['max'] = max(numeric_values)
        
        return statistics
    
    def _get_recent_responses(self, question_answers, include_demographics):
        """Get recent responses"""
        recent_answers = question_answers.order_by('-response__submitted_at')[:5]
        recent_responses = []
        
        for answer in recent_answers:
            response_data = {
                'id': f'resp_{answer.id}',
                'response_time': serialize_datetime_uae(answer.response.submitted_at),
                'is_authenticated': answer.response.respondent is not None,
                'completion_time_seconds': 30  # Placeholder - would need to calculate from actual data
            }
            
            # Add answer data based on question type
            if answer.question.question_type in ['single_choice', 'multiple_choice']:
                response_data['selected_option'] = {
                    'id': 'opt1',  # Simplified
                    'label': answer.answer_text
                }
            elif answer.question.question_type == 'rating':
                response_data['rating'] = answer.answer_text
            elif answer.question.question_type == 'yes_no':
                response_data['choice'] = answer.answer_text
            elif answer.question.question_type in ['text', 'textarea']:
                if include_demographics:
                    response_data['text_excerpt'] = answer.answer_text[:100] + '...' if len(answer.answer_text) > 100 else answer.answer_text
                    response_data['word_count'] = len(answer.answer_text.split())
                else:
                    response_data['text_excerpt'] = '[Text response - demographics not included]'
                    response_data['word_count'] = len(answer.answer_text.split())
            
            recent_responses.append(response_data)
        
        return recent_responses
    
    def _generate_question_insights(self, question, question_answers, total_responses):
        """Generate insights for the question"""
        insights = []
        answered_count = question_answers.count()
        answer_rate = answered_count / total_responses if total_responses > 0 else 0
        
        # Answer rate insight
        if answer_rate >= 0.9:
            insights.append({
                'type': 'skip_rate',
                'title': 'معدل تخطي منخفض',
                'description': f'{round(answer_rate * 100, 1)}% من المستجيبين أجابوا على هذا السؤال',
                'severity': 'success'
            })
        elif answer_rate < 0.7:
            insights.append({
                'type': 'skip_rate',
                'title': 'معدل تخطي مرتفع',
                'description': f'{round((1 - answer_rate) * 100, 1)}% من المستجيبين لم يجيبوا على هذا السؤال',
                'severity': 'warning'
            })
        
        # Question-type specific insights
        if question.question_type in ['single_choice', 'multiple_choice'] and answered_count > 0:
            answer_texts = [answer.answer_text for answer in question_answers]
            most_common = Counter(answer_texts).most_common(1)[0]
            most_common_pct = most_common[1] / answered_count
            
            if most_common_pct > 0.6:
                insights.append({
                    'type': 'popular_choice',
                    'title': 'الخيار الأكثر شعبية',
                    'description': f'{most_common[0]} هو الخيار الأكثر اختيارًا بنسبة {round(most_common_pct * 100, 1)}%',
                    'severity': 'info'
                })
            
            # Check for low-response options
            option_counts = Counter(answer_texts)
            for option, count in option_counts.items():
                option_pct = count / answered_count
                if option_pct < 0.1 and count > 0:
                    insights.append({
                        'type': 'low_response_option',
                        'title': 'خيار قليل الاختيار',
                        'description': f'{option} تم اختياره بنسبة {round(option_pct * 100, 1)}% فقط',
                        'severity': 'warning'
                    })
        
        elif question.question_type == 'rating' and answered_count > 0:
            numeric_values = []
            for answer in question_answers:
                try:
                    value = float(answer.answer_text)
                    numeric_values.append(value)
                except (ValueError, TypeError):
                    pass
            
            if numeric_values:
                avg_rating = mean(numeric_values)
                if avg_rating >= 4:
                    insights.append({
                        'type': 'high_rating',
                        'title': 'تقييم إيجابي',
                        'description': f'متوسط التقييم {round(avg_rating, 1)} من 5',
                        'severity': 'success'
                    })
                elif avg_rating <= 2:
                    insights.append({
                        'type': 'low_rating',
                        'title': 'تقييم منخفض',
                        'description': f'متوسط التقييم {round(avg_rating, 1)} من 5',
                        'severity': 'warning'
                    })
        
        return insights


class MySharedSurveysView(generics.ListAPIView):
    """
    Get all submitted surveys accessible to the authenticated user based on sharing rules.
    
    This includes only submitted surveys (excludes drafts):
    - ALL submitted surveys with visibility "PUBLIC" (accessible to everyone)
    - ALL submitted surveys with visibility "AUTH" (accessible to all authenticated users)
    - Submitted surveys with visibility "PRIVATE" where the user is explicitly shared (excluding own private surveys)
    - Submitted surveys with visibility "GROUPS" where the user belongs to shared groups
    
    Draft surveys are excluded as they are only visible to their creators.
    
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
    
    @classmethod
    def get_oracle_safe_fields(cls):
        """
        Get the list of fields safe to use with distinct() in Oracle.
        Excludes NCLOB fields (EncryptedTextField) to prevent ORA-00932 error.
        """
        return [
            'id', 'title_hash', 'creator', 'visibility', 
            'start_date', 'end_date', 'is_locked', 'is_active', 
            'public_contact_method', 'per_device_access', 'status',
            'created_at', 'updated_at'
        ]
    
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
            # Oracle fix: use only() to exclude NCLOB fields when using distinct() to avoid ORA-00932 error
            queryset = Survey.objects.filter(
                base_query,
                deleted_at__isnull=True,
                is_active=True,  # Only show active surveys
                status='submitted'  # Only show submitted surveys, exclude drafts
            ).distinct().select_related('creator').only(*self.get_oracle_safe_fields())
            
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
                # Oracle fix: use only() to exclude NCLOB fields when using distinct() to avoid ORA-00932 error
                return Survey.objects.filter(
                    Q(visibility='PUBLIC') | Q(visibility='AUTH'),
                    deleted_at__isnull=True,
                    is_active=True
                ).distinct().select_related('creator').only(*self.get_oracle_safe_fields())
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
                    'status': get_status_uae(survey),
                    'is_currently_active': is_currently_active_uae(survey),
                    'start_date': serialize_datetime_uae(survey.start_date),
                    'end_date': serialize_datetime_uae(survey.end_date),
                    'created_at': serialize_datetime_uae(survey.created_at),
                    'updated_at': serialize_datetime_uae(survey.updated_at),
                    'creator': {
                        'id': survey.creator.id if survey.creator else None,
                        'email': survey.creator.email if survey.creator else 'Deleted User',
                        'name': survey.creator.full_name if survey.creator else 'Deleted User'
                    } if survey.creator else {
                        'id': None,
                        'email': 'Deleted User',
                        'name': 'Deleted User'
                    },
                    'questions_count': survey.questions.count(),
                    'estimated_time': max(survey.questions.count() * 1, 5),
                    'access_info': {
                        'access_type': survey.visibility,
                        'can_submit': not has_submitted and is_currently_active_uae(survey) and not survey.is_locked,
                        'has_submitted': has_submitted,
                        'is_shared_explicitly': survey.visibility == 'PRIVATE',
                        'is_shared_via_group': survey.visibility == 'GROUPS',
                        'is_creator': survey.creator == request.user if survey.creator is not None else False
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
            query = safe_get_query_params(request, 'query', '').strip()
            
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
            
            # Check if survey is currently active based on dates using UAE timezone
            if not is_currently_active_uae(survey):
                status_message = f"Survey is {get_status_uae(survey)}"
                return uniform_response(
                    success=False,
                    message=status_message,
                    data={
                        'survey_status': get_status_uae(survey),
                        'start_date': serialize_datetime_uae(survey.start_date),
                        'end_date': serialize_datetime_uae(survey.end_date)
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
        Validate access to survey based on visibility and provided credentials using UAE timezone
        Returns tuple: (has_access, user_or_email_or_phone, error_message)
        """
        # Check if survey is currently active based on dates using UAE timezone
        if not is_currently_active_uae(survey):
            status_message = f"Survey is {get_status_uae(survey)}"
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
            # Check if survey uses per-device access
            if survey.per_device_access:
                # For per-device access, no email/phone required but check device
                from .models import DeviceResponse
                
                # Check if device has already submitted
                if DeviceResponse.has_device_submitted(survey, request):
                    return False, None, "This device has already submitted a response to this survey"
                
                # Allow access without email/phone requirement
                if request.user.is_authenticated:
                    return True, request.user, None
                else:
                    return True, "anonymous_device", None
            else:
                # Standard PUBLIC survey - require email or phone for anonymous users
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
            respondent_email = None
            respondent_phone = None
            
            # Handle per-device access differently
            if survey.per_device_access and user_or_contact == "anonymous_device":
                # For per-device access, no email/phone needed
                pass  
            elif isinstance(user_or_contact, str) and user_or_contact != "anonymous_device":
                respondent_email = user_or_contact if '@' in user_or_contact else None
                respondent_phone = user_or_contact if '@' not in user_or_contact else None
            
            # Check for duplicate submissions (skip for per-device access as it's handled in validation)
            existing_response = None
            if not survey.per_device_access:
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
            
            # Create device tracking record if per-device access is enabled
            if survey.per_device_access:
                from .models import DeviceResponse
                DeviceResponse.create_device_tracking(survey, request, survey_response)
            
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
        token = request.data.get('token') or safe_get_query_params(request, 'token')
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
            
            # Check if survey is currently active based on dates using UAE timezone
            if not is_currently_active_uae(survey):
                status_message = f"Survey is {get_status_uae(survey)}"
                return uniform_response(
                    success=False,
                    message=status_message,
                    data={
                        'survey_status': get_status_uae(survey),
                        'start_date': serialize_datetime_uae(survey.start_date),
                        'end_date': serialize_datetime_uae(survey.end_date)
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
        
        # Validate survey ID
        if not survey_id or survey_id == 'undefined' or survey_id == 'null':
            return SurveyResponse.objects.none()
            
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


# Analytics Dashboard APIs
class SurveyAnalyticsDashboardView(APIView):
    """
    Survey-level analytics dashboard providing comprehensive KPIs and question summaries.
    
    GET /api/surveys/admin/surveys/{survey_id}/dashboard/
    Access: Admin, Super Admin, or Survey Creator only
    
    Query Parameters:
    - start (ISO datetime): Filter responses from this date
    - end (ISO datetime): Filter responses until this date  
    - tz (timezone): Timezone for grouping (default: Asia/Dubai)
    - group_by (day|week|month): Time series grouping (default: day)
    - include_personal (true|false): Include PII in responses (default: false)
    """
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request, survey_id):
        """Get comprehensive survey analytics dashboard"""
        try:
            # Validate survey access
            survey = self._get_survey_with_permission_check(request, survey_id)
            if isinstance(survey, Response):  # Error response
                return survey
            
            # Parse query parameters
            try:
                params = self._parse_query_params(request)
                logger.info(f"Successfully parsed query parameters for survey {survey_id}")
            except Exception as parse_error:
                logger.error(f"Error parsing query parameters for survey {survey_id}: {parse_error}")
                # Use default parameters if parsing fails
                params = {
                    'start': None,
                    'end': None,
                    'tz': 'Asia/Dubai',
                    'group_by': 'day',
                    'include_personal': False
                }
            
            # Get filtered responses with optimized prefetch
            responses = self._get_filtered_responses(survey, params)
            logger.info(f"Retrieved {responses.count()} responses for survey {survey_id} analytics")
            
            # Build dashboard data
            dashboard_data = {
                'survey': self._get_survey_info(survey),
                'kpis': self._calculate_kpis(survey, responses, params['include_personal']),
                'time_series': self._generate_time_series(responses, params),
                'segments': self._calculate_segments(responses),
                'questions_summary': self._get_questions_summary(survey, responses, params['include_personal']),
                'export': self._get_export_links(survey, params['include_personal'])
            }
            
            logger.info(f"Successfully generated analytics dashboard for survey {survey_id}")
            return uniform_response(
                success=True,
                message="Survey analytics retrieved successfully",
                data=dashboard_data
            )
            
        except Exception as e:
            logger.error(f"Error generating survey analytics dashboard: {e}")
            return uniform_response(
                success=False,
                message="Failed to generate analytics dashboard",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _get_survey_with_permission_check(self, request, survey_id):
        """Get survey and check permissions"""
        try:
            survey = Survey.objects.get(id=survey_id, deleted_at__isnull=True)
            logger.info(f"Found survey {survey_id}: {survey.title}")
        except Survey.DoesNotExist:
            logger.warning(f"Survey {survey_id} not found")
            return uniform_response(
                success=False,
                message="Survey not found",
                status_code=status.HTTP_404_NOT_FOUND
            )
        
        user = request.user
        if not (user.role in ['admin', 'super_admin'] or user == survey.creator):
            logger.warning(f"Access denied to survey {survey_id} for user {user.id} (role: {user.role})")
            return uniform_response(
                success=False,
                message="Access denied. Only admins, super admins, or survey creators can view analytics.",
                status_code=status.HTTP_403_FORBIDDEN
            )
        
        logger.info(f"Analytics access granted to user {user.id} (role: {user.role}) for survey {survey_id}")
        return survey
    
    def _parse_query_params(self, request):
        """Parse and validate query parameters"""
        try:
            params = {
                'start': None,
                'end': None,
                'tz': 'Asia/Dubai',
                'group_by': 'day',
                'include_personal': False
            }
            
            # Parse start date
            start_str = safe_get_query_params(request, 'start')
            if start_str:
                try:
                    params['start'] = parse_datetime(start_str)
                except (ValueError, TypeError) as e:
                    logger.warning(f"Invalid start date format '{start_str}': {e}")
            
            # Parse end date
            end_str = safe_get_query_params(request, 'end')
            if end_str:
                try:
                    params['end'] = parse_datetime(end_str)
                except (ValueError, TypeError) as e:
                    logger.warning(f"Invalid end date format '{end_str}': {e}")
            
            # Parse timezone
            tz_str = safe_get_query_params(request, 'tz', 'Asia/Dubai')
            try:
                pytz.timezone(tz_str)  # Validate timezone
                params['tz'] = tz_str
            except pytz.exceptions.UnknownTimeZoneError as e:
                logger.warning(f"Invalid timezone '{tz_str}': {e}, using default 'Asia/Dubai'")
                params['tz'] = 'Asia/Dubai'
            
            # Parse group_by
            group_by = safe_get_query_params(request, 'group_by', 'day').lower()
            if group_by in ['day', 'week', 'month']:
                params['group_by'] = group_by
            else:
                logger.warning(f"Invalid group_by value '{group_by}', using default 'day'")
                params['group_by'] = 'day'
            
            # Parse include_personal
            include_personal = safe_get_query_params(request, 'include_personal', 'false').lower()
            params['include_personal'] = include_personal in ['true', '1', 'yes']
            
            return params
            
        except Exception as e:
            logger.error(f"Error parsing query parameters: {e}")
            # Return default parameters on any error
            return {
                'start': None,
                'end': None,
                'tz': 'Asia/Dubai',
                'group_by': 'day',
                'include_personal': False
            }
    
    def _get_filtered_responses(self, survey, params):
        """Get responses with date filtering and optimization"""
        queryset = survey.responses.all().select_related('respondent').prefetch_related('answers__question')
        
        # Apply date filters
        if params['start']:
            queryset = queryset.filter(submitted_at__gte=params['start'])
        if params['end']:
            queryset = queryset.filter(submitted_at__lte=params['end'])
        
        return queryset
    
    def _get_survey_info(self, survey):
        """Get basic survey information"""
        return {
            'id': str(survey.id),
            'title': survey.title,
            'visibility': survey.visibility,
            'created_at': serialize_datetime_uae(survey.created_at),
            'total_questions': survey.questions.count()
        }
    
    def _calculate_kpis(self, survey, responses, include_personal):
        """Calculate key performance indicators"""
        total_responses = responses.count()
        
        if total_responses == 0:
            return {
                'total_responses': 0,
                'unique_respondents': 0,
                'completion_rate': 0.0,
                'authenticated_count': 0,
                'anonymous_count': 0,
                'first_response_at': None,
                'last_response_at': None,
                'unique_ips': 0
            }
        
        # Calculate unique respondents based on survey's contact method
        unique_respondents = self._calculate_unique_respondents(survey, responses)
        
        # Completion rate
        complete_count = responses.filter(is_complete=True).count()
        completion_rate = complete_count / total_responses if total_responses > 0 else 0.0
        
        # Authentication counts
        authenticated_count = responses.filter(respondent__isnull=False).count()
        anonymous_count = total_responses - authenticated_count
        
        # Time range
        first_response = responses.order_by('submitted_at').first()
        last_response = responses.order_by('-submitted_at').first()
        
        # Unique IPs (only if include_personal is True)
        unique_ips = 0
        if include_personal:
            unique_ips = responses.filter(ip_address__isnull=False).values('ip_address').distinct().count()
        
        return {
            'total_responses': total_responses,
            'unique_respondents': unique_respondents,
            'completion_rate': round(completion_rate, 3),
            'authenticated_count': authenticated_count,
            'anonymous_count': anonymous_count,
            'first_response_at': serialize_datetime_uae(first_response.submitted_at) if first_response else None,
            'last_response_at': serialize_datetime_uae(last_response.submitted_at) if last_response else None,
            'unique_ips': unique_ips
        }
    
    def _calculate_unique_respondents(self, survey, responses):
        """Calculate unique respondents based on contact method"""
        # Count authenticated users
        auth_count = responses.filter(respondent__isnull=False).values('respondent').distinct().count()
        
        # Count anonymous users based on contact method
        anon_count = 0
        if survey.public_contact_method == 'email':
            anon_count = responses.filter(
                respondent__isnull=True,
                respondent_email__isnull=False
            ).values('respondent_email').distinct().count()
        elif survey.public_contact_method == 'phone':
            anon_count = responses.filter(
                respondent__isnull=True,
                respondent_phone__isnull=False
            ).values('respondent_phone').distinct().count()
        
        return auth_count + anon_count
    
    def _generate_time_series(self, responses, params):
        """Generate time series data for responses"""
        if not responses.exists():
            return []
        
        # Get timezone for grouping
        tz = pytz.timezone(params['tz'])
        
        # Group responses by time period
        grouped_data = defaultdict(lambda: {'responses': 0, 'complete': 0, 'incomplete': 0})
        
        for response in responses:
            # Convert to specified timezone
            local_time = response.submitted_at.astimezone(tz)
            
            # Generate period key based on group_by
            if params['group_by'] == 'day':
                period_key = local_time.strftime('%Y-%m-%d')
            elif params['group_by'] == 'week':
                # Week start (Monday)
                week_start = local_time - timedelta(days=local_time.weekday())
                period_key = week_start.strftime('%Y-%m-%d')
            else:  # month
                period_key = local_time.strftime('%Y-%m')
            
            grouped_data[period_key]['responses'] += 1
            if response.is_complete:
                grouped_data[period_key]['complete'] += 1
            else:
                grouped_data[period_key]['incomplete'] += 1
        
        # Sort and format output
        time_series = []
        for period in sorted(grouped_data.keys()):
            data = grouped_data[period]
            time_series.append({
                'period': period,
                'responses': data['responses'],
                'complete': data['complete'],
                'incomplete': data['incomplete']
            })
        
        return time_series
    
    def _calculate_segments(self, responses):
        """Calculate response segments"""
        total = responses.count()
        
        # By authentication type
        auth_count = responses.filter(respondent__isnull=False).count()
        anon_count = total - auth_count
        
        by_auth = [
            {'type': 'authenticated', 'count': auth_count},
            {'type': 'anonymous', 'count': anon_count}
        ]
        
        # By completion status
        complete_count = responses.filter(is_complete=True).count()
        incomplete_count = total - complete_count
        
        by_completion = [
            {'status': 'complete', 'count': complete_count},
            {'status': 'incomplete', 'count': incomplete_count}
        ]
        
        return {
            'by_auth': by_auth,
            'by_completion': by_completion
        }
    
    def _get_questions_summary(self, survey, responses, include_personal):
        """Generate summary analytics for each question"""
        questions = survey.questions.all().order_by('order')
        total_responses = responses.count()
        summaries = []
        
        for question in questions:
            # Get all answers for this question
            question_answers = Answer.objects.filter(
                question=question,
                response__in=responses
            ).select_related('response')
            
            answer_count = question_answers.count()
            skipped_count = total_responses - answer_count
            
            # Generate distributions based on question type
            distributions = self._calculate_question_distributions(
                question, question_answers, include_personal
            )
            
            summary = {
                'question_id': str(question.id),
                'order': question.order,
                'type': question.question_type,
                'is_required': question.is_required,
                'answer_count': answer_count,
                'skipped_count': skipped_count,
                'distributions': distributions
            }
            
            summaries.append(summary)
        
        return summaries
    
    def _calculate_question_distributions(self, question, answers, include_personal):
        """Calculate distributions based on question type"""
        distributions = {}
        answer_texts = [answer.answer_text for answer in answers]
        
        if question.question_type in ['single_choice', 'multiple_choice']:
            # Parse options from question
            try:
                options = json.loads(question.options) if question.options else []
            except (json.JSONDecodeError, TypeError):
                options = []
            
            # Count responses for each option
            option_counts = Counter()
            total_answers = len(answer_texts)
            
            for answer_text in answer_texts:
                if question.question_type == 'multiple_choice':
                    # Handle multiple selections (assuming comma-separated or JSON array)
                    try:
                        selected = json.loads(answer_text) if answer_text.startswith('[') else answer_text.split(',')
                        for selection in selected:
                            selection = selection.strip()
                            option_counts[selection] += 1
                    except (json.JSONDecodeError, AttributeError):
                        option_counts[answer_text] += 1
                else:
                    option_counts[answer_text] += 1
            
            # Format option distribution
            option_list = []
            for option in options:
                count = option_counts.get(option['value'] if isinstance(option, dict) else option, 0)
                pct = count / total_answers if total_answers > 0 else 0
                option_list.append({
                    'label': option['label'] if isinstance(option, dict) else option,
                    'count': count,
                    'pct': round(pct, 3)
                })
            
            distributions['options'] = option_list
            
        elif question.question_type == 'yes_no':
            # Count yes/no responses
            yes_count = sum(1 for text in answer_texts if text.lower() in ['yes', 'true', '1', 'نعم'])
            no_count = sum(1 for text in answer_texts if text.lower() in ['no', 'false', '0', 'لا'])
            total_answers = len(answer_texts)
            
            distributions['yes_no'] = [
                {
                    'value': 'yes',
                    'count': yes_count,
                    'pct': round(yes_count / total_answers, 3) if total_answers > 0 else 0
                },
                {
                    'value': 'no', 
                    'count': no_count,
                    'pct': round(no_count / total_answers, 3) if total_answers > 0 else 0
                }
            ]
            
        elif question.question_type == 'rating':
            # Calculate rating statistics
            numeric_values = []
            for text in answer_texts:
                try:
                    numeric_values.append(float(text))
                except (ValueError, TypeError):
                    pass
            
            if numeric_values:
                avg_rating = mean(numeric_values)
                median_rating = median(numeric_values)
                
                # Create histogram
                histogram = defaultdict(int)
                for value in numeric_values:
                    bucket = str(int(value))  # Round to nearest integer for buckets
                    histogram[bucket] += 1
                
                histogram_list = []
                for bucket in sorted(histogram.keys(), key=lambda x: int(x)):
                    histogram_list.append({
                        'bucket': bucket,
                        'count': histogram[bucket]
                    })
                
                distributions['rating'] = {
                    'avg': round(avg_rating, 2),
                    'median': median_rating,
                    'histogram': histogram_list
                }
            
        elif question.question_type in ['text', 'textarea']:
            # Text analysis
            if include_personal:
                # Show sample responses (limited to 5)
                sample_texts = [text for text in answer_texts[:5] if text.strip()]
                distributions['sample_text'] = sample_texts
            else:
                # Count basic statistics without revealing content
                word_counts = []
                for text in answer_texts:
                    word_counts.append(len(text.split()) if text else 0)
                
                if word_counts:
                    distributions['textual'] = {
                        'avg_words': round(mean(word_counts), 1),
                        'total_responses': len(word_counts)
                    }
                else:
                    distributions['textual'] = {
                        'avg_words': 0,
                        'total_responses': 0
                    }
        
        return distributions
    
    def _get_export_links(self, survey, include_personal):
        """Generate export links"""
        personal_param = 'true' if include_personal else 'false'
        base_url = f"/api/surveys/surveys/{survey.id}/export/"
        
        return {
            'csv': f"{base_url}?format=csv&include_personal_data={personal_param}",
            'json': f"{base_url}?format=json&include_personal_data={personal_param}"
        }


class QuestionAnalyticsDashboardView(APIView):
    """
    Question-level analytics dashboard providing deep dive analysis per question.
    
    GET /api/surveys/admin/surveys/{survey_id}/questions/{question_id}/dashboard/
    Access: Admin, Super Admin, or Survey Creator only
    
    Query Parameters:
    - start (ISO datetime): Filter responses from this date
    - end (ISO datetime): Filter responses until this date
    - tz (timezone): Timezone for analysis (default: Asia/Dubai)
    - group_by (day|week|month): Not used for question analysis but kept for API consistency
    - include_personal (true|false): Include PII in text responses (default: false)
    """
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request, survey_id, question_id):
        """Get detailed question analytics"""
        try:
            # Validate survey and question access
            survey, question = self._get_survey_question_with_permission_check(request, survey_id, question_id)
            if isinstance(survey, Response):  # Error response
                return survey
            
            # Parse query parameters
            params = self._parse_query_params(request)
            
            # Get filtered responses for this question
            responses = self._get_filtered_responses(survey, params)
            question_answers = Answer.objects.filter(
                question=question,
                response__in=responses
            ).select_related('response', 'response__respondent')
            
            # Build question dashboard data
            dashboard_data = {
                'question': self._get_question_info(question),
                'kpis': self._calculate_question_kpis(responses.count(), question_answers),
                'analytics': self._get_detailed_question_analytics(question, question_answers, params['include_personal'])
            }
            
            return uniform_response(
                success=True,
                message="Question analytics retrieved successfully",
                data=dashboard_data
            )
            
        except Exception as e:
            logger.error(f"Error generating question analytics dashboard: {e}")
            return uniform_response(
                success=False,
                message="Failed to generate question analytics",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _get_survey_question_with_permission_check(self, request, survey_id, question_id):
        """Get survey and question with permission check"""
        try:
            survey = Survey.objects.get(id=survey_id, deleted_at__isnull=True)
            question = Question.objects.get(id=question_id, survey=survey)
        except Survey.DoesNotExist:
            return uniform_response(
                success=False,
                message="Survey not found",
                status_code=status.HTTP_404_NOT_FOUND
            ), None
        except Question.DoesNotExist:
            return uniform_response(
                success=False,
                message="Question not found in this survey",
                status_code=status.HTTP_404_NOT_FOUND
            ), None
        
        user = request.user
        if not (user.role in ['admin', 'super_admin'] or user == survey.creator):
            return uniform_response(
                success=False,
                message="Access denied. Only admins, super admins, or survey creators can view question analytics.",
                status_code=status.HTTP_403_FORBIDDEN
            ), None
        
        return survey, question
    
    def _parse_query_params(self, request):
        """Parse query parameters (same as survey dashboard)"""
        params = {
            'start': None,
            'end': None,
            'tz': 'Asia/Dubai',
            'include_personal': False
        }
        
        # Parse start date
        start_str = safe_get_query_params(request, 'start')
        if start_str:
            try:
                params['start'] = parse_datetime(start_str)
            except (ValueError, TypeError):
                pass
        
        # Parse end date
        end_str = safe_get_query_params(request, 'end')
        if end_str:
            try:
                params['end'] = parse_datetime(end_str)
            except (ValueError, TypeError):
                pass
        
        # Parse include_personal
        include_personal = safe_get_query_params(request, 'include_personal', 'false').lower()
        params['include_personal'] = include_personal in ['true', '1', 'yes']
        
        return params
    
    def _get_filtered_responses(self, survey, params):
        """Get responses with date filtering"""
        queryset = survey.responses.all()
        
        # Apply date filters
        if params['start']:
            queryset = queryset.filter(submitted_at__gte=params['start'])
        if params['end']:
            queryset = queryset.filter(submitted_at__lte=params['end'])
        
        return queryset
    
    def _get_question_info(self, question):
        """Get question information"""
        return {
            'id': str(question.id),
            'order': question.order,
            'type': question.question_type,
            'is_required': question.is_required,
            'text': question.text
        }
    
    def _calculate_question_kpis(self, total_responses, question_answers):
        """Calculate question-level KPIs"""
        answer_count = question_answers.count()
        skipped_count = total_responses - answer_count
        answer_rate = answer_count / total_responses if total_responses > 0 else 0.0
        
        return {
            'answer_count': answer_count,
            'skipped_count': skipped_count,
            'answer_rate': round(answer_rate, 3)
        }
    
    def _get_detailed_question_analytics(self, question, answers, include_personal):
        """Get detailed analytics based on question type"""
        analytics = {}
        answer_texts = [answer.answer_text for answer in answers]
        total_answers = len(answer_texts)
        
        if question.question_type == 'single_choice':
            analytics['single_choice'] = self._analyze_single_choice(question, answer_texts, total_answers)
            
        elif question.question_type == 'multiple_choice':
            analytics['multiple_choice'] = self._analyze_multiple_choice(question, answer_texts, total_answers)
            
        elif question.question_type == 'yes_no':
            analytics['yes_no'] = self._analyze_yes_no(answer_texts, total_answers)
            
        elif question.question_type == 'rating':
            analytics['rating'] = self._analyze_rating(answer_texts)
            
        elif question.question_type in ['text', 'textarea']:
            analytics['textual'] = self._analyze_textual(answer_texts, include_personal)
        
        return analytics
    
    def _analyze_single_choice(self, question, answer_texts, total_answers):
        """Analyze single choice question"""
        try:
            options = json.loads(question.options) if question.options else []
        except (json.JSONDecodeError, TypeError):
            options = []
        
        # Count responses for each option
        option_counts = Counter(answer_texts)
        
        option_list = []
        for option in options:
            option_key = option['value'] if isinstance(option, dict) else option
            option_label = option['label'] if isinstance(option, dict) else option
            
            count = option_counts.get(option_key, 0)
            pct = count / total_answers if total_answers > 0 else 0
            
            option_list.append({
                'label': option_label,
                'count': count,
                'pct': round(pct, 3)
            })
        
        # Add any "other" responses not in predefined options
        predefined_values = {option['value'] if isinstance(option, dict) else option for option in options}
        for answer_text, count in option_counts.items():
            if answer_text not in predefined_values:
                pct = count / total_answers if total_answers > 0 else 0
                option_list.append({
                    'label': f'Other: {answer_text}',
                    'count': count,
                    'pct': round(pct, 3)
                })
        
        return {'options': option_list}
    
    def _analyze_multiple_choice(self, question, answer_texts, total_answers):
        """Analyze multiple choice question"""
        try:
            options = json.loads(question.options) if question.options else []
        except (json.JSONDecodeError, TypeError):
            options = []
        
        # Count how many respondents selected each option
        option_counts = defaultdict(int)
        
        for answer_text in answer_texts:
            try:
                # Try parsing as JSON array first
                if answer_text.startswith('['):
                    selections = json.loads(answer_text)
                else:
                    # Split by comma as fallback
                    selections = [s.strip() for s in answer_text.split(',')]
                
                for selection in selections:
                    if selection:  # Skip empty selections
                        option_counts[selection] += 1
                        
            except (json.JSONDecodeError, AttributeError):
                # Single selection case
                if answer_text:
                    option_counts[answer_text] += 1
        
        option_list = []
        for option in options:
            option_key = option['value'] if isinstance(option, dict) else option
            option_label = option['label'] if isinstance(option, dict) else option
            
            count = option_counts.get(option_key, 0)
            respondent_pct = count / total_answers if total_answers > 0 else 0
            
            option_list.append({
                'label': option_label,
                'count': count,
                'respondent_pct': round(respondent_pct, 3)  # Percentage of respondents who selected this
            })
        
        # Add any "other" responses
        predefined_values = {option['value'] if isinstance(option, dict) else option for option in options}
        for selection, count in option_counts.items():
            if selection not in predefined_values:
                respondent_pct = count / total_answers if total_answers > 0 else 0
                option_list.append({
                    'label': f'Other: {selection}',
                    'count': count,
                    'respondent_pct': round(respondent_pct, 3)
                })
        
        return {'options': option_list}
    
    def _analyze_yes_no(self, answer_texts, total_answers):
        """Analyze yes/no question"""
        yes_count = sum(1 for text in answer_texts if text.lower() in ['yes', 'true', '1', 'نعم'])
        no_count = sum(1 for text in answer_texts if text.lower() in ['no', 'false', '0', 'لا'])
        
        result = []
        for value, count in [('yes', yes_count), ('no', no_count)]:
            pct = count / total_answers if total_answers > 0 else 0
            result.append({
                'value': value,
                'count': count,
                'pct': round(pct, 3)
            })
        
        return result
    
    def _analyze_rating(self, answer_texts):
        """Analyze rating question"""
        numeric_values = []
        for text in answer_texts:
            try:
                value = float(text)
                numeric_values.append(value)
            except (ValueError, TypeError):
                pass
        
        if not numeric_values:
            return {
                'avg': 0,
                'median': 0,
                'histogram': []
            }
        
        avg_rating = mean(numeric_values)
        median_rating = median(numeric_values)
        
        # Create histogram (bucket by integer values)
        histogram_data = defaultdict(int)
        for value in numeric_values:
            bucket = str(int(value))  # Round to nearest integer
            histogram_data[bucket] += 1
        
        histogram = []
        for bucket in sorted(histogram_data.keys(), key=lambda x: int(x)):
            histogram.append({
                'bucket': bucket,
                'count': histogram_data[bucket]
            })
        
        return {
            'avg': round(avg_rating, 2),
            'median': median_rating,
            'histogram': histogram
        }
    
    def _analyze_textual(self, answer_texts, include_personal):
        """Analyze text/textarea questions"""
        if not answer_texts:
            return {
                'top_terms': [],
                'samples': []
            }
        
        # Simple word frequency analysis (without PII if include_personal is False)
        word_freq = defaultdict(int)
        clean_texts = [text for text in answer_texts if text and text.strip()]
        
        if not include_personal:
            # Return basic statistics without revealing content
            word_counts = [len(text.split()) for text in clean_texts]
            char_counts = [len(text) for text in clean_texts]
            
            return {
                'response_count': len(clean_texts),
                'avg_words': round(mean(word_counts), 1) if word_counts else 0,
                'avg_chars': round(mean(char_counts), 1) if char_counts else 0,
                'samples': []  # No samples when include_personal is False
            }
        
        # When include_personal is True, provide more detailed analysis
        for text in clean_texts:
            # Simple word extraction (split by space and clean)
            words = text.lower().split()
            for word in words:
                # Simple cleaning (remove punctuation)
                clean_word = ''.join(c for c in word if c.isalnum())
                if len(clean_word) > 2:  # Only include words longer than 2 characters
                    word_freq[clean_word] += 1
        
        # Get top terms
        top_terms = []
        for word, count in sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:10]:
            if count > 1:  # Only include words that appear more than once
                top_terms.append({
                    'term': word,
                    'count': count
                })
        
        # Get sample responses (up to 5)
        samples = clean_texts[:5]
        
        return {
            'top_terms': top_terms,
            'samples': samples
        }


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


class SurveyQuestionsAnalyticsView(APIView):
    """
    Survey questions analytics overview providing summary analytics for all questions.
    
    GET /api/surveys/admin/surveys/{survey_id}/questions/analytics/dashboard/
    Access: Admin, Super Admin, or Survey Creator only
    
    This endpoint provides an overview of analytics for all questions in a survey,
    similar to the questions_summary section in the survey dashboard but with
    more detailed analytics per question.
    """
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request, survey_id):
        """Get analytics overview for all questions in a survey"""
        try:
            # Validate survey access
            survey = self._get_survey_with_permission_check(request, survey_id)
            if isinstance(survey, Response):  # Error response
                return survey
            
            # Parse query parameters
            params = self._parse_query_params(request)
            
            # Get filtered responses with optimized prefetch
            responses = self._get_filtered_responses(survey, params)
            
            # Get questions with their analytics
            questions = survey.questions.all().order_by('order')
            questions_analytics = []
            
            for question in questions:
                # Get answers for this question from filtered responses
                question_answers = []
                for response in responses:
                    for answer in response.answers.all():
                        if answer.question_id == question.id:
                            question_answers.append(answer)
                
                # Calculate question KPIs
                answer_count = len(question_answers)
                skipped_count = len(responses) - answer_count
                answer_rate = answer_count / len(responses) if responses else 0
                
                # Get detailed analytics for this question
                analytics = self._get_detailed_question_analytics(question, question_answers, params['include_personal'])
                
                question_data = {
                    'id': str(question.id),
                    'text': question.text,
                    'type': question.question_type,
                    'is_required': question.is_required,
                    'order': question.order,
                    'kpis': {
                        'answer_count': answer_count,
                        'skipped_count': skipped_count,
                        'answer_rate': round(answer_rate, 3),
                        'total_eligible_responses': len(responses)
                    },
                    'analytics': analytics
                }
                
                questions_analytics.append(question_data)
            
            # Build dashboard data
            dashboard_data = {
                'survey': {
                    'id': str(survey.id),
                    'title': survey.title,
                    'total_questions': len(questions),
                    'total_responses': len(responses)
                },
                'questions': questions_analytics,
                'summary': {
                    'total_questions': len(questions),
                    'avg_answer_rate': round(sum(q['kpis']['answer_rate'] for q in questions_analytics) / len(questions_analytics) if questions_analytics else 0, 3),
                    'total_responses': len(responses)
                }
            }
            
            return uniform_response(
                success=True,
                message="Survey questions analytics retrieved successfully",
                data=dashboard_data
            )
            
        except Exception as e:
            logger.error(f"Error generating survey questions analytics: {e}")
            return uniform_response(
                success=False,
                message="Failed to generate questions analytics",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _get_survey_with_permission_check(self, request, survey_id):
        """Get survey with permission check (reuse from SurveyAnalyticsDashboardView)"""
        try:
            survey = Survey.objects.get(id=survey_id, deleted_at__isnull=True)
        except Survey.DoesNotExist:
            return uniform_response(
                success=False,
                message="Survey not found",
                status_code=status.HTTP_404_NOT_FOUND
            )
        
        user = request.user
        if not (user.role in ['admin', 'super_admin'] or user == survey.creator):
            return uniform_response(
                success=False,
                message="Access denied. Only admins, super admins, or survey creators can view analytics.",
                status_code=status.HTTP_403_FORBIDDEN
            )
        
        return survey
    
    def _parse_query_params(self, request):
        """Parse query parameters (same logic as other analytics views)"""
        params = {
            'start': None,
            'end': None,
            'tz': 'Asia/Dubai',
            'include_personal': False
        }
        
        # Parse start date
        start = safe_get_query_params(request, 'start')
        if start:
            try:
                params['start'] = parse_datetime(start)
            except ValueError:
                pass
        
        # Parse end date
        end = safe_get_query_params(request, 'end')
        if end:
            try:
                params['end'] = parse_datetime(end)
            except ValueError:
                pass
        
        # Parse timezone
        tz = safe_get_query_params(request, 'tz', 'Asia/Dubai')
        try:
            pytz.timezone(tz)
            params['tz'] = tz
        except pytz.exceptions.UnknownTimeZoneError:
            pass
        
        # Parse include_personal
        include_personal = safe_get_query_params(request, 'include_personal', 'false').lower()
        params['include_personal'] = include_personal in ['true', '1', 'yes']
        
        return params
    
    def _get_filtered_responses(self, survey, params):
        """Get filtered responses (same logic as other analytics views)"""
        responses = SurveyResponse.objects.filter(
            survey=survey
        ).prefetch_related(
            'answers',
            'answers__question'
        ).select_related('respondent')
        
        # Apply date filtering
        if params['start']:
            responses = responses.filter(submitted_at__gte=params['start'])
        if params['end']:
            responses = responses.filter(submitted_at__lte=params['end'])
        
        return responses
    
    def _get_detailed_question_analytics(self, question, question_answers, include_personal):
        """Get detailed analytics for a specific question type (reuse from QuestionAnalyticsDashboardView)"""
        distributions = {}
        answer_texts = []
        answer_values = []
        
        for answer in question_answers:
            if answer.answer_text:
                answer_texts.append(answer.answer_text)
                # For choice questions, the answer_text contains the selected values
                answer_values.append(answer.answer_text)
        
        if question.question_type == 'single_choice':
            # Single choice analytics
            if answer_values and question.options:
                import json
                from collections import Counter
                try:
                    options = json.loads(question.options) if question.options else []
                except (json.JSONDecodeError, TypeError):
                    options = []
                
                if options:
                    value_counts = Counter(answer_values)
                    total = len(answer_values)
                    
                    option_results = []
                    for option in options:
                        count = value_counts.get(option, 0)
                        pct = count / total if total > 0 else 0
                        
                        option_results.append({
                            'label': option,
                            'value': option,
                            'count': count,
                            'pct': round(pct, 3)
                        })
                    
                    # Find top choice
                    top_choice = None
                    if option_results:
                        top_option = max(option_results, key=lambda x: x['count'])
                        top_choice = {
                            'label': top_option['label'],
                            'count': top_option['count'],
                            'pct': top_option['pct']
                        }
                    
                    distributions['single_choice'] = {
                        'options': sorted(option_results, key=lambda x: x['count'], reverse=True),
                        'top_choice': top_choice
                    }
        
        elif question.question_type == 'multiple_choice':
            # Multiple choice analytics
            if answer_texts and question.options:
                import json
                from collections import Counter
                try:
                    options = json.loads(question.options) if question.options else []
                except (json.JSONDecodeError, TypeError):
                    options = []
                
                if options:
                    all_selections = []
                    
                    for text in answer_texts:
                        if text:
                            selections = [choice.strip() for choice in text.split(',')]
                            all_selections.extend(selections)
                    
                    value_counts = Counter(all_selections)
                    total_selections = len(all_selections)
                    respondents = len(answer_texts)
                    
                    option_results = []
                    for option in options:
                        count = value_counts.get(option, 0)
                        pct = count / respondents if respondents > 0 else 0
                        
                        option_results.append({
                            'label': option,
                            'value': option,
                            'count': count,
                            'pct': round(pct, 3),
                            'selected_by_respondents': count
                        })
                    
                    # Find most popular
                    most_popular = None
                    if option_results:
                        top_option = max(option_results, key=lambda x: x['count'])
                        most_popular = {
                            'label': top_option['label'],
                            'count': top_option['count'],
                            'pct': top_option['pct']
                        }
                    
                    distributions['multiple_choice'] = {
                        'options': sorted(option_results, key=lambda x: x['count'], reverse=True),
                        'total_selections': total_selections,
                        'avg_selections_per_respondent': round(total_selections / respondents, 2) if respondents > 0 else 0,
                    'most_popular': most_popular
                }
        
        elif question.question_type == 'yes_no':
            # Yes/No analytics
            if answer_values:
                from collections import Counter
                value_counts = Counter(answer_values)
                total = len(answer_values)
                
                yes_no_data = []
                for value in ['yes', 'no']:
                    count = value_counts.get(value, 0)
                    pct = count / total if total > 0 else 0
                    
                    yes_no_data.append({
                        'value': value,
                        'label': value.title(),
                        'count': count,
                        'pct': round(pct, 3)
                    })
                
                distributions['yes_no'] = yes_no_data
        
        elif question.question_type == 'rating':
            # Rating analytics with statistics
            numeric_values = []
            for answer in question_answers:
                if answer.answer_text:
                    try:
                        numeric_values.append(float(answer.answer_text))
                    except (ValueError, TypeError):
                        pass
            
            if numeric_values:
                from statistics import mean, median
                avg_rating = mean(numeric_values)
                median_rating = median(numeric_values)
                
                # Create histogram
                from collections import defaultdict
                histogram = defaultdict(int)
                for value in numeric_values:
                    bucket = str(int(value))  # Round to nearest integer for buckets
                    histogram[bucket] += 1
                
                histogram_list = []
                for bucket in sorted(histogram.keys(), key=lambda x: int(x)):
                    total = len(numeric_values)
                    count = histogram[bucket]
                    pct = count / total if total > 0 else 0
                    
                    histogram_list.append({
                        'rating': int(bucket),
                        'count': count,
                        'pct': round(pct, 3)
                    })
                
                distributions['rating'] = {
                    'avg': round(avg_rating, 2),
                    'median': median_rating,
                    'mode': max(histogram.keys(), key=lambda x: histogram[x]) if histogram else None,
                    'min': min(numeric_values),
                    'max': max(numeric_values),
                    'histogram': histogram_list
                }
        
        elif question.question_type in ['text', 'textarea']:
            # Text analysis
            if answer_texts:
                word_counts = []
                char_counts = []
                
                for text in answer_texts:
                    if text and text.strip():
                        word_count = len(text.split())
                        char_count = len(text)
                        word_counts.append(word_count)
                        char_counts.append(char_count)
                
                if word_counts and char_counts:
                    from statistics import mean
                    # Categorize by length
                    short_count = sum(1 for c in char_counts if c < 50)
                    medium_count = sum(1 for c in char_counts if 50 <= c <= 200)
                    long_count = sum(1 for c in char_counts if c > 200)
                    total = len(char_counts)
                    
                    distributions['textual'] = {
                        'total_responses': total,
                        'avg_word_count': round(mean(word_counts), 1),
                        'avg_char_count': round(mean(char_counts), 1),
                        'response_lengths': {
                            'short': {
                                'count': short_count, 
                                'pct': round(short_count / total, 3) if total > 0 else 0,
                                'description': '< 50 characters'
                            },
                            'medium': {
                                'count': medium_count,
                                'pct': round(medium_count / total, 3) if total > 0 else 0,
                                'description': '50-200 characters'
                            },
                            'long': {
                                'count': long_count,
                                'pct': round(long_count / total, 3) if total > 0 else 0,
                                'description': '> 200 characters'
                            }
                        }
                    }
                else:
                    distributions['textual'] = {
                        'total_responses': 0,
                        'avg_word_count': 0,
                        'avg_char_count': 0,
                        'response_lengths': {
                            'short': {'count': 0, 'pct': 0, 'description': '< 50 characters'},
                            'medium': {'count': 0, 'pct': 0, 'description': '50-200 characters'},
                            'long': {'count': 0, 'pct': 0, 'description': '> 200 characters'}
                        }
                    }
        
        return distributions


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
        start_date = safe_get_query_params(self.request, 'start_date')
        end_date = safe_get_query_params(self.request, 'end_date')
        
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
            export_format = safe_get_query_params(request, 'export')
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
    pagination_class = ResponsePagination
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
        
        # Validate survey ID
        if not survey_id or survey_id == 'undefined' or survey_id == 'null':
            return SurveyResponse.objects.none()
            
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
            
            # Check if pagination parameters are provided
            page_param = request.query_params.get('page')
            per_page_param = request.query_params.get('per_page')
            
            # Only paginate if pagination parameters are provided
            page = None
            if page_param is not None or per_page_param is not None:
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
                'creator_email': survey.creator.email if survey.creator else 'هذا الشخص لم يعد متاح',
                'total_questions': survey.questions.count(),
                'total_responses': survey.responses.count()
            }
            
            if page is not None:
                # Return paginated response with survey context
                paginated_response = self.get_paginated_response(response_data)
                paginated_response.data['data']['survey'] = survey_context
                return paginated_response
            
            # Return all data without pagination
            return uniform_response(
                success=True,
                message="Survey responses retrieved successfully",
                data={
                    'survey': survey_context,
                    'results': response_data,
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
            
            # Check if survey is submitted (not draft) - draft surveys should not be publicly accessible
            if access_token.survey.status != 'submitted':
                return None, "This survey is not yet available for public access"
            
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
                'per_device_access': survey.per_device_access,
                'estimated_time': max(survey.questions.count() * 1, 5),
                'questions_count': survey.questions.count(),
                'visibility': survey.visibility,
                'is_active': survey.is_active,
                'created_at': survey.created_at.isoformat(),
                'creator_email': survey.creator.email if survey.creator else 'Deleted User',
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
        """Validate token and survey access using UAE timezone"""
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
            
            # Check if survey is submitted (not draft) - draft surveys should not be publicly accessible
            if survey.status != 'submitted':
                return None, None, "This survey is not yet available for public access"
            
            if not is_currently_active_uae(survey):
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
                'per_device_access': survey.per_device_access,
                'estimated_time': max(survey.questions.count() * 1, 5),
                'questions_count': survey.questions.count(),
                'created_at': survey.created_at.isoformat(),
                'updated_at': survey.updated_at.isoformat(),
                'creator_email': survey.creator.email if survey.creator else 'Deleted User',
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
            
            # Check if survey is submitted (not draft) - draft surveys should not be publicly accessible
            if survey.status != 'submitted':
                return uniform_response(
                    success=False,
                    message="This survey is not yet available for public access. Please contact the survey creator.",
                    data={
                        'has_access': False,
                        'survey_status': 'draft',
                        'reason': 'survey_not_submitted'
                    },
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
            if not is_currently_active_uae(survey):
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
                'token_expires_at': serialize_datetime_uae(access_token.expires_at),
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
            
            # Check if survey is submitted (not draft) - draft surveys should not be publicly accessible
            if survey.status != 'submitted':
                return None, None, "This survey is not yet available for public access"
            
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
                'per_device_access': survey.per_device_access,
                'estimated_time': max(survey.questions.count() * 1, 5),
                'questions_count': survey.questions.count(),
                'created_at': survey.created_at.isoformat(),
                'updated_at': survey.updated_at.isoformat(),
                'creator_email': survey.creator.email if survey.creator else 'Deleted User',
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
        Validate password-protected access to survey using UAE timezone
        Returns tuple: (has_access, user_or_contact, error_message)
        """
        # Check if survey is currently active based on dates using UAE timezone
        if not is_currently_active_uae(survey):
            status_message = f"Survey is {get_status_uae(survey)}"
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


class SurveyDraftView(APIView):
    """
    Create and manage survey drafts.
    POST /api/surveys/draft/ - Create a new survey draft
    """
    
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Create a new survey draft"""
        try:
            # Pass request context to serializer so it can access the user
            serializer = SurveySerializer(data=request.data, context={'request': request})
            serializer.is_valid(raise_exception=True)
            
            # Create survey as draft - the serializer will handle setting the creator
            survey = serializer.save(status='draft')
            
            return uniform_response(
                success=True,
                message="Survey draft created successfully",
                data=serializer.data,
                status_code=status.HTTP_201_CREATED
            )
            
        except Exception as e:
            logger.error(f"Error creating survey draft: {e}")
            return uniform_response(
                success=False,
                message=str(e),
                status_code=status.HTTP_400_BAD_REQUEST
            )


class SurveySubmitView(APIView):
    """
    Submit survey to make it final and non-editable.
    POST /api/surveys/submit/ - Submit a draft survey
    """
    
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Submit a survey (make it final)"""
        try:
            survey_id = request.data.get('survey_id')
            if not survey_id:
                return uniform_response(
                    success=False,
                    message="Survey ID is required",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                survey = Survey.objects.get(id=survey_id, deleted_at__isnull=True)
            except Survey.DoesNotExist:
                return uniform_response(
                    success=False,
                    message="Survey not found",
                    status_code=status.HTTP_404_NOT_FOUND
                )
            
            # Check permissions
            user = request.user
            if not can_user_manage_survey(user, survey):
                return uniform_response(
                    success=False,
                    message="You can only submit surveys you created" + (" (orphaned surveys can only be managed by super admin)" if survey.creator is None else ""),
                    status_code=status.HTTP_403_FORBIDDEN
                )
            
            # Check if survey is already submitted
            if survey.status == 'submitted':
                return uniform_response(
                    success=False,
                    message="Survey is already submitted",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            # Submit the survey
            survey.submit()
            
            # Send notifications to eligible users about the new survey
            # Check if notifications should be sent (default: False to prevent spam)
            send_notifications = request.data.get('send_notifications', False)
            
            if send_notifications:
                try:
                    # Use force_send=True when explicitly requested to send notifications
                    force_send = survey.visibility in ['PUBLIC', 'AUTH']
                    SurveyNotificationService.notify_users_of_new_survey(survey, request, force_send=force_send)
                    logger.info(f"Sent survey availability notifications for survey {survey.id}")
                except Exception as e:
                    logger.error(f"Failed to send survey availability notifications for survey {survey.id}: {e}")
            else:
                logger.info(f"Skipped sending survey availability notifications for survey {survey.id} as send_notifications was not requested")
            
            # Serialize the updated survey with proper context
            serializer = SurveySerializer(survey, context={'request': request})
            
            return uniform_response(
                success=True,
                message="Survey submitted successfully. It is now final and cannot be edited.",
                data=serializer.data,
                status_code=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Error submitting survey: {e}")
            return uniform_response(
                success=False,
                message="An error occurred while submitting the survey",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
