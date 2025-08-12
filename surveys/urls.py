"""
URL patterns for surveys API endpoints.

This module defines the URL routing following the same patterns
as news_service and Files_Endpoints.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'surveys'

# Router for ViewSets
router = DefaultRouter()
router.register('surveys', views.SurveyViewSet, basename='survey')

urlpatterns = [
    # ViewSet routes
    path('', include(router.urls)),
    
    # My shared surveys endpoint
    path('my-shared/', 
         views.MySharedSurveysView.as_view(), 
         name='my-shared-surveys'),
    
    # New survey response submission endpoint
    path('responses/', 
         views.SurveyResponseSubmissionView.as_view(), 
         name='survey-response-submission'),
    
    # Authenticated survey response submission (no email required)
    path('auth-responses/', 
         views.AuthenticatedSurveyResponseView.as_view(), 
         name='authenticated-survey-response'),
    
    # Survey submission endpoint (legacy)
    path('surveys/<uuid:survey_id>/submit/', 
         views.SurveySubmissionView.as_view(), 
         name='survey-submit'),
    
    # Response management
    path('surveys/<uuid:survey_id>/responses/', 
         views.SurveyResponsesView.as_view(), 
         name='survey-responses'),
    
    # Admin APIs - Survey Response Management
    path('admin/responses/', 
         views.AdminResponsesView.as_view(), 
         name='admin-all-responses'),
    
    path('admin/surveys/<uuid:survey_id>/responses/', 
         views.AdminSurveyResponsesView.as_view(), 
         name='admin-survey-responses'),
    
    # Token-Based Access APIs
    path('token/surveys/', 
         views.TokenSurveysView.as_view(), 
         name='token-surveys'),
    
    path('token/surveys/<uuid:survey_id>/', 
         views.TokenSurveyDetailView.as_view(), 
         name='token-survey-detail'),
    
    # Password-Protected Survey Access APIs
    path('password-access/<str:token>/', 
         views.PasswordAccessValidationView.as_view(), 
         name='password-access-validation'),
    
    path('password-surveys/<uuid:survey_id>/', 
         views.PasswordProtectedSurveyView.as_view(), 
         name='password-survey-detail'),
    
    path('password-responses/', 
         views.PasswordProtectedSurveyResponseView.as_view(), 
         name='password-survey-response'),
    
    # Bulk operations
    path('bulk-operations/', views.bulk_operations, name='bulk-operations'),
    
    # User search for sharing
    path('users/search/', views.UserSearchView.as_view(), name='user-search'),
    
    # Get admin groups for sharing
    path('my-admin-groups/', views.MyAdminGroupsView.as_view(), name='my-admin-groups'),
    
    # Health check
    path('health/', views.health_check, name='health-check'),
]
