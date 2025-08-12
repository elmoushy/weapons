"""
Tests for surveys app.

This module contains unit tests for models, views, permissions,
and serializers following Django testing best practices.
"""

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from .models import Survey, Question, Response, Answer
from .encryption import surveys_data_encryption
import json

User = get_user_model()


class SurveyModelTest(TestCase):
    """Test cases for Survey model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
    
    def test_survey_creation(self):
        """Test creating a survey"""
        survey = Survey.objects.create(
            title='Test Survey',
            description='Test Description',
            creator=self.user,
            visibility='PRIVATE'
        )
        
        self.assertEqual(survey.title, 'Test Survey')
        self.assertEqual(survey.creator, self.user)
        self.assertEqual(survey.visibility, 'PRIVATE')
        self.assertIsNotNone(survey.title_hash)
    
    def test_encryption(self):
        """Test field encryption"""
        survey = Survey.objects.create(
            title='Encrypted Title',
            description='Encrypted Description',
            creator=self.user
        )
        
        # Retrieve from database to test decryption
        saved_survey = Survey.objects.get(id=survey.id)
        self.assertEqual(saved_survey.title, 'Encrypted Title')
        self.assertEqual(saved_survey.description, 'Encrypted Description')


class SurveyAPITest(APITestCase):
    """Test cases for Survey API endpoints"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            role='employee'
        )
        self.admin_user = User.objects.create_user(
            email='admin@example.com',
            password='adminpass123',
            role='admin'
        )
        
    def test_create_survey(self):
        """Test creating survey via API"""
        self.client.force_authenticate(user=self.user)
        
        data = {
            'title': 'API Test Survey',
            'description': 'Test survey created via API',
            'visibility': 'PRIVATE'
        }
        
        response = self.client.post('/api/surveys/surveys/', data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['status'], 'success')
    
    def test_list_surveys(self):
        """Test listing surveys"""
        Survey.objects.create(
            title='Public Survey',
            creator=self.user,
            visibility='PUBLIC'
        )
        
        response = self.client.get('/api/surveys/surveys/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_survey_permissions(self):
        """Test survey visibility permissions"""
        private_survey = Survey.objects.create(
            title='Private Survey',
            creator=self.admin_user,
            visibility='PRIVATE'
        )
        
        # User should not see private survey they don't own
        self.client.force_authenticate(user=self.user)
        response = self.client.get(f'/api/surveys/surveys/{private_survey.id}/')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        # Admin should see their own survey
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(f'/api/surveys/surveys/{private_survey.id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class SurveySubmissionTest(APITestCase):
    """Test cases for survey response submission"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        
        self.survey = Survey.objects.create(
            title='Test Survey',
            creator=self.user,
            visibility='PUBLIC',
            is_active=True
        )
        
        self.question = Question.objects.create(
            survey=self.survey,
            text='What is your name?',
            question_type='text',
            order=1
        )
    
    def test_submit_response(self):
        """Test submitting survey response"""
        data = {
            'answers': [
                {
                    'question_id': str(self.question.id),
                    'answer_text': 'John Doe'
                }
            ]
        }
        
        response = self.client.post(
            f'/api/surveys/surveys/{self.survey.id}/submit/',
            data,
            format='json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['status'], 'success')
        
        # Verify response was created
        survey_response = Response.objects.get(survey=self.survey)
        self.assertEqual(survey_response.answers.count(), 1)
    
    def test_submit_to_inactive_survey(self):
        """Test submitting to inactive survey"""
        self.survey.is_active = False
        self.survey.save()
        
        data = {
            'answers': [
                {
                    'question_id': str(self.question.id),
                    'answer_text': 'Test Answer'
                }
            ]
        }
        
        response = self.client.post(
            f'/api/surveys/surveys/{self.survey.id}/submit/',
            data,
            format='json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


# Add more test cases as needed...
