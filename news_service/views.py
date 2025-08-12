"""
Views for the news service API
"""
from rest_framework import viewsets, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Q
from django.utils import timezone
from .models import SliderNews, Achievement, CardsNews, NewsImage
from .serializers import (
    SliderNewsSerializer, SliderNewsPublicSerializer,
    AchievementSerializer, AchievementPublicSerializer,
    CardsNewsSerializer, CardsNewsPublicSerializer,
    NewsImageUploadSerializer, BulkNewsImageSerializer, MainImageUploadSerializer
)
from .permissions import IsAdminOrReadOnly, PublicReadOnlyPermission
from .pagination import NewsPageNumberPagination
import logging

logger = logging.getLogger(__name__)


class BaseNewsViewSet(viewsets.ModelViewSet):
    """
    Base viewset for all news models
    """
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['title_arabic', 'title_english', 'description']
    ordering_fields = ['date', 'created_at', 'updated_at']
    ordering = ['-date', '-created_at']
    
    def get_serializer_class(self):
        """
        Return appropriate serializer based on user permissions
        """
        # Check if user is admin
        if self.request.user.is_authenticated:
            user_role = getattr(self.request.user, 'role', None)
            is_admin = user_role == 'admin' or self.request.user.is_staff or self.request.user.is_superuser
            
            if is_admin:
                return self.admin_serializer_class
        
        # Return public serializer for non-admin users
        return self.public_serializer_class
    
    def get_queryset(self):
        """
        Return filtered queryset
        """
        queryset = self.queryset.filter(is_active=True)
        
        # Add any additional filtering here
        return queryset
    
    def create(self, request, *args, **kwargs):
        """
        Create a new news item with uniform response format
        """
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            
            return Response({
                'status': 'success',
                'message': f'{self.model_name} created successfully',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Error creating {self.model_name}: {e}")
            return Response({
                'status': 'error',
                'message': f'Failed to create {self.model_name}',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def update(self, request, *args, **kwargs):
        """
        Update a news item with uniform response format
        """
        try:
            partial = kwargs.pop('partial', False)
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)
            
            return Response({
                'status': 'success',
                'message': f'{self.model_name} updated successfully',
                'data': serializer.data
            })
            
        except Exception as e:
            logger.error(f"Error updating {self.model_name}: {e}")
            return Response({
                'status': 'error',
                'message': f'Failed to update {self.model_name}',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def destroy(self, request, *args, **kwargs):
        """
        Delete a news item with uniform response format
        """
        try:
            instance = self.get_object()
            self.perform_destroy(instance)
            
            return Response({
                'status': 'success',
                'message': f'{self.model_name} deleted successfully',
                'data': None
            }, status=status.HTTP_204_NO_CONTENT)
            
        except Exception as e:
            logger.error(f"Error deleting {self.model_name}: {e}")
            return Response({
                'status': 'error',
                'message': f'Failed to delete {self.model_name}',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def list(self, request, *args, **kwargs):
        """
        List news items with uniform response format
        """
        try:
            queryset = self.filter_queryset(self.get_queryset())
            
            # Check if pagination is needed
            if hasattr(self, 'paginate_queryset') and self.paginate_queryset is not None:
                page = self.paginate_queryset(queryset)
                if page is not None:
                    serializer = self.get_serializer(page, many=True)
                    return self.get_paginated_response({
                        'status': 'success',
                        'message': f'{self.model_name} list retrieved successfully',
                        'data': serializer.data
                    })
            
            serializer = self.get_serializer(queryset, many=True)
            return Response({
                'status': 'success',
                'message': f'{self.model_name} list retrieved successfully',
                'data': serializer.data
            })
            
        except Exception as e:
            logger.error(f"Error listing {self.model_name}: {e}")
            return Response({
                'status': 'error',
                'message': f'Failed to retrieve {self.model_name} list',
                'data': None
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def retrieve(self, request, *args, **kwargs):
        """
        Retrieve a specific news item with uniform response format
        """
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance)
            
            return Response({
                'status': 'success',
                'message': f'{self.model_name} retrieved successfully',
                'data': serializer.data
            })
            
        except Exception as e:
            logger.error(f"Error retrieving {self.model_name}: {e}")
            return Response({
                'status': 'error',
                'message': f'Failed to retrieve {self.model_name}',
                'data': None
            }, status=status.HTTP_404_NOT_FOUND)
    
    @action(detail=True, methods=['post'], permission_classes=[IsAdminOrReadOnly])
    def upload_images(self, request, pk=None):
        """
        Upload multiple images to a news item
        """
        try:
            news_item = self.get_object()
            serializer = NewsImageUploadSerializer(data=request.data)
            
            if serializer.is_valid():
                images_data = serializer.validated_data['images']
                created_images = []
                
                for image_data in images_data:
                    # Create NewsImage instance
                    image_serializer = BulkNewsImageSerializer(
                        data=image_data,
                        context={
                            'parent_model': self.model_name.lower().replace(' ', '_'),
                            'parent_id': news_item.id
                        }
                    )
                    
                    if image_serializer.is_valid():
                        image_instance = image_serializer.save()
                        created_images.append(image_serializer.data)
                    else:
                        logger.error(f"Image validation failed: {image_serializer.errors}")
                
                return Response({
                    'status': 'success',
                    'message': f'{len(created_images)} images uploaded successfully',
                    'data': created_images
                })
            else:
                return Response({
                    'status': 'error',
                    'message': 'Invalid image data',
                    'data': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.error(f"Error uploading images: {e}")
            return Response({
                'status': 'error',
                'message': 'Failed to upload images',
                'data': None
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['post'], permission_classes=[IsAdminOrReadOnly])
    def update_main_image(self, request, pk=None):
        """
        Update the main image of a news item (separate from PUT/PATCH to ensure proper file handling)
        """
        try:
            news_item = self.get_object()
            serializer = MainImageUploadSerializer(data=request.data)
            
            if serializer.is_valid():
                main_image_data = serializer.validated_data['main_image']
                
                # Update the main image
                news_item.main_image = main_image_data
                news_item.save(update_fields=['main_image'])
                
                # Return the updated news item
                response_serializer = self.get_serializer(news_item)
                
                return Response({
                    'status': 'success',
                    'message': f'{self.model_name} main image updated successfully',
                    'data': response_serializer.data
                })
            else:
                return Response({
                    'status': 'error',
                    'message': 'Invalid main image data',
                    'data': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.error(f"Error updating main image: {e}")
            return Response({
                'status': 'error',
                'message': 'Failed to update main image',
                'data': None
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SliderNewsViewSet(BaseNewsViewSet):
    """
    ViewSet for slider news (no pagination)
    """
    queryset = SliderNews.objects.all()
    admin_serializer_class = SliderNewsSerializer
    public_serializer_class = SliderNewsPublicSerializer
    permission_classes = [PublicReadOnlyPermission | IsAdminOrReadOnly]
    model_name = 'Slider News'
    filterset_fields = ['priority', 'is_active']
    search_fields = ['title_arabic', 'title_english', 'description']
    ordering = ['-priority', '-date']
    
    # No pagination for slider news


class AchievementViewSet(BaseNewsViewSet):
    """
    ViewSet for achievements (no pagination)
    """
    queryset = Achievement.objects.all()
    admin_serializer_class = AchievementSerializer
    public_serializer_class = AchievementPublicSerializer
    permission_classes = [PublicReadOnlyPermission | IsAdminOrReadOnly]
    model_name = 'Achievement'
    filterset_fields = ['category', 'is_active']
    search_fields = ['title_arabic', 'title_english', 'description']
    ordering = ['-achievement_date', '-date']
    
    # No pagination for achievements


class CardsNewsViewSet(BaseNewsViewSet):
    """
    ViewSet for cards news (with pagination)
    """
    queryset = CardsNews.objects.all()
    admin_serializer_class = CardsNewsSerializer
    public_serializer_class = CardsNewsPublicSerializer
    permission_classes = [PublicReadOnlyPermission | IsAdminOrReadOnly]
    model_name = 'Cards News'
    filterset_fields = ['category', 'is_featured', 'is_active']
    search_fields = ['title_arabic', 'title_english', 'description']
    ordering = ['-is_featured', '-date']
    pagination_class = NewsPageNumberPagination
    
    def get_queryset(self):
        """
        Override to add view count increment for detail view
        """
        queryset = super().get_queryset()
        
        # Increment view count for detail view
        if self.action == 'retrieve' and self.kwargs.get('pk'):
            try:
                pk = self.kwargs['pk']
                news_item = queryset.get(pk=pk)
                news_item.increment_view_count()
            except CardsNews.DoesNotExist:
                pass
            except Exception as e:
                logger.error(f"Error incrementing view count: {e}")
        
        return queryset


class NewsImageViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing news images
    """
    queryset = NewsImage.objects.all()
    serializer_class = BulkNewsImageSerializer
    permission_classes = [IsAdminOrReadOnly]
    
    def create(self, request, *args, **kwargs):
        """
        Create a news image with uniform response format
        """
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            
            return Response({
                'status': 'success',
                'message': 'Image created successfully',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Error creating image: {e}")
            return Response({
                'status': 'error',
                'message': 'Failed to create image',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def destroy(self, request, *args, **kwargs):
        """
        Delete a news image with uniform response format
        """
        try:
            instance = self.get_object()
            self.perform_destroy(instance)
            
            return Response({
                'status': 'success',
                'message': 'Image deleted successfully',
                'data': None
            }, status=status.HTTP_204_NO_CONTENT)
            
        except Exception as e:
            logger.error(f"Error deleting image: {e}")
            return Response({
                'status': 'error',
                'message': 'Failed to delete image',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)
