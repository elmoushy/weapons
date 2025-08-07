"""
URL configuration for the news service
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create a router and register our viewsets with it
router = DefaultRouter()
router.register(r'slider-news', views.SliderNewsViewSet, basename='slider-news')
router.register(r'achievements', views.AchievementViewSet, basename='achievements')
router.register(r'cards-news', views.CardsNewsViewSet, basename='cards-news')
router.register(r'images', views.NewsImageViewSet, basename='news-images')

# The API URLs are now determined automatically by the router
urlpatterns = [
    path('', include(router.urls)),
]
