"""
Admin configuration for the news service
"""
from django.contrib import admin
from django.utils.html import format_html
from .models import SliderNews, Achievement, CardsNews, NewsImage


class NewsImageInline(admin.TabularInline):
    """
    Inline admin for news images
    """
    model = NewsImage
    extra = 0
    fields = ['caption', 'alt_text', 'order']
    readonly_fields = ['image_preview']
    
    def image_preview(self, obj):
        """
        Display a small preview of the image
        """
        if obj.image_data:
            # Note: In a real implementation, you'd want to create a view
            # that serves the decrypted image data
            return format_html('<div>Image uploaded</div>')
        return "No image"
    image_preview.short_description = "Preview"


@admin.register(SliderNews)
class SliderNewsAdmin(admin.ModelAdmin):
    """
    Admin configuration for SliderNews
    """
    list_display = [
        'title_english', 'title_arabic', 'priority', 
        'display_duration', 'date', 'is_active', 'created_by'
    ]
    list_filter = ['is_active', 'priority', 'date', 'created_at']
    search_fields = ['title_english', 'title_arabic', 'description']
    ordering = ['-priority', '-date']
    readonly_fields = ['created_at', 'updated_at', 'image_preview']
    inlines = [NewsImageInline]
    
    fieldsets = (
        ('Content', {
            'fields': ('title_arabic', 'title_english', 'description')
        }),
        ('Media', {
            'fields': ('main_image', 'image_preview')
        }),
        ('Settings', {
            'fields': ('priority', 'display_duration', 'date', 'is_active')
        }),
        ('Metadata', {
            'fields': ('created_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def image_preview(self, obj):
        """Display image preview"""
        if obj.main_image:
            return format_html('<div>Main image uploaded</div>')
        return "No main image"
    image_preview.short_description = "Main Image Preview"
    
    def save_model(self, request, obj, form, change):
        """Set created_by when saving"""
        if not change:  # Creating new object
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(Achievement)
class AchievementAdmin(admin.ModelAdmin):
    """
    Admin configuration for Achievement
    """
    list_display = [
        'title_english', 'title_arabic', 'category', 
        'achievement_date', 'date', 'is_active', 'created_by'
    ]
    list_filter = ['is_active', 'category', 'achievement_date', 'date']
    search_fields = ['title_english', 'title_arabic', 'description']
    ordering = ['-achievement_date', '-date']
    readonly_fields = ['created_at', 'updated_at', 'image_preview']
    inlines = [NewsImageInline]
    
    fieldsets = (
        ('Content', {
            'fields': ('title_arabic', 'title_english', 'description')
        }),
        ('Achievement Details', {
            'fields': ('category', 'achievement_date')
        }),
        ('Media', {
            'fields': ('main_image', 'image_preview')
        }),
        ('Settings', {
            'fields': ('date', 'is_active')
        }),
        ('Metadata', {
            'fields': ('created_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def image_preview(self, obj):
        """Display image preview"""
        if obj.main_image:
            return format_html('<div>Main image uploaded</div>')
        return "No main image"
    image_preview.short_description = "Main Image Preview"
    
    def save_model(self, request, obj, form, change):
        """Set created_by when saving"""
        if not change:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(CardsNews)
class CardsNewsAdmin(admin.ModelAdmin):
    """
    Admin configuration for CardsNews
    """
    list_display = [
        'title_english', 'title_arabic', 'category', 
        'is_featured', 'view_count', 'date', 'is_active', 'created_by'
    ]
    list_filter = ['is_active', 'category', 'is_featured', 'date']
    search_fields = ['title_english', 'title_arabic', 'description']
    ordering = ['-is_featured', '-date']
    readonly_fields = ['created_at', 'updated_at', 'view_count', 'image_preview']
    inlines = [NewsImageInline]
    
    fieldsets = (
        ('Content', {
            'fields': ('title_arabic', 'title_english', 'description')
        }),
        ('Classification', {
            'fields': ('category', 'is_featured')
        }),
        ('Media', {
            'fields': ('main_image', 'image_preview')
        }),
        ('Settings', {
            'fields': ('date', 'is_active')
        }),
        ('Statistics', {
            'fields': ('view_count',),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('created_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def image_preview(self, obj):
        """Display image preview"""
        if obj.main_image:
            return format_html('<div>Main image uploaded</div>')
        return "No main image"
    image_preview.short_description = "Main Image Preview"
    
    def save_model(self, request, obj, form, change):
        """Set created_by when saving"""
        if not change:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(NewsImage)
class NewsImageAdmin(admin.ModelAdmin):
    """
    Admin configuration for NewsImage
    """
    list_display = ['id', 'get_parent', 'caption', 'order', 'created_at']
    list_filter = ['created_at']
    search_fields = ['caption', 'alt_text']
    ordering = ['order', 'created_at']
    readonly_fields = ['created_at', 'image_preview']
    
    fieldsets = (
        ('Image', {
            'fields': ('image_data', 'image_preview')
        }),
        ('Metadata', {
            'fields': ('caption', 'alt_text', 'order')
        }),
        ('Associations', {
            'fields': ('slider_news', 'achievement', 'cards_news')
        }),
        ('Timestamps', {
            'fields': ('created_at',),
            'classes': ('collapse',)
        })
    )
    
    def get_parent(self, obj):
        """Get the parent news item"""
        if obj.slider_news:
            return f"Slider: {obj.slider_news.title_english}"
        elif obj.achievement:
            return f"Achievement: {obj.achievement.title_english}"
        elif obj.cards_news:
            return f"Card: {obj.cards_news.title_english}"
        return "No parent"
    get_parent.short_description = "Parent News Item"
    
    def image_preview(self, obj):
        """Display image preview"""
        if obj.image_data:
            return format_html('<div>Image uploaded</div>')
        return "No image"
    image_preview.short_description = "Image Preview"
