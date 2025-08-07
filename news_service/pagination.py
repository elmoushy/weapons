"""
Custom pagination for the news service
"""
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from django.conf import settings


class NewsPageNumberPagination(PageNumberPagination):
    """
    Custom pagination for news service with uniform response format
    """
    page_size = getattr(settings, 'NEWS_PAGINATION_SIZE', 12)
    page_size_query_param = 'page_size'
    max_page_size = 50
    
    def get_paginated_response(self, data):
        """
        Return a paginated response with uniform format
        """
        return Response({
            'status': 'success',
            'message': 'Data retrieved successfully',
            'data': {
                'results': data,
                'pagination': {
                    'count': self.page.paginator.count,
                    'page': self.page.number,
                    'pages': self.page.paginator.num_pages,
                    'page_size': self.page_size,
                    'next': self.get_next_link(),
                    'previous': self.get_previous_link(),
                    'has_next': self.page.has_next(),
                    'has_previous': self.page.has_previous()
                }
            }
        })
