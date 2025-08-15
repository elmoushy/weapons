"""
Timezone utilities for surveys service.
Ensures all datetime operations maintain Asia/Dubai timezone consistently.
"""

import pytz
from django.utils import timezone
from datetime import datetime


# UAE timezone constant
UAE_TIMEZONE = pytz.timezone('Asia/Dubai')


def ensure_uae_timezone(dt):
    """
    Ensure datetime is in UAE timezone.
    
    Args:
        dt: datetime object (can be naive or timezone-aware)
    
    Returns:
        datetime object in UAE timezone
    """
    if dt is None:
        return None
    
    if timezone.is_naive(dt):
        # If naive, assume it's already in UAE timezone and localize it
        return UAE_TIMEZONE.localize(dt)
    else:
        # If timezone-aware, convert to UAE timezone
        return dt.astimezone(UAE_TIMEZONE)


def format_uae_datetime(dt, format_string='%Y-%m-%d %H:%M'):
    """
    Format datetime in UAE timezone.
    
    Args:
        dt: datetime object
        format_string: strftime format string
    
    Returns:
        Formatted string in UAE timezone
    """
    if dt is None:
        return None
    
    uae_dt = ensure_uae_timezone(dt)
    return uae_dt.strftime(format_string)


def format_uae_date_only(dt, format_string='%Y-%m-%d'):
    """
    Format date only in UAE timezone.
    
    Args:
        dt: datetime object
        format_string: strftime format string
    
    Returns:
        Formatted date string in UAE timezone
    """
    if dt is None:
        return None
    
    uae_dt = ensure_uae_timezone(dt)
    return uae_dt.strftime(format_string)


def now_uae():
    """
    Get current datetime in UAE timezone.
    
    Returns:
        Current datetime in UAE timezone
    """
    return timezone.now().astimezone(UAE_TIMEZONE)


def is_currently_active_uae(survey):
    """
    Check if survey is currently active using UAE timezone for all comparisons.
    
    Args:
        survey: Survey instance
    
    Returns:
        bool: True if survey is currently active
    """
    if not survey.is_active or survey.deleted_at is not None:
        return False
    
    now_uae_time = now_uae()
    
    # Check start date
    if survey.start_date:
        start_uae = ensure_uae_timezone(survey.start_date)
        if now_uae_time < start_uae:
            return False
    
    # Check end date
    if survey.end_date:
        end_uae = ensure_uae_timezone(survey.end_date)
        if now_uae_time > end_uae:
            return False
    
    return True


def get_status_uae(survey):
    """
    Get survey status using UAE timezone for all comparisons.
    
    Args:
        survey: Survey instance
    
    Returns:
        str: Survey status ('active', 'scheduled', 'expired', 'inactive', 'deleted')
    """
    if survey.deleted_at is not None:
        return 'deleted'
    
    if not survey.is_active:
        return 'inactive'
    
    now_uae_time = now_uae()
    
    if survey.start_date:
        start_uae = ensure_uae_timezone(survey.start_date)
        if now_uae_time < start_uae:
            return 'scheduled'
    
    if survey.end_date:
        end_uae = ensure_uae_timezone(survey.end_date)
        if now_uae_time > end_uae:
            return 'expired'
    
    return 'active'


def serialize_datetime_uae(dt):
    """
    Serialize datetime to string in UAE timezone with timezone info.
    
    Args:
        dt: datetime object
    
    Returns:
        ISO formatted string with UAE timezone (+04:00)
    """
    if dt is None:
        return None
    
    uae_dt = ensure_uae_timezone(dt)
    return uae_dt.isoformat()
