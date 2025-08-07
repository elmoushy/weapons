"""
Custom User models for Azure AD authentication.

This module defines a minimal User model that only includes the fields
needed for Azure AD authentication, removing Django's default group
and permission system.
"""

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models
from django.utils import timezone


class CustomUserManager(BaseUserManager):
    """
    Custom manager for the User model.
    
    This manager handles user creation without relying on Django's
    built-in group and permission system.
    """
    
    def create_user(self, username, email=None, password=None, auth_type='regular', **extra_fields):
        """
        Create and return a regular user.
        
        Args:
            username: The username (email for regular users, Azure AD Object ID for Azure users)
            email: User's email address
            password: User's password (only for regular users)
            auth_type: 'regular' for email/password, 'azure' for Azure AD
            **extra_fields: Additional fields
            
        Returns:
            User instance
        """
        if not username:
            raise ValueError('The Username field must be set')
        
        email = self.normalize_email(email) if email else ''
        
        # For regular users, username should be the email
        if auth_type == 'regular' and not email:
            if '@' in username:
                email = username
            else:
                raise ValueError('Email must be provided for regular users')
        
        user = self.model(
            username=username,
            email=email,
            auth_type=auth_type,
            **extra_fields
        )
        
        if auth_type == 'regular' and password:
            user.set_password(password)
        else:
            user.set_unusable_password()  # For Azure AD users
            
        user.save(using=self._db)
        return user
    
    def create_superuser(self, username, email=None, password=None, **extra_fields):
        """
        Create and return a superuser.
        
        Args:
            username: The username (typically Azure AD Object ID for Azure users)
            email: User's email address
            password: User's password (only for regular users)
            **extra_fields: Additional fields
            
        Returns:
            User instance with admin privileges
        """
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('role', 'super_admin')
        extra_fields.setdefault('auth_type', 'regular')  # Default to regular for superuser creation
        
        return self.create_user(username, email, password, **extra_fields)


class User(AbstractBaseUser):
    """
    Custom User model for Azure AD authentication.
    
    This model includes only the essential fields needed for the application:
    - id: Primary key
    - password: Set as unusable for Azure AD users
    - role: User role (default: 'employee')
    - username: Azure AD Object ID or username claim
    - email: User's email address
    - is_active: Whether the user account is active
    - date_joined: When the user was first created
    """
    
    ROLE_CHOICES = [
        ('user', 'User'),
        ('admin', 'Administrator'),
        ('super_admin', 'Super Administrator'),
    ]
    
    AUTH_TYPE_CHOICES = [
        ('regular', 'Regular Email/Password'),
        ('azure', 'Azure AD SSO'),
    ]
    
    # Core required fields
    username = models.CharField(
        max_length=255,
        unique=True,
        help_text='Azure AD Object ID for Azure users, email for regular users'
    )
    email = models.EmailField(
        max_length=254,
        unique=True,
        help_text='User email address'
    )
    auth_type = models.CharField(
        max_length=20,
        choices=AUTH_TYPE_CHOICES,
        default='regular',
        help_text='Authentication type used for this user'
    )
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default='user',
        help_text='User role in the system'
    )
    is_active = models.BooleanField(
        default=True,
        help_text='Whether this user account is active'
    )
    date_joined = models.DateTimeField(
        default=timezone.now,
        help_text='When the user account was created'
    )
    
    # Optional fields for better user experience
    first_name = models.CharField(
        max_length=150,
        blank=True,
        help_text='User first name from Azure AD'
    )
    last_name = models.CharField(
        max_length=150,
        blank=True,
        help_text='User last name from Azure AD'
    )
    last_login = models.DateTimeField(
        blank=True,
        null=True,
        help_text='Last time user logged in'
    )
    
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']
    
    class Meta:
        db_table = 'auth_user'  # Use Django's default table name
        verbose_name = 'User'
        verbose_name_plural = 'Users'
    
    def __str__(self):
        return f"{self.email or self.username} ({self.role})"
    
    @property
    def full_name(self):
        """Return the user's full name."""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.email or self.username
    
    @property
    def is_staff(self):
        """Return True if user is admin or super_admin (for Django admin access)."""
        return self.role in ['admin', 'super_admin']
    
    @property
    def is_superuser(self):
        """Return True if user is super_admin (for Django admin access)."""
        return self.role == 'super_admin'
    
    def has_perm(self, perm, obj=None):
        """
        Check if user has a specific permission.
        
        Since we're not using Django's permission system,
        this is based on user role.
        """
        if self.role == 'super_admin':
            return True
        elif self.role == 'admin':
            # Admins have permissions within their groups
            return True
        # Add custom permission logic based on roles if needed
        return False
    
    def has_module_perms(self, app_label):
        """
        Check if user has permissions to view the app.
        
        Super admins and admins have access to modules.
        """
        return self.role in ['admin', 'super_admin']


class Group(models.Model):
    """
    Group model for organizing users.
    
    Each group can contain multiple users and must have at least one admin.
    """
    
    name = models.CharField(
        max_length=255,
        unique=True,
        help_text='Unique name of the group'
    )
    description = models.TextField(
        blank=True,
        help_text='Optional description of the group'
    )
    created_at = models.DateTimeField(
        default=timezone.now,
        help_text='When the group was created'
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text='When the group was last updated'
    )
    
    class Meta:
        verbose_name = 'Group'
        verbose_name_plural = 'Groups'
        ordering = ['name']
    
    def __str__(self):
        return self.name
    
    @property
    def admin_count(self):
        """Return the number of admins in this group."""
        return self.user_groups.filter(is_group_admin=True).count()
    
    @property
    def user_count(self):
        """Return the total number of users in this group."""
        return self.user_groups.count()
    
    def get_admins(self):
        """Return all admin users in this group."""
        return User.objects.filter(
            user_groups__group=self,
            user_groups__is_group_admin=True
        )
    
    def get_members(self):
        """Return all users in this group."""
        return User.objects.filter(user_groups__group=self)


class UserGroup(models.Model):
    """
    Through model for User-Group many-to-many relationship.
    
    This model tracks which users belong to which groups and
    whether they are administrators of that group.
    """
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='user_groups',
        help_text='User in the group'
    )
    group = models.ForeignKey(
        Group,
        on_delete=models.CASCADE,
        related_name='user_groups',
        help_text='Group the user belongs to'
    )
    is_group_admin = models.BooleanField(
        default=False,
        help_text='Whether the user is an admin of this group'
    )
    joined_at = models.DateTimeField(
        default=timezone.now,
        help_text='When the user joined the group'
    )
    
    class Meta:
        unique_together = ['user', 'group']
        verbose_name = 'User Group Membership'
        verbose_name_plural = 'User Group Memberships'
        ordering = ['group__name', 'user__email']
    
    def __str__(self):
        admin_status = " (Admin)" if self.is_group_admin else ""
        return f"{self.user.email} - {self.group.name}{admin_status}"
    
    def save(self, *args, **kwargs):
        """
        Override save to handle role assignment logic.
        """
        # If user is not super_admin and being added to a group, make them admin
        if self.user.role != 'super_admin' and self.user.role != 'admin':
            self.user.role = 'admin'
            self.user.save()
        
        super().save(*args, **kwargs)
    
    def delete(self, *args, **kwargs):
        """
        Override delete to handle role downgrade logic.
        """
        user = self.user
        super().delete(*args, **kwargs)
        
        # Check if user is still in any groups
        if user.role != 'super_admin' and not user.user_groups.exists():
            user.role = 'user'
            user.save()


# Add groups property to User model
User.add_to_class('groups', models.ManyToManyField(
    Group,
    through=UserGroup,
    related_name='users',
    blank=True,
    help_text='Groups this user belongs to'
))
