"""
Serializers for the authentication API.

This module contains serializers for user-related data that will be
returned by the API endpoints, including both Azure AD and regular authentication.
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import Group, UserGroup


User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for user information.
    
    Returns basic user information that can be safely exposed to the frontend.
    """
    
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id',
            'username',  # This will be the Azure AD Object ID
            'email',
            'first_name',
            'last_name',
            'full_name',
            'role',
            'is_active',
            'date_joined',
            'last_login'
        ]
        read_only_fields = ['id', 'username', 'date_joined', 'last_login']
    
    def get_full_name(self, obj):
        """
        Get the user's full name.
        
        Args:
            obj: User instance
            
        Returns:
            Full name string
        """
        return f"{obj.first_name} {obj.last_name}".strip() or obj.email


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Extended serializer for user profile information.
    
    This serializer includes additional fields that might be useful
    for user profile management.
    """
    
    full_name = serializers.SerializerMethodField()
    initials = serializers.SerializerMethodField()
    azure_object_id = serializers.SerializerMethodField()
    role_display = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id',
            'azure_object_id',
            'email',
            'first_name',
            'last_name',
            'full_name',
            'initials',
            'role',
            'role_display',
            'is_active',
            'is_staff',
            'date_joined',
            'last_login'
        ]
        read_only_fields = [
            'id', 
            'azure_object_id', 
            'is_staff', 
            'date_joined', 
            'last_login'
        ]
    
    def get_full_name(self, obj):
        """Get the user's full name."""
        return f"{obj.first_name} {obj.last_name}".strip() or obj.email
    
    def get_initials(self, obj):
        """Get the user's initials."""
        if obj.first_name and obj.last_name:
            return f"{obj.first_name[0]}{obj.last_name[0]}".upper()
        elif obj.first_name:
            return obj.first_name[0].upper()
        elif obj.email:
            return obj.email[0].upper()
        return "U"
    
    def get_azure_object_id(self, obj):
        """Get the Azure AD Object ID (stored as username)."""
        return obj.username
    
    def get_role_display(self, obj):
        """Get the human-readable role name."""
        return obj.get_role_display()


class UserGroupSerializer(serializers.ModelSerializer):
    """
    Serializer for UserGroup model (through model).
    """
    
    user = UserSerializer(read_only=True)
    group_name = serializers.CharField(source='group.name', read_only=True)
    
    class Meta:
        model = UserGroup
        fields = [
            'id',
            'user',
            'group_name',
            'is_group_admin',
            'joined_at'
        ]
        read_only_fields = ['id', 'joined_at']


class GroupSerializer(serializers.ModelSerializer):
    """
    Serializer for Group model.
    """
    
    admin_count = serializers.ReadOnlyField()
    user_count = serializers.ReadOnlyField()
    admins = UserSerializer(source='get_admins', many=True, read_only=True)
    members = UserSerializer(source='get_members', many=True, read_only=True)
    
    class Meta:
        model = Group
        fields = [
            'id',
            'name',
            'description',
            'admin_count',
            'user_count',
            'admins',
            'members',
            'created_at',
            'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class GroupDetailSerializer(serializers.ModelSerializer):
    """
    Detailed serializer for Group model with user memberships.
    """
    
    user_groups = UserGroupSerializer(many=True, read_only=True)
    admin_count = serializers.ReadOnlyField()
    user_count = serializers.ReadOnlyField()
    
    class Meta:
        model = Group
        fields = [
            'id',
            'name',
            'description',
            'admin_count',
            'user_count',
            'user_groups',
            'created_at',
            'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class CreateGroupSerializer(serializers.ModelSerializer):
    """
    Serializer for creating a new group with admin assignments.
    """
    
    admin_user_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        min_length=1,
        help_text="List of user IDs to be assigned as group admins"
    )
    
    class Meta:
        model = Group
        fields = ['name', 'description', 'admin_user_ids']
    
    def validate_admin_user_ids(self, value):
        """Validate that all admin user IDs exist and are valid."""
        if not value:
            raise serializers.ValidationError("At least one admin must be assigned.")
        
        # Check if all users exist
        existing_users = User.objects.filter(id__in=value).count()
        if existing_users != len(value):
            raise serializers.ValidationError("One or more user IDs do not exist.")
        
        return value
    
    def create(self, validated_data):
        """Create group and assign admins."""
        admin_user_ids = validated_data.pop('admin_user_ids')
        group = Group.objects.create(**validated_data)
        
        # Add admin users to the group
        for user_id in admin_user_ids:
            user = User.objects.get(id=user_id)
            UserGroup.objects.create(
                user=user,
                group=group,
                is_group_admin=True
            )
        
        return group


class AddUserToGroupSerializer(serializers.Serializer):
    """
    Serializer for adding a user to a group.
    """
    
    user_id = serializers.IntegerField()
    is_group_admin = serializers.BooleanField(default=False)
    
    def validate_user_id(self, value):
        """Validate that the user exists."""
        try:
            User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User does not exist.")
        return value


class UpdateUserGroupSerializer(serializers.ModelSerializer):
    """
    Serializer for updating user group membership.
    """
    
    class Meta:
        model = UserGroup
        fields = ['is_group_admin']
    
    def validate(self, data):
        """Validate group admin requirements."""
        if not data.get('is_group_admin', True):
            # If removing admin status, ensure at least one admin remains
            group = self.instance.group
            if group.admin_count == 1 and self.instance.is_group_admin:
                raise serializers.ValidationError(
                    "Cannot remove the last admin from a group."
                )
        return data


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration with email/password.
    """
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'}
    )
    
    class Meta:
        model = User
        fields = [
            'email',
            'password',
            'password_confirm',
            'first_name',
            'last_name'
        ]
    
    def validate_email(self, value):
        """Validate email is unique."""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value
    
    def validate_password(self, value):
        """Validate password meets requirements."""
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value
    
    def validate(self, data):
        """Validate password confirmation."""
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError("Passwords do not match.")
        return data
    
    def create(self, validated_data):
        """Create a new regular user."""
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        email = validated_data['email']
        
        user = User.objects.create_user(
            username=email,  # Use email as username for regular users
            email=email,
            password=password,
            auth_type='regular',
            **validated_data
        )
        return user


class UserLoginSerializer(serializers.Serializer):
    """
    Serializer for user login with email/password.
    """
    email = serializers.EmailField()
    password = serializers.CharField(
        style={'input_type': 'password'}
    )
    
    def validate(self, data):
        """Validate user credentials."""
        email = data.get('email')
        password = data.get('password')
        
        if email and password:
            # Check if user exists and is a regular user
            try:
                user = User.objects.get(email=email, auth_type='regular')
            except User.DoesNotExist:
                raise serializers.ValidationError("Invalid email or password.")
            
            # Authenticate user
            user = authenticate(username=user.username, password=password)
            if not user:
                raise serializers.ValidationError("Invalid email or password.")
            
            if not user.is_active:
                raise serializers.ValidationError("User account is disabled.")
            
            data['user'] = user
        else:
            raise serializers.ValidationError("Email and password are required.")
        
        return data


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for changing password.
    """
    old_password = serializers.CharField(
        style={'input_type': 'password'}
    )
    new_password = serializers.CharField(
        style={'input_type': 'password'},
        min_length=8
    )
    new_password_confirm = serializers.CharField(
        style={'input_type': 'password'}
    )
    
    def validate_old_password(self, value):
        """Validate old password."""
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect.")
        return value
    
    def validate_new_password(self, value):
        """Validate new password meets requirements."""
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value
    
    def validate(self, data):
        """Validate password confirmation."""
        if data['new_password'] != data['new_password_confirm']:
            raise serializers.ValidationError("New passwords do not match.")
        return data
    
    def save(self):
        """Update user password."""
        user = self.context['request'].user
        if user.auth_type != 'regular':
            raise serializers.ValidationError("Password change not allowed for Azure AD users.")
        
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user
