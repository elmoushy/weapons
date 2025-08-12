#!/usr/bin/env python
"""
Script to add a super_admin user to the system.

This script creates a new super_admin user with regular authentication (email/password).
Usage: python add_super_admin_user.py
"""

import os
import sys
import django

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'weaponpowercloud_backend.settings')
django.setup()

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password

User = get_user_model()


def create_super_admin():
    """
    Create a super admin user with the specified credentials.
    """
    # User details
    email = "seif778811@gmail.com"
    auth_type = "regular"
    password = "Password778811"
    first_name = "Seif"
    last_name = "Eldein"
    role = "super_admin"
    
    print(f"Creating super_admin user: {email}")
    
    try:
        # Check if user already exists using Oracle-compatible method
        existing_user = User.objects.get_by_email(email)
        if existing_user:
            print(f"❌ Error: User with email '{email}' already exists!")
            return False
        
        # Validate password
        try:
            validate_password(password)
            print("✅ Password validation passed")
        except ValidationError as e:
            print(f"❌ Password validation failed:")
            for error in e.messages:
                print(f"   - {error}")
            return False
        
        # Create the user
        user = User.objects.create_user(
            username=email,  # Use email as username for regular users
            email=email,
            password=password,
            auth_type=auth_type,
            first_name=first_name,
            last_name=last_name,
            role=role
        )
        
        print("✅ Super admin user created successfully!")
        print(f"   - ID: {user.id}")
        print(f"   - Email: {user.email}")
        print(f"   - Username: {user.username}")
        print(f"   - Name: {user.full_name}")
        print(f"   - Role: {user.role}")
        print(f"   - Auth Type: {user.auth_type}")
        print(f"   - Active: {user.is_active}")
        print(f"   - Is Staff: {user.is_staff}")
        print(f"   - Is Superuser: {user.is_superuser}")
        print(f"   - Date Joined: {user.date_joined}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating user: {str(e)}")
        return False


def main():
    """
    Main function to execute the user creation.
    """
    print("=" * 60)
    print("Super Admin User Creation Script")
    print("=" * 60)
    
    # Check if we're in a Django environment
    try:
        User.objects.count()
        print("✅ Django environment setup successful")
    except Exception as e:
        print(f"❌ Django setup failed: {str(e)}")
        print("Make sure you're running this from the project root directory")
        return
    
    # Create the user
    success = create_super_admin()
    
    if success:
        print("\n" + "=" * 60)
        print("🎉 SUCCESS: Super admin user created successfully!")
        print("=" * 60)
        print("\nYou can now use these credentials to:")
        print("1. Login via /api/auth/login/ endpoint")
        print("2. Access admin functionality")
        print("3. Create other users via /api/auth/add-user/ endpoint")
        print("\nLogin credentials:")
        print("  Email: seif778811@gmail.com")
        print("  Password: Password778811")
    else:
        print("\n" + "=" * 60)
        print("❌ FAILED: Could not create super admin user")
        print("=" * 60)


if __name__ == "__main__":
    main()
