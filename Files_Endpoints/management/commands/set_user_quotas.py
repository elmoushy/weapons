"""
Management command to set user quotas in bulk.

This command allows administrators to set quotas for users
based on their role or other criteria.
"""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from Files_Endpoints.models import UserQuota


User = get_user_model()


class Command(BaseCommand):
    help = 'Set user quotas in bulk'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--role',
            type=str,
            help='Set quota for users with specific role (admin, manager, employee)',
        )
        parser.add_argument(
            '--quota-gb',
            type=float,
            required=True,
            help='Quota size in GB',
        )
        parser.add_argument(
            '--user-email',
            type=str,
            help='Set quota for specific user by email',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without making changes',
        )
    
    def handle(self, *args, **options):
        role = options['role']
        quota_gb = options['quota_gb']
        user_email = options['user_email']
        dry_run = options['dry_run']
        
        quota_bytes = int(quota_gb * 1024**3)
        
        self.stdout.write(f"Setting quota to {quota_gb} GB ({quota_bytes} bytes)")
        self.stdout.write(f"Dry run: {dry_run}")
        
        # Build user queryset
        if user_email:
            users = User.objects.filter(email=user_email, is_active=True)
            if not users.exists():
                self.stdout.write(
                    self.style.ERROR(f"User with email {user_email} not found")
                )
                return
        elif role:
            users = User.objects.filter(role=role, is_active=True)
            if not users.exists():
                self.stdout.write(
                    self.style.ERROR(f"No active users found with role {role}")
                )
                return
        else:
            self.stdout.write(
                self.style.ERROR("Must specify either --role or --user-email")
            )
            return
        
        self.stdout.write(f"Found {users.count()} users to update")
        
        updated_count = 0
        created_count = 0
        
        for user in users:
            quota, created = UserQuota.objects.get_or_create(
                user=user,
                defaults={'limit_bytes': quota_bytes}
            )
            
            if created:
                created_count += 1
                self.stdout.write(f"Created quota for {user.email}: {quota_gb} GB")
            elif quota.limit_bytes != quota_bytes:
                old_gb = quota.limit_bytes / (1024**3)
                
                if not dry_run:
                    quota.limit_bytes = quota_bytes
                    quota.save()
                
                updated_count += 1
                self.stdout.write(
                    f"Updated {user.email}: {old_gb:.2f} GB -> {quota_gb} GB"
                )
            else:
                self.stdout.write(f"No change needed for {user.email}")
        
        if not dry_run:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Completed: {created_count} created, {updated_count} updated"
                )
            )
        else:
            self.stdout.write(
                f"Would create {created_count} and update {updated_count} quotas"
            )
