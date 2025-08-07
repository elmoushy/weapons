"""
Management command to cleanup orphaned files and update quotas.

This command performs maintenance tasks on the file system:
- Remove files marked for deletion
- Recalculate user quotas
- Clean up expired shares
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db.models import Sum
from Files_Endpoints.models import File, Share, UserQuota


class Command(BaseCommand):
    help = 'Cleanup files system and update quotas'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without making changes',
        )
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Delete files older than specified days (default: 30)',
        )
    
    def handle(self, *args, **options):
        dry_run = options['dry_run']
        days_old = options['days']
        
        cutoff_date = timezone.now() - timezone.timedelta(days=days_old)
        
        self.stdout.write(f"Files cleanup - Dry run: {dry_run}")
        self.stdout.write(f"Cutoff date: {cutoff_date}")
        
        # Find files to hard delete
        files_to_delete = File.objects.filter(
            deleted_at__isnull=False,
            deleted_at__lt=cutoff_date
        )
        
        self.stdout.write(f"Files to permanently delete: {files_to_delete.count()}")
        
        if not dry_run:
            deleted_count = files_to_delete.count()
            files_to_delete.delete()
            self.stdout.write(
                self.style.SUCCESS(f"Permanently deleted {deleted_count} files")
            )
        
        # Clean up expired shares
        expired_shares = Share.objects.filter(
            expires_at__isnull=False,
            expires_at__lt=timezone.now()
        )
        
        self.stdout.write(f"Expired shares to remove: {expired_shares.count()}")
        
        if not dry_run:
            expired_count = expired_shares.count()
            expired_shares.delete()
            self.stdout.write(
                self.style.SUCCESS(f"Removed {expired_count} expired shares")
            )
        
        # Recalculate quotas
        self.stdout.write("Recalculating user quotas...")
        
        quotas_updated = 0
        for quota in UserQuota.objects.all():
            old_used = quota.used_bytes
            
            # Calculate actual usage
            actual_used = quota.user.files.filter(
                deleted_at__isnull=True
            ).aggregate(
                total=Sum('size_bytes')
            )['total'] or 0
            
            if old_used != actual_used:
                if not dry_run:
                    quota.used_bytes = actual_used
                    quota.save()
                
                quotas_updated += 1
                self.stdout.write(
                    f"User {quota.user.email}: {old_used} -> {actual_used} bytes"
                )
        
        if quotas_updated > 0:
            if not dry_run:
                self.stdout.write(
                    self.style.SUCCESS(f"Updated {quotas_updated} user quotas")
                )
            else:
                self.stdout.write(f"Would update {quotas_updated} user quotas")
        else:
            self.stdout.write("All quotas are up to date")
        
        self.stdout.write(self.style.SUCCESS("Cleanup completed"))
