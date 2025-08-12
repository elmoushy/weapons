"""
Management command to setup the news service database
"""
from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.db import connection
from django.contrib.auth import get_user_model
import logging

logger = logging.getLogger(__name__)
User = get_user_model()


class Command(BaseCommand):
    help = 'Setup the news service database with fresh migrations'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--reset',
            action='store_true',
            help='Reset the database completely (WARNING: This will delete all data)',
        )
        parser.add_argument(
            '--create-admin',
            action='store_true',
            help='Create a default admin user',
        )
    
    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('Starting news service database setup...')
        )
        
        try:
            if options['reset']:
                self.reset_database()
            
            # Make migrations
            self.stdout.write('Making migrations...')
            call_command('makemigrations', verbosity=1)
            
            # Apply migrations
            self.stdout.write('Applying migrations...')
            call_command('migrate', verbosity=1)
            
            if options['create_admin']:
                self.create_admin_user()
            
            self.stdout.write(
                self.style.SUCCESS('News service database setup completed successfully!')
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error setting up database: {e}')
            )
            logger.error(f'Database setup error: {e}')
    
    def reset_database(self):
        """Reset the database by dropping all tables"""
        self.stdout.write(
            self.style.WARNING('Resetting database (this will delete all data)...')
        )
        
        with connection.cursor() as cursor:
            # Get all table names
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
            )
            tables = cursor.fetchall()
            
            # Drop all tables
            for table in tables:
                cursor.execute(f'DROP TABLE IF EXISTS {table[0]}')
                self.stdout.write(f'Dropped table: {table[0]}')
        
        self.stdout.write(
            self.style.SUCCESS('Database reset completed')
        )
    
    def create_admin_user(self):
        """Create a default admin user"""
        self.stdout.write('Creating admin user...')
        
        try:
            admin_email = 'admin@weaponpowercloud.com'
            
            if User.objects.filter(email=admin_email).exists():
                self.stdout.write(f'Admin user {admin_email} already exists')
                return
            
            admin_user = User.objects.create_user(
                email=admin_email,
                first_name='Admin',
                last_name='User',
                role='admin',
                is_staff=True,
                is_superuser=True,
                is_active=True
            )
            
            self.stdout.write(
                self.style.SUCCESS(f'Admin user created: {admin_email}')
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error creating admin user: {e}')
            )
