from django.core.management.base import BaseCommand
from Application.models import Admin
from django.conf import settings
import os
from dotenv import load_dotenv

class Command(BaseCommand):
    help = 'Creates a superadmin user using credentials from .env file'

    def handle(self, *args, **options):
        # Load environment variables
        load_dotenv()

        # Get credentials from .env file
        email = os.getenv('ADMIN_EMAIL')
        password = os.getenv('ADMIN_PASSWORD')
        name = os.getenv('ADMIN_NAME')

        try:
            # Check if admin already exists
            existing_admin = Admin.objects(email=email).first()
            
            if existing_admin:
                self.stdout.write(
                    self.style.WARNING(f'Admin with email {email} already exists')
                )
            else:
                # Create new admin
                admin = Admin(
                    email=email,
                    name=name,
                    is_superadmin=True
                )
                admin.set_password(password)
                admin.save()
                
                self.stdout.write(
                    self.style.SUCCESS(f'Successfully created admin with email {email}')
                )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error creating admin: {str(e)}')
            )