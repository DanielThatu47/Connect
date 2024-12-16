#!/bin/bash

# Install dependencies from requirements.txt
pip install -r requirements.txt

# Collect static files (for production deployment)
python manage.py collectstatic --noinput

python manage.py create_admin.py
# Run database migrations
python manage.py migrate --noinput
