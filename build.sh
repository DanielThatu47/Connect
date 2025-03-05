#!/bin/bash

# Install dependencies from requirements.txt
pip install -r requirements.txt


# Run database migrations
python manage.py migrate --noinput

python manage.py runserver
