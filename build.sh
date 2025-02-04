#!/bin/bash

# Install dependencies from requirements.txt
pip3.11 install -r requirements.txt


# Run database migrations
python3.11 manage.py migrate --noinput
