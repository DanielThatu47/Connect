#!/bin/bash

# Install dependencies from requirements.txt
pip3 install -r requirements.txt


# Run database migrations
python3 manage.py migrate --noinput
