# your_app_name/models.py
from mongoengine import Document,ReferenceField, FloatField, StringField, EmailField, DateTimeField, BooleanField,ImageField ,FileField ,IntField
import bcrypt
from datetime import datetime
import random
import mongoengine as me
# from django.contrib.auth.models import AbstractUser
from django.db import models

def generate_random_color():
    return "#{:06x}".format(random.randint(0, 0xFFFFFF))


class User(me.Document):
    name = me.StringField(required=True, max_length=50)
    email = me.EmailField(required=True, unique=True)
    password = me.StringField(required=True)
    created_at = DateTimeField(default=datetime.utcnow)
    profile_color = StringField(default=generate_random_color)  # New field for profile color
    avatar = StringField()   # No `upload_to` in MongoEngine's FileField
    # avatar = ImageField(upload_to='avatars/')
    expire_at = me.DateTimeField()


    meta = {
        'indexes': [
            {'fields': ['expire_at'], 'expireAfterSeconds': 0}
        ]
    }

    def set_password(self, raw_password):
        if raw_password is not None:
            self.password = bcrypt.hashpw(raw_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        else:
            self.password = None

    def check_password(self, raw_password):
        # Check the hashed password
        return bcrypt.checkpw(raw_password.encode('utf-8'), self.password.encode('utf-8'))

class Admin(Document):
    name = StringField(required=True, max_length=50)
    email = EmailField(required=True, unique=True)
    password = StringField(required=True)
    is_superadmin = BooleanField(default=False)
    created_at = DateTimeField(default=datetime.utcnow)

    def set_password(self, raw_password):
        self.password = bcrypt.hashpw(raw_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, raw_password):
        return bcrypt.checkpw(raw_password.encode('utf-8'), self.password.encode('utf-8'))

class NGO(Document):
    name = StringField(required=True, max_length=100)
    description = StringField(required=True)
    address = StringField(required=True)
    image = StringField()  # We'll store the image path here
    category = StringField(required=True)
    vision = StringField(required=True)
    mission = StringField(required=True)
    contact_number = IntField(required=True)
    email = EmailField(required=True)
    website = StringField(required=True)
    created_at = DateTimeField(default=datetime.utcnow)


class Donation(Document):
    user = ReferenceField(User, required=True)  # Link to User
    ngo = ReferenceField(NGO, required=True)    # Link to NGO
    amount = FloatField(required=True)          # Donation amount
    message = StringField()                     # Optional message
    donated_at = DateTimeField(default=datetime.utcnow)  # Donation date and time

