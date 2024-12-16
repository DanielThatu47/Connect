# myapp/mongodb.py

from pymongo import MongoClient

# MongoDB connection settings
MONGODB_URI = "mongodb+srv://danielthatu10:qqNmEymnjs5KBZl1@cluster0.2yqq8ix.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
MONGODB_DB_NAME = "NGO"
MONGO_DB_USERNAME = "danielthatu10"
MONGO_DB_PASSWORD = "qqNmEymnjs5KBZl1"


# Create a MongoClient instance
client = MongoClient(MONGODB_URI)
db = client[MONGODB_DB_NAME]
