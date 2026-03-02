"""
MongoDB Configuration for DarkHook Defense

This module handles the MongoDB Atlas connection with proper SSL/TLS configuration.
The TLSV1_ALERT_INTERNAL_ERROR (SSL alert 80) is typically caused by:
1. IP not whitelisted in MongoDB Atlas Network Access List
2. SSL/TLS version incompatibility

Solution:
1. Go to MongoDB Atlas -> Network Access -> Add IP Address
2. Add your current IP (or 0.0.0.0/0 for development)
3. Ensure you're using the correct connection string format
"""

import os
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from urllib.parse import quote_plus

# Get MongoDB configuration from environment variables
MONGO_URI = os.getenv("MONGO_URI", "")
DATABASE_NAME = os.getenv("DATABASE_NAME", "Phishing")

# SSL/TLS Configuration
# MongoDB Atlas requires TLS 1.2+
# The following settings help with connection issues
MONGO_CLIENT_OPTIONS = {
    "serverSelectionTimeoutMS": 10000,
    "connectTimeoutMS": 20000,
    "retryWrites": True,
    "retryReads": True,
    # SSL/TLS specific options
    "tls": True,
}


def get_mongo_client() -> MongoClient:
    """
    Create and return a MongoDB client with proper SSL/TLS configuration.
    
    Returns:
        MongoClient: Configured MongoDB client
        
    Raises:
        ConnectionFailure: If unable to connect to MongoDB
        ConfigurationError: If MONGO_URI is not set
    """
    global MONGO_URI
    
    if not MONGO_URI:
        raise ValueError(
            "MONGO_URI environment variable is not set. "
            "Please configure your MongoDB Atlas connection string in .env file.\n"
            "Example: MONGO_URI=mongodb+srv://<username>:<password>@cluster.mongodb.net/Phishing"
        )
    
    # Handle special characters in password
    # If the password contains special characters, they need to be URL-encoded
    if "://" in MONGO_URI and "@" in MONGO_URI:
        # Parse the connection string to handle special characters
        try:
            # Extract parts from mongodb+srv:// or mongodb://
            prefix = "mongodb+srv://" if MONGO_URI.startswith("mongodb+srv://") else "mongodb://"
            rest = MONGO_URI[len(prefix):]
            
            if "@" in rest:
                creds, host_part = rest.split("@", 1)
                if ":" in creds:
                    username, password = creds.split(":", 1)
                    # URL-encode the password
                    encoded_password = quote_plus(password)
                MONGO_URI = f"{prefix}{username}:{encoded_password}@{host_part}"
        except Exception:
            pass  # If parsing fails, use the original URI
    
    # Create client with SSL configuration
    try:
        client = MongoClient(
            MONGO_URI,
            server_api=ServerApi('1'),
            **MONGO_CLIENT_OPTIONS
        )
        
        # Test the connection
        client.admin.command('ping')
        
        return client
        
    except Exception as e:
        error_message = str(e)
        
        # Provide helpful error messages for common issues
        if "TLSV1_ALERT_INTERNAL_ERROR" in error_message or "SSL alert number 80" in error_message:
            raise ConnectionError(
                "Unable to connect to MongoDB Atlas. This is typically caused by:\n"
                "1. IP address not whitelisted in MongoDB Atlas Network Access\n"
                "2. SSL/TLS version incompatibility\n\n"
                "Solution:\n"
                "1. Go to https://cloud.mongodb.com/v2/ -> Select your project\n"
                "2. Click 'Network Access' in the left sidebar\n"
                "3. Click 'Add IP Address'\n"
                "4. Add your current IP address (or use 0.0.0.0/0 for development)\n"
                "5. Wait a few minutes for the changes to take effect\n\n"
                f"Original error: {error_message}"
            )
        elif "authentication" in error_message.lower():
            raise ConnectionError(
                "MongoDB authentication failed. Please check your username and password.\n"
                "Make sure to URL-encode special characters in your password.\n"
                f"Original error: {error_message}"
            )
        else:
            raise ConnectionError(
                f"Failed to connect to MongoDB: {error_message}"
            )


def get_database():
    """
    Get the MongoDB database instance.
    
    Returns:
        Database: MongoDB database object
    """
    client = get_client()
    return client[DATABASE_NAME]


def get_collection(collection_name: str):
    """
    Get a specific MongoDB collection.
    
    Args:
        collection_name: Name of the collection
        
    Returns:
        Collection: MongoDB collection object
    """
    db = get_database()
    return db[collection_name]


# Singleton client instance
_mongo_client = None


def get_client() -> MongoClient:
    """
    Get a singleton MongoDB client instance.
    This helps avoid creating multiple connections.
    
    Returns:
        MongoClient: Singleton MongoDB client
    """
    global _mongo_client
    
    if _mongo_client is None:
        _mongo_client = get_mongo_client()
    
    return _mongo_client


def close_connection():
    """
    Close the MongoDB connection.
    Call this when shutting down the application.
    """
    global _mongo_client
    
    if _mongo_client is not None:
        _mongo_client.close()
        _mongo_client = None
