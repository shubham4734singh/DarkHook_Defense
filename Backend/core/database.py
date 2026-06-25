from pymongo import MongoClient
from pymongo.server_api import ServerApi
from urllib.parse import quote_plus
from core.config import settings

# MongoDB options
MONGO_CLIENT_OPTIONS = {
    "serverSelectionTimeoutMS": 10000,
    "connectTimeoutMS": 20000,
    "retryWrites": True,
    "retryReads": True,
    "tls": True,
}

_mongo_client: MongoClient | None = None

def get_mongo_client() -> MongoClient:
    """
    Create and return a MongoDB client with proper SSL/TLS configuration.
    """
    mongo_uri = settings.MONGO_URI
    
    if not mongo_uri:
        raise ValueError(
            "MONGO_URI setting is not set. "
            "Please configure your MongoDB Atlas connection string."
        )
    
    # Handle special characters in password
    if "://" in mongo_uri and "@" in mongo_uri:
        try:
            prefix = "mongodb+srv://" if mongo_uri.startswith("mongodb+srv://") else "mongodb://"
            rest = mongo_uri[len(prefix):]
            
            if "@" in rest:
                creds, host_part = rest.split("@", 1)
                if ":" in creds:
                    username, password = creds.split(":", 1)
                    # URL-encode the password
                    encoded_password = quote_plus(password)
                    mongo_uri = f"{prefix}{username}:{encoded_password}@{host_part}"
        except Exception:
            pass  # If parsing fails, use the original URI
    
    try:
        client = MongoClient(
            mongo_uri,
            server_api=ServerApi('1'),
            **MONGO_CLIENT_OPTIONS
        )
        
        # Test connection
        client.admin.command('ping')
        return client
        
    except Exception as e:
        error_message = str(e)
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

def get_client() -> MongoClient:
    """Get or create singleton MongoClient connection."""
    global _mongo_client
    if _mongo_client is None:
        _mongo_client = get_mongo_client()
    return _mongo_client

def get_database():
    """Get the MongoDB database instance."""
    client = get_client()
    return client[settings.DATABASE_NAME]

def get_collection(collection_name: str):
    """Get a specific MongoDB collection."""
    db = get_database()
    return db[collection_name]

def close_connection():
    """Close the MongoDB connection client."""
    global _mongo_client
    if _mongo_client is not None:
        _mongo_client.close()
        _mongo_client = None
