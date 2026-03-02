# Database module for DarkHook Defense
from .mongo_config import get_client, get_database, get_collection, close_connection

__all__ = ['get_client', 'get_database', 'get_collection', 'close_connection']
