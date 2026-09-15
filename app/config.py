import os
from dotenv import load_dotenv

load_dotenv()

OTX_API_KEY = os.getenv("OTX_API_KEY", "")
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "")
THREATFOX_AUTH_KEY = os.getenv("THREATFOX_AUTH_KEY", "")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/cti.db")