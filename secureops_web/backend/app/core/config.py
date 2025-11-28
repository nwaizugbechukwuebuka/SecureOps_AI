from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    app_name: str = "SecureOps Web App"
    debug: bool = True
    secret_key: str = "CHANGE_ME"
    ai_api_key: str = "AI_API_KEY_PLACEHOLDER"

settings = Settings()
