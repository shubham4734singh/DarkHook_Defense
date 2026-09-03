from pydantic import BaseModel, EmailStr, field_validator

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        cleaned = value.strip()
        if len(cleaned) < 2:
            raise ValueError("Name must be at least 2 characters long")
        if len(cleaned) > 100:
            raise ValueError("Name must be 100 characters or fewer")
        return cleaned

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return str(value).strip().lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if len(value) > 128:
            raise ValueError("Password must be 128 characters or fewer")
        if not any(ch.isalpha() for ch in value) or not any(ch.isdigit() for ch in value):
            raise ValueError("Password must include both letters and numbers")
        return value

class UserLogin(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return str(value).strip().lower()

class EmailOtpRequest(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return str(value).strip().lower()

class EmailOtpVerify(BaseModel):
    email: EmailStr
    otp: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return str(value).strip().lower()

class Token(BaseModel):
    access_token: str
    token_type: str

class RegisterResponse(BaseModel):
    message: str
    email: str
    requires_verification: bool

class UserResponse(BaseModel):
    name: str
    email: str
