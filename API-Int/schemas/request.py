from pydantic import BaseModel, Field, model_validator
from typing import Optional, List


class MessageRequest(BaseModel):
    message: str = Field(
        min_length=1,
        max_length=10000,
        description="Suspicious message to analyze"
    )
    sender_email: Optional[str] = Field(
        default="",
        max_length=320,
        description="Claimed sender email address (optional)"
    )
    sender_name: Optional[str] = Field(
        default="",
        max_length=200,
        description="Claimed sender display name (optional)"
    )


class URLRequest(BaseModel):
    url: str = Field(
        min_length=1,
        max_length=2048,
        description="URL to analyze"
    )


class ImpersonationRequest(BaseModel):
    claimed_entity: Optional[str] = Field(
        default="",
        max_length=200,
        description="Claimed brand, bank, or organization (e.g. State Bank of India, PayPal, Netflix)"
    )
    sender_email: Optional[str] = Field(
        default="",
        max_length=320,
        description="Sender email address to verify"
    )
    sender_name: Optional[str] = Field(
        default="",
        max_length=200,
        description="Claimed sender name"
    )
    message: Optional[str] = Field(
        default="",
        max_length=10000,
        description="Optional message body context"
    )
    url: Optional[str] = Field(
        default="",
        max_length=2048,
        description="Link or destination address mentioned in communication"
    )

    @model_validator(mode="after")
    def validate_impersonation_input(self):
        has_brand = bool(self.claimed_entity and self.claimed_entity.strip())
        has_sender = bool(self.sender_email and self.sender_email.strip())
        has_msg = bool(self.message and self.message.strip())
        has_url = bool(self.url and self.url.strip())
        if not (has_brand or has_sender or has_msg or has_url):
            raise ValueError("Please provide a claimed brand, sender email, message, or link to verify.")
        return self


class CombinedRequest(BaseModel):
    message: Optional[str] = Field(
        default=None,
        max_length=10000
    )
    url: Optional[str] = Field(
        default=None,
        max_length=2048
    )
    sender_email: Optional[str] = Field(
        default="",
        max_length=320
    )
    sender_name: Optional[str] = Field(
        default="",
        max_length=200
    )
    claimed_entity: Optional[str] = Field(
        default="",
        max_length=200
    )

    @model_validator(mode="after")
    def validate_input(self):
        has_message = bool(self.message and self.message.strip())
        has_url = bool(self.url and self.url.strip())
        has_sender = bool(self.sender_email and self.sender_email.strip())
        has_brand = bool(self.claimed_entity and self.claimed_entity.strip())
        if not has_message and not has_url and not has_sender and not has_brand:
            raise ValueError("Please provide a message, URL, sender, or brand to analyze.")

        return self
