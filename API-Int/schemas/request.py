from pydantic import BaseModel, Field, model_validator
from typing import Optional


class MessageRequest(BaseModel):
    message: str = Field(
        min_length=1,
        max_length=10000,
        description="Suspicious message to analyze"
    )


class URLRequest(BaseModel):
    url: str = Field(
        min_length=1,
        max_length=2048,
        description="URL to analyze"
    )


class CombinedRequest(BaseModel):
    message: Optional[str] = Field(
        default=None,
        max_length=10000
    )

    url: Optional[str] = Field(
        default=None,
        max_length=2048
    )

    @model_validator(mode="after")
    def validate_input(self):
        if not (self.message and self.message.strip()) and not (
            self.url and self.url.strip()
        ):
            raise ValueError("Please provide a message, URL, or both.")

        return self