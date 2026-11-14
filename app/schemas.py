"""Request models. Unknown fields are rejected (`extra="forbid"`) so a typo is an error, not a no-op."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, HttpUrl

Money = Annotated[Decimal, Field(ge=0, max_digits=12, decimal_places=2)]
PositiveMoney = Annotated[Decimal, Field(gt=0, max_digits=12, decimal_places=2)]
Quantity = Annotated[Decimal, Field(gt=0, max_digits=10, decimal_places=2)]
Role = Literal["admin", "staff", "auditor", "viewer"]
OrderStatus = Literal["CREATED", "PAID", "SHIPPED", "DELIVERED", "CANCELLED", "REFUNDED"]
PaymentMethod = Literal["CARD", "CASH", "BKASH", "NAGAD", "BANK"]
MIN_PASSWORD = 6
Password = Annotated[str, Field(min_length=MIN_PASSWORD, max_length=128)]
ENTITY_PATTERN = r"^[a-z][a-z0-9_]{0,29}$"
EventPattern = Annotated[str, Field(pattern=r"^(\*|[a-z][a-z0-9_]*(\.[a-z0-9_]+)*(\.\*)?)$", max_length=80)]


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ---- auth / users ---------------------------------------------------------------------
class SignupIn(_In):
    organization: str = Field(min_length=2, max_length=120)
    full_name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: Password


class LoginIn(_In):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class RefreshIn(_In):
    refresh_token: str | None = Field(default=None, max_length=200,
                                      description="Omit when using the browser cookie")


class PasswordChangeIn(_In):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: Password


class UserCreate(_In):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=120)
    password: Password
    role: Role = "viewer"


class UserUpdate(_In):
    full_name: str | None = Field(default=None, min_length=2, max_length=120)
    role: Role | None = None
    is_active: bool | None = None


class OrganizationUpdate(_In):
    name: str = Field(min_length=2, max_length=120)


class SettingsUpdate(_In):
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    approval_price_change_pct: Decimal | None = Field(default=None, ge=0, le=1000)
    price_change_alert_pct: Decimal | None = Field(default=None, ge=0, le=1000)
    discount_alert_pct: Decimal | None = Field(default=None, ge=0, le=100)
    large_refund_amount: Money | None = None
    rapid_change_count: int | None = Field(default=None, ge=2, le=1000)
    rapid_change_minutes: int | None = Field(default=None, ge=1, le=1440)


# ---- catalogue ------------------------------------------------------------------------
class CustomerIn(_In):
    name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    phone: str | None = Field(default=None, max_length=30)


class CustomerUpdate(_In):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    email: EmailStr | None = None
    phone: str | None = Field(default=None, max_length=30)


class ProductIn(_In):
    sku: str = Field(min_length=1, max_length=40)
    name: str = Field(min_length=1, max_length=120)
    price: Money
    active: bool = True


class ProductUpdate(_In):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    price: Money | None = None
    active: bool | None = None
    reason: str | None = Field(default=None, max_length=500, description="Why the price is changing")


# ---- orders ---------------------------------------------------------------------------
class OrderItemIn(_In):
    product_id: int
    quantity: Quantity
    unit_price: Money | None = Field(default=None, description="Override list price (manual discount)")


class OrderCreate(_In):
    customer_id: int
    notes: str | None = Field(default=None, max_length=500)
    items: list[OrderItemIn] = Field(default_factory=list, max_length=200)


class OrderItemUpdate(_In):
    quantity: Quantity
    unit_price: Money | None = None


class PaymentIn(_In):
    amount: PositiveMoney
    method: PaymentMethod
    reference: str | None = Field(default=None, max_length=80)


class StatusChange(_In):
    status: OrderStatus


# ---- governance -----------------------------------------------------------------------
class AlertUpdate(_In):
    status: Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"]


class ReviewIn(_In):
    note: str | None = Field(default=None, max_length=500)


class WebhookIn(_In):
    url: HttpUrl
    event_types: list[EventPattern] = Field(default_factory=lambda: ["*"], min_length=1, max_length=20)
    description: str | None = Field(default=None, max_length=200)


class WebhookUpdate(_In):
    url: HttpUrl | None = None
    event_types: list[EventPattern] | None = Field(default=None, min_length=1, max_length=20)
    description: str | None = Field(default=None, max_length=200)
    is_active: bool | None = None


class CheckpointIn(_In):
    """A checkpoint the caller kept outside this system (for example from a webhook)."""

    chain_seq: int = Field(gt=0)
    row_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    signature: str = Field(min_length=10, max_length=200)


class VerifyIn(_In):
    checkpoints: list[CheckpointIn] = Field(default_factory=list, max_length=1000)


# ---- integration ----------------------------------------------------------------------
CaptureMethod = Literal["CDC", "TRIGGER", "API", "CSV_IMPORT", "POLLING", "MANUAL"]
TrustLevel = Literal["HIGH", "MEDIUM", "LOW"]
ApiKeyScope = Literal["events:write", "events:read", "audit:read", "audit:verify", "audit:export"]


class SourceIn(_In):
    code: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,59}$", description="Used as the CloudEvents `source`")
    name: str = Field(min_length=1, max_length=120)
    capture_method: CaptureMethod
    trust_level: TrustLevel


class SourceUpdate(_In):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    status: Literal["ACTIVE", "PAUSED"] | None = None
    trust_level: TrustLevel | None = None


class ApiKeyIn(_In):
    name: str = Field(min_length=1, max_length=100)
    scopes: list[ApiKeyScope] = Field(min_length=1)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650, description="Omit for a key that does not expire")


class CloudEventIn(BaseModel):
    """CloudEvents 1.0, structured mode. Extension attributes are accepted and stored."""

    model_config = ConfigDict(extra="allow")
    specversion: Literal["1.0"]
    id: str = Field(min_length=1, max_length=200, description="Unique per source; used for idempotency")
    source: str = Field(min_length=1, max_length=60, description="Code of a registered source")
    type: str = Field(pattern=r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$", max_length=120, examples=["order.updated"])
    subject: str | None = Field(default=None, max_length=200, examples=["order/10045"],
                                description="`<entity>/<external id>`; required for reconstruction and reconciliation")
    time: datetime = Field(description="When the change happened in the source system")
    datacontenttype: Literal["application/json"] | None = None
    data: dict[str, Any] = Field(description="Debezium-style `{op, before, after}` is recommended")


class ReconRecord(_In):
    external_id: str = Field(min_length=1, max_length=100)
    fields: dict[str, Any] = Field(default_factory=dict, description="Fields to compare, e.g. {status, total}")


class ReconIn(_In):
    source: str = Field(min_length=1, max_length=60)
    entity: str = Field(pattern=ENTITY_PATTERN)
    as_of: datetime | None = Field(default=None, description="Compare against evidence up to this time (default now)")
    complete: bool = Field(default=False, description="True if `records` is the full set; enables UNEXPECTED detection")
    records: list[ReconRecord] = Field(max_length=5000)
