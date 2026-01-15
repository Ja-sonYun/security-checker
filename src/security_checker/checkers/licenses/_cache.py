from datetime import datetime, timezone

from sqlalchemy import Index, UniqueConstraint
from sqlmodel import Field, SQLModel


class LicenseCache(SQLModel, table=True):
    __table_args__ = (
        UniqueConstraint(
            "ecosystem",
            "name",
            "version",
            name="uq_license_cache_ecosystem_name_version",
        ),
        Index(
            "ix_license_cache_ecosystem_name_version",
            "ecosystem",
            "name",
            "version",
        ),
    )

    id: int | None = Field(default=None, primary_key=True)

    ecosystem: str
    name: str
    version: str
    license: str
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
