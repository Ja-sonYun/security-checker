from sqlmodel import Field, SQLModel


class LicenseCache(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)

    ecosystem: str = Field(index=True)
    name: str = Field(index=True)
    version: str = Field(index=True)
    license: str
