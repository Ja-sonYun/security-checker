from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine


class Database:
    def __init__(
        self,
        db_path: Path = Path("license_cache.db"),
        echo: bool = False,
    ) -> None:
        self.db_path = db_path
        self.engine = create_engine(f"sqlite:///{self.db_path}", echo=False)

    def create_tables(self) -> None:
        from security_checker.checkers.licenses._cache import LicenseCache

        SQLModel.metadata.create_all(self.engine)

    @asynccontextmanager
    async def session(self) -> AsyncIterator[Session]:
        with Session(self.engine) as session:
            yield session
