import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession


class Database:
    def __init__(
        self,
        db_path: Path,
        echo: bool = False,
    ) -> None:
        self._table_created = False
        self._table_lock = asyncio.Lock()
        self.db_path = db_path
        self.engine = create_async_engine(
            f"sqlite+aiosqlite:///{self.db_path}",
            echo=echo,
        )
        self._sessionmaker = async_sessionmaker(
            self.engine,
            expire_on_commit=False,
            class_=AsyncSession,
        )

    async def create_tables(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

    async def _ensure_tables(self) -> None:
        if self._table_created:
            return
        async with self._table_lock:
            if self._table_created:
                return
            await self.create_tables()
            self._table_created = True

    async def close(self) -> None:
        await self.engine.dispose()

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        await self._ensure_tables()
        async with self._sessionmaker() as session:
            yield session
