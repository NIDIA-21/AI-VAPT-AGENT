"""
SQLAlchemy async engine and session factory.
"""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings

settings = get_settings()

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    connect_args={"check_same_thread": False},
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    """Declarative base shared by all ORM models."""
    pass


async def get_db() -> AsyncSession:
    """FastAPI dependency — yields an async DB session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Create all tables on startup (dev convenience) and apply safe migrations."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
        # SQLite schema migration for newly added columns if table already exists
        def _migrate(connection):
            try:
                # Assessments migrations
                res = connection.exec_driver_sql("PRAGMA table_info(assessments)")
                cols = [r[1] for r in res.fetchall()]
                if cols:
                    if "assessment_type" not in cols:
                        connection.exec_driver_sql("ALTER TABLE assessments ADD COLUMN assessment_type VARCHAR(64) DEFAULT 'Network & Web'")
                    if "start_time" not in cols:
                        connection.exec_driver_sql("ALTER TABLE assessments ADD COLUMN start_time DATETIME")
                    if "validated_scope_snapshot" not in cols:
                        connection.exec_driver_sql("ALTER TABLE assessments ADD COLUMN validated_scope_snapshot TEXT")

                # AuthorizedTargets migrations
                res_t = connection.exec_driver_sql("PRAGMA table_info(authorized_targets)")
                t_cols = [r[1] for r in res_t.fetchall()]
                if t_cols:
                    new_cols = {
                        "target_url": "VARCHAR(512)",
                        "purpose": "VARCHAR(128) DEFAULT 'Vulnerability Assessment'",
                        "description": "TEXT",
                        "auth_contact": "VARCHAR(255)",
                        "auth_reference": "VARCHAR(128)",
                        "valid_from": "DATETIME",
                        "valid_to": "DATETIME",
                        "permitted_ports": "TEXT",
                        "excluded_ports": "TEXT",
                        "excluded_paths": "TEXT",
                        "restrictions": "TEXT",
                        "revoked_by": "VARCHAR(255)",
                        "revoked_at": "DATETIME",
                        "revocation_reason": "TEXT",
                        "is_deleted": "BOOLEAN DEFAULT 0",
                        "created_by": "VARCHAR(255)",
                    }
                    for col_name, col_type in new_cols.items():
                        if col_name not in t_cols:
                            connection.exec_driver_sql(f"ALTER TABLE authorized_targets ADD COLUMN {col_name} {col_type}")
            except Exception:
                pass
                
        await conn.run_sync(_migrate)
