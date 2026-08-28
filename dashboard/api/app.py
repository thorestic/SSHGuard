from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import DashboardSettings
from .repository import DatabaseUnavailable, SecurityReadRepository
from .routers import analytics, authentication, firewall, incidents, overview
from .schemas import HealthResponse


def create_app(
    database_path: str | Path | None = None,
    web_dist_path: str | Path | None = None,
) -> FastAPI:
    settings = DashboardSettings.from_environment()
    selected_database = database_path or settings.database_path
    selected_web_dist = Path(
        web_dist_path or settings.web_dist_path
    )

    application = FastAPI(
        title="SSHGuard Security API",
        summary="Read-only security telemetry for SSHGuard clients",
        description=(
            "A versioned, read-only API over SSHGuard's SQLite event store. "
            "The API does not execute detection or nftables operations."
        ),
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    application.state.repository = SecurityReadRepository(
        selected_database
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=False,
        allow_methods=["GET"],
        allow_headers=["Accept", "Content-Type"],
    )

    @application.exception_handler(DatabaseUnavailable)
    async def database_unavailable_handler(
        request: Request,
        error: DatabaseUnavailable,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=503,
            content={
                "detail": "SSHGuard security data is temporarily unavailable.",
            },
        )

    @application.get(
        "/api/v1/health",
        response_model=HealthResponse,
        tags=["System"],
    )
    def health() -> dict[str, str]:
        return application.state.repository.health()

    application.include_router(
        overview.router,
        prefix="/api/v1",
    )
    application.include_router(
        incidents.router,
        prefix="/api/v1",
    )
    application.include_router(
        authentication.router,
        prefix="/api/v1",
    )
    application.include_router(
        firewall.router,
        prefix="/api/v1",
    )
    application.include_router(
        analytics.router,
        prefix="/api/v1",
    )

    assets_directory = selected_web_dist / "assets"
    index_file = selected_web_dist / "index.html"

    if assets_directory.is_dir() and index_file.is_file():
        application.mount(
            "/assets",
            StaticFiles(directory=assets_directory),
            name="dashboard-assets",
        )

        @application.get(
            "/{client_path:path}",
            include_in_schema=False,
        )
        def dashboard_client(client_path: str) -> FileResponse:
            if client_path.startswith("api/"):
                raise HTTPException(status_code=404)

            return FileResponse(index_file)

    return application


app = create_app()
