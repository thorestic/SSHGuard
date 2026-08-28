from fastapi import Request

from .repository import SecurityReadRepository


def get_repository(request: Request) -> SecurityReadRepository:
    return request.app.state.repository

