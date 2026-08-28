from typing import Annotated

from fastapi import APIRouter, Depends, Query

from ..dependencies import get_repository
from ..repository import SecurityReadRepository
from ..schemas import AuthenticationEventList, Pagination


router = APIRouter(
    prefix="/authentication-events",
    tags=["Authentication"],
)


@router.get("", response_model=AuthenticationEventList)
def list_authentication_events(
    repository: Annotated[
        SecurityReadRepository,
        Depends(get_repository),
    ],
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
    event_type: str | None = None,
    source_ip: str | None = None,
    username: str | None = None,
) -> AuthenticationEventList:
    items, total = repository.list_authentication_events(
        limit=limit,
        offset=offset,
        event_type=event_type,
        source_ip=source_ip,
        username=username,
    )

    return AuthenticationEventList(
        items=items,
        pagination=Pagination(
            total=total,
            limit=limit,
            offset=offset,
        ),
    )

