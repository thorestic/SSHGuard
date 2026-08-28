from typing import Annotated

from fastapi import APIRouter, Depends, Query

from ..dependencies import get_repository
from ..repository import SecurityReadRepository
from ..schemas import IncidentList, Pagination


router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get("", response_model=IncidentList)
def list_incidents(
    repository: Annotated[
        SecurityReadRepository,
        Depends(get_repository),
    ],
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
    status: str | None = None,
    source_ip: str | None = None,
) -> IncidentList:
    items, total = repository.list_incidents(
        limit=limit,
        offset=offset,
        status=status,
        source_ip=source_ip,
    )

    return IncidentList(
        items=items,
        pagination=Pagination(
            total=total,
            limit=limit,
            offset=offset,
        ),
    )

