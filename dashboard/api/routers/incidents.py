from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from ..dependencies import get_repository
from ..repository import SecurityReadRepository
from ..schemas import IncidentDetail, IncidentList, Pagination


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


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident_detail(
    incident_id: int,
    repository: Annotated[
        SecurityReadRepository,
        Depends(get_repository),
    ],
) -> IncidentDetail:
    detail = repository.get_incident_detail(incident_id)

    if detail is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return IncidentDetail(**detail)

