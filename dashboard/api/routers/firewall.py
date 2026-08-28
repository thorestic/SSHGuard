from typing import Annotated

from fastapi import APIRouter, Depends, Query

from ..dependencies import get_repository
from ..repository import SecurityReadRepository
from ..schemas import FirewallActionList, Pagination


router = APIRouter(
    prefix="/firewall-actions",
    tags=["Firewall"],
)


@router.get("", response_model=FirewallActionList)
def list_firewall_actions(
    repository: Annotated[
        SecurityReadRepository,
        Depends(get_repository),
    ],
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
    action: str | None = None,
    source_ip: str | None = None,
) -> FirewallActionList:
    items, total = repository.list_firewall_actions(
        limit=limit,
        offset=offset,
        action=action,
        source_ip=source_ip,
    )

    return FirewallActionList(
        items=items,
        pagination=Pagination(
            total=total,
            limit=limit,
            offset=offset,
        ),
    )

