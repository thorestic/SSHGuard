from typing import Annotated

from fastapi import APIRouter, Depends, Query

from ..dependencies import get_repository
from ..repository import SecurityReadRepository
from ..schemas import AnalyticsResponse


router = APIRouter(prefix="/analytics", tags=["Analytics"])


@router.get("", response_model=AnalyticsResponse)
def get_analytics(
    repository: Annotated[
        SecurityReadRepository,
        Depends(get_repository),
    ],
    hours: Annotated[int, Query(ge=1, le=24 * 30)] = 24,
) -> dict:
    return repository.analytics(hours=hours)

