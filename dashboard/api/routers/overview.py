from typing import Annotated

from fastapi import APIRouter, Depends

from ..dependencies import get_repository
from ..repository import SecurityReadRepository
from ..schemas import OverviewResponse


router = APIRouter(prefix="/overview", tags=["Overview"])


@router.get("", response_model=OverviewResponse)
def get_overview(
    repository: Annotated[
        SecurityReadRepository,
        Depends(get_repository),
    ],
) -> dict:
    return repository.overview()

