from typing import Annotated

from fastapi import APIRouter, Depends

from ..dependencies import get_repository
from ..repository import SecurityReadRepository
from ..schemas import FirewallReconciliationResponse


router = APIRouter(
    prefix="/firewall-reconciliation",
    tags=["Firewall"],
)


@router.get("", response_model=FirewallReconciliationResponse)
def get_firewall_reconciliation(
    repository: Annotated[
        SecurityReadRepository,
        Depends(get_repository),
    ],
) -> FirewallReconciliationResponse:
    return FirewallReconciliationResponse(
        **repository.firewall_reconciliation()
    )
