"""Currency-safe double-entry journal primitives.

This is a domain validation layer, not a complete accounting application or
jurisdiction-specific tax implementation.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from uuid import UUID


class JournalStatus(StrEnum):
    DRAFT = "draft"
    POSTED = "posted"
    REVERSED = "reversed"


class EntrySide(StrEnum):
    DEBIT = "debit"
    CREDIT = "credit"


def _valid_uuid(value: str, field: str) -> None:
    try:
        UUID(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError(f"{field} must be a valid UUID") from exc


@dataclass(frozen=True, slots=True)
class JournalLine:
    account_code: str
    side: EntrySide
    amount: Decimal
    currency: str
    memo: str | None = None

    def __post_init__(self) -> None:
        if not self.account_code or not self.account_code.strip():
            raise ValueError("account_code is required")
        if not isinstance(self.amount, Decimal) or not self.amount.is_finite():
            raise ValueError("amount must be a finite Decimal")
        if self.amount <= 0:
            raise ValueError("journal line amount must be greater than zero")
        if len(self.currency) != 3 or not self.currency.isalpha() or self.currency.upper() != self.currency:
            raise ValueError("currency must be a three-letter uppercase code")


@dataclass(frozen=True, slots=True)
class JournalEntry:
    id: str
    tenant_id: str
    reference: str
    description: str
    effective_at: datetime
    created_at: datetime
    lines: tuple[JournalLine, ...]
    status: JournalStatus = JournalStatus.DRAFT
    reversal_of: str | None = None

    def __post_init__(self) -> None:
        _valid_uuid(self.id, "journal id")
        _valid_uuid(self.tenant_id, "tenant_id")
        if not self.reference.strip():
            raise ValueError("reference is required")
        if not self.description.strip():
            raise ValueError("description is required")
        for field in ("effective_at", "created_at"):
            value = getattr(self, field)
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"{field} must be timezone-aware")
        if len(self.lines) < 2:
            raise ValueError("journal entry requires at least two lines")
        currencies = {line.currency for line in self.lines}
        if len(currencies) != 1:
            raise ValueError("a journal entry cannot mix currencies")
        debits = sum(
            (line.amount for line in self.lines if line.side is EntrySide.DEBIT),
            Decimal(0),
        )
        credits = sum(
            (line.amount for line in self.lines if line.side is EntrySide.CREDIT),
            Decimal(0),
        )
        if debits != credits:
            raise ValueError("journal entry is not balanced: debits must equal credits")
        if self.reversal_of is not None:
            _valid_uuid(self.reversal_of, "reversal_of")
            if self.reversal_of == self.id:
                raise ValueError("journal entry cannot reverse itself")

    @property
    def total_debits(self) -> Decimal:
        return sum(
            (line.amount for line in self.lines if line.side is EntrySide.DEBIT),
            Decimal(0),
        )

    @property
    def total_credits(self) -> Decimal:
        return sum(
            (line.amount for line in self.lines if line.side is EntrySide.CREDIT),
            Decimal(0),
        )


def build_reversal(
    original: JournalEntry, *, reversal_id: str, reference: str, created_at: datetime
) -> JournalEntry:
    """Build a balanced, linked reversal; caller must authorize and persist it."""
    if original.status is not JournalStatus.POSTED:
        raise ValueError("only a posted journal entry can be reversed")
    if original.reversal_of is not None:
        raise ValueError("a reversal entry cannot itself be reversed")
    reversed_lines = tuple(
        JournalLine(
            account_code=line.account_code,
            side=EntrySide.CREDIT if line.side is EntrySide.DEBIT else EntrySide.DEBIT,
            amount=line.amount,
            currency=line.currency,
            memo=f"Reversal: {line.memo}" if line.memo else "Reversal",
        )
        for line in original.lines
    )
    return JournalEntry(
        id=reversal_id,
        tenant_id=original.tenant_id,
        reference=reference,
        description=f"Reversal of {original.reference}",
        effective_at=created_at,
        created_at=created_at,
        lines=reversed_lines,
        status=JournalStatus.DRAFT,
        reversal_of=original.id,
    )
