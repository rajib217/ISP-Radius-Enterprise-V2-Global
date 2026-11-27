from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest

from isp_radius.finance.ledger import (
    EntrySide,
    JournalEntry,
    JournalLine,
    JournalStatus,
    build_reversal,
)


def uid():
    return str(uuid4())


def entry(status=JournalStatus.DRAFT):
    now = datetime.now(UTC)
    return JournalEntry(
        id=uid(),
        tenant_id=uid(),
        reference="INV-2026-0001",
        description="Invoice posting",
        effective_at=now,
        created_at=now,
        lines=(
            JournalLine("1100-AR", EntrySide.DEBIT, Decimal("1000.00"), "BDT"),
            JournalLine("4000-REVENUE", EntrySide.CREDIT, Decimal("1000.00"), "BDT"),
        ),
        status=status,
    )


def test_balanced_journal_entry_uses_decimal():
    item = entry()
    assert item.total_debits == Decimal("1000.00")
    assert item.total_credits == Decimal("1000.00")


def test_unbalanced_journal_is_rejected():
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="not balanced"):
        JournalEntry(
            uid(), uid(), "REF-1", "Unbalanced", now, now,
            (
                JournalLine("1000", EntrySide.DEBIT, Decimal(10), "BDT"),
                JournalLine("4000", EntrySide.CREDIT, Decimal(9), "BDT"),
            ),
        )


def test_mixed_currency_journal_is_rejected():
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="mix currencies"):
        JournalEntry(
            uid(), uid(), "REF-2", "Mixed", now, now,
            (
                JournalLine("1000", EntrySide.DEBIT, Decimal(10), "BDT"),
                JournalLine("4000", EntrySide.CREDIT, Decimal(10), "USD"),
            ),
        )


def test_reversal_flips_sides_and_links_original():
    original = entry(JournalStatus.POSTED)
    reversal = build_reversal(
        original, reversal_id=uid(), reference="REV-INV-2026-0001",
        created_at=datetime.now(UTC),
    )
    assert reversal.reversal_of == original.id
    assert reversal.total_debits == original.total_credits
    assert reversal.total_credits == original.total_debits
    assert reversal.status is JournalStatus.DRAFT


def test_only_posted_entries_can_be_reversed():
    with pytest.raises(ValueError, match="posted"):
        build_reversal(entry(), reversal_id=uid(), reference="REV-1",
                       created_at=datetime.now(UTC))
