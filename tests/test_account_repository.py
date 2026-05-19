"""AccountRepository tests — accounts table + binding-token lifecycle."""

from __future__ import annotations

import time
from datetime import timedelta

import pytest

from auspexai_platform.db.models import IdentityProvider, TrustTier
from auspexai_platform.db.repositories import AccountRepository
from auspexai_platform.db.repositories.accounts import (
    BindingTokenConsumedError,
    BindingTokenExpiredError,
    BindingTokenNotFoundError,
    DuplicateAccountError,
)

# ---- account writes / reads ------------------------------------------------


def test_create_returns_account_with_defaults(account_repository: AccountRepository) -> None:
    account = account_repository.create(
        account_id="acct-test123",
        idp=IdentityProvider.GITHUB,
        idp_sub="246774008",
        display_name="jasongagne-git",
    )
    assert account.account_id == "acct-test123"
    assert account.idp is IdentityProvider.GITHUB
    assert account.idp_sub == "246774008"
    assert account.display_name == "jasongagne-git"
    assert account.trust_tier is TrustTier.T1_VERIFIED
    assert account.retired_at is None


def test_create_duplicate_idp_sub_raises(account_repository: AccountRepository) -> None:
    account_repository.create(
        account_id="acct-a",
        idp=IdentityProvider.GITHUB,
        idp_sub="123",
    )
    with pytest.raises(DuplicateAccountError):
        account_repository.create(
            account_id="acct-b",
            idp=IdentityProvider.GITHUB,
            idp_sub="123",
        )


def test_create_duplicate_account_id_raises(account_repository: AccountRepository) -> None:
    account_repository.create(
        account_id="acct-shared",
        idp=IdentityProvider.GITHUB,
        idp_sub="1",
    )
    with pytest.raises(DuplicateAccountError):
        account_repository.create(
            account_id="acct-shared",
            idp=IdentityProvider.GITHUB,
            idp_sub="2",
        )


def test_get_by_idp_subject_returns_match(account_repository: AccountRepository) -> None:
    created = account_repository.create(
        account_id="acct-lookup",
        idp=IdentityProvider.GITHUB,
        idp_sub="42",
    )
    found = account_repository.get_by_idp_subject(IdentityProvider.GITHUB, "42")
    assert found is not None
    assert found.account_id == created.account_id


def test_get_by_idp_subject_returns_none_when_missing(
    account_repository: AccountRepository,
) -> None:
    assert account_repository.get_by_idp_subject(IdentityProvider.GITHUB, "nope") is None


# ---- binding-token lifecycle ----------------------------------------------


def test_issue_and_consume_binding_roundtrip(account_repository: AccountRepository) -> None:
    account = account_repository.create(
        account_id="acct-1",
        idp=IdentityProvider.GITHUB,
        idp_sub="9001",
    )
    binding = account_repository.issue_binding(account.account_id)
    assert binding.account_id == account.account_id
    assert binding.consumed_at is None
    assert binding.expires_at > binding.created_at

    consumed = account_repository.consume_binding(binding.binding_token)
    assert consumed.consumed_at is not None
    assert consumed.account_id == account.account_id


def test_consume_unknown_binding_raises(account_repository: AccountRepository) -> None:
    with pytest.raises(BindingTokenNotFoundError):
        account_repository.consume_binding("does-not-exist")


def test_consume_twice_raises(account_repository: AccountRepository) -> None:
    account = account_repository.create(
        account_id="acct-2",
        idp=IdentityProvider.GITHUB,
        idp_sub="2",
    )
    binding = account_repository.issue_binding(account.account_id)
    account_repository.consume_binding(binding.binding_token)
    with pytest.raises(BindingTokenConsumedError):
        account_repository.consume_binding(binding.binding_token)


def test_consume_expired_raises(account_repository: AccountRepository) -> None:
    account = account_repository.create(
        account_id="acct-3",
        idp=IdentityProvider.GITHUB,
        idp_sub="3",
    )
    # 1-millisecond TTL — guaranteed expired by the time we consume.
    binding = account_repository.issue_binding(
        account.account_id,
        ttl=timedelta(milliseconds=1),
    )
    time.sleep(0.01)
    with pytest.raises(BindingTokenExpiredError):
        account_repository.consume_binding(binding.binding_token)


def test_binding_tokens_are_distinct_per_call(account_repository: AccountRepository) -> None:
    account = account_repository.create(
        account_id="acct-4",
        idp=IdentityProvider.GITHUB,
        idp_sub="4",
    )
    a = account_repository.issue_binding(account.account_id)
    b = account_repository.issue_binding(account.account_id)
    assert a.binding_token != b.binding_token
