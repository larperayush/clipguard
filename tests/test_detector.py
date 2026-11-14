"""
Unit tests for the secret detector engine.
"""

from clipguard.detector import detect_secrets, calculate_shannon_entropy


def test_aws_key_detection():
    sample = "Deploying to AWS using AKIAIOSFODNN7EXAMPLE key"
    res = detect_secrets(sample)
    assert res.is_secret is True
    assert any(m.secret_type == "AWS Access Key" for m in res.matches)
    assert "AKIA" in res.masked_content
    assert "EXAMPLE" not in res.masked_content


def test_github_pat_detection():
    sample = "Here is my token: ghp_111122223333444455556666777788889999"
    res = detect_secrets(sample)
    assert res.is_secret is True
    assert any(m.secret_type == "GitHub Token" for m in res.matches)


def test_openai_key_detection():
    sample = "OPENAI_API_KEY=sk-proj-abcde12345ABCDE12345ABCDE12345abcde12345"
    res = detect_secrets(sample)
    assert res.is_secret is True
    assert any("OpenAI" in m.secret_type for m in res.matches)


def test_postgres_connection_detection():
    sample = "DATABASE_URL=postgres://admin:SuperSecretPass123@db.prod.internal:5432/maindb"
    res = detect_secrets(sample)
    assert res.is_secret is True
    assert any(m.secret_type == "Database Connection URL" for m in res.matches)


def test_safe_content():
    sample = "git commit -m 'feat: improve clipboard handling and tests'"
    res = detect_secrets(sample)
    assert res.is_secret is False
    assert len(res.matches) == 0
    assert res.masked_content == sample


def test_empty_content():
    assert detect_secrets("").is_secret is False
    assert detect_secrets("   ").is_secret is False


def test_entropy():
    # Low entropy repetitive string
    low = calculate_shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    # High entropy random string
    high = calculate_shannon_entropy("9F8aB7cD6eE1fA3bC5dE7fA9bC1dE3fA")
    assert high > low
