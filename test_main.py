import pytest
from fastapi.testclient import TestClient

from main import app
from masking import mask_pribadi_data

client = TestClient(app)
API_HEADERS = {"X-API-Key": "test-api-key"}


@pytest.fixture(autouse=True)
def configure_test_api_key(monkeypatch):
    monkeypatch.setenv("GOVAI_API_KEY", API_HEADERS["X-API-Key"])


def test_masking_pii_nik_and_phone():
    sample_input = (
        "Karyawan dengan NIK 3171234567890001 dan HP +62 812-3456-7890."
    )
    masked_output = mask_pribadi_data(sample_input)

    assert "3171234567890001" not in masked_output
    assert "+62 812-3456-7890" not in masked_output
    assert "[REDACTED_NIK_UU_PDP]" in masked_output
    assert "[REDACTED_PHONE_UU_PDP]" in masked_output


def test_api_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "Active"


def test_secure_rag_endpoint_does_not_echo_user_input_or_internal_context():
    payload = {
        "user_id": "auditor_01",
        "query_text": "Tolong periksa data keamanan NIK 3171234567890001.",
    }
    response = client.post(
        "/api/v1/secure-rag-query",
        json=payload,
        headers=API_HEADERS,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert payload["query_text"] not in response.text
    assert "3171234567890001" not in response.text
    assert "SOP Kebijakan Keamanan Data" not in response.text
    assert "original_query" not in data
    assert "retrieved_internal_context" not in data


def test_query_request_rejects_oversized_input_and_unexpected_fields():
    oversized_response = client.post(
        "/api/v1/secure-query",
        json={"user_id": "auditor_01", "query_text": "x" * 4001},
        headers=API_HEADERS,
    )
    unexpected_field_response = client.post(
        "/api/v1/secure-query",
        json={
            "user_id": "auditor_01",
            "query_text": "Pertanyaan",
            "extra": "unexpected",
        },
        headers=API_HEADERS,
    )

    assert oversized_response.status_code == 422
    assert unexpected_field_response.status_code == 422


def test_query_endpoint_requires_a_configured_valid_api_key(monkeypatch):
    payload = {"user_id": "auditor_01", "query_text": "Pertanyaan"}
    endpoint = "/api/v1/secure-query"

    monkeypatch.delenv("GOVAI_API_KEY")
    unconfigured_response = client.post(
        endpoint,
        json=payload,
        headers=API_HEADERS,
    )
    monkeypatch.setenv("GOVAI_API_KEY", API_HEADERS["X-API-Key"])
    missing_key_response = client.post(endpoint, json=payload)
    invalid_key_response = client.post(
        endpoint,
        json=payload,
        headers={"X-API-Key": "wrong-key"},
    )
    valid_key_response = client.post(endpoint, json=payload, headers=API_HEADERS)

    assert unconfigured_response.status_code == 503
    assert missing_key_response.status_code == 401
    assert invalid_key_response.status_code == 401
    assert valid_key_response.status_code == 200
