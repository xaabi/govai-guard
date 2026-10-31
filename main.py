import os
import secrets
from typing import Literal

from fastapi import FastAPI, HTTPException, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field

from masking import mask_pribadi_data

_API_KEY_ENV = "GOVAI_API_KEY"
_api_key_header = APIKeyHeader(
    name="X-API-Key",
    scheme_name="APIKey",
    auto_error=False,
)


def require_api_key(api_key: str | None = Security(_api_key_header)) -> None:
    configured_api_key = os.getenv(_API_KEY_ENV)
    if configured_api_key is None or not configured_api_key.strip():
        raise HTTPException(
            status_code=503,
            detail="API key authentication is not configured.",
        )

    if api_key is None or not secrets.compare_digest(
        api_key.encode("utf-8"),
        configured_api_key.encode("utf-8"),
    ):
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")


app = FastAPI(
    title="GovAI-Guard: Enterprise RAG & Compliance API",
    description=(
        "API Gateway dengan pelindungan privasi data UU PDP dan Secure RAG Pipeline. "
        "Endpoint query memerlukan header X-API-Key dari GOVAI_API_KEY."
    ),
    version="2.0",
)

INTERNAL_SOP_DOCS = {
    "keamanan": "SOP Kebijakan Keamanan Data: Setiap data karyawan, NIK, dan nomor HP wajib di-masking sesuai UU PDP No. 27/2022 sebelum diakses oleh model AI.",
    "cuti": "SOP SDM: Pengajuan cuti karyawan wajib melalui portal HR paling lambat 3 hari sebelumnya.",
}


class QueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(min_length=1, max_length=100)
    query_text: str = Field(min_length=1, max_length=4000)


class QueryResponse(BaseModel):
    status: Literal["SUCCESS"]
    governed_by: str
    ai_final_response: str


@app.get("/")
def home():
    return {"status": "Active", "system": "GovAI-Guard Gateway & Secure RAG Online"}


@app.post(
    "/api/v1/secure-rag-query",
    response_model=QueryResponse,
    dependencies=[Security(require_api_key)],
)
@app.post(
    "/api/v1/secure-query",
    response_model=QueryResponse,
    dependencies=[Security(require_api_key)],
)
def secure_rag_query(data: QueryRequest) -> QueryResponse:
    sanitized_query = mask_pribadi_data(data.query_text)
    query_lower = sanitized_query.lower()
    retrieved_context = (
        INTERNAL_SOP_DOCS["keamanan"]
        if "data" in query_lower or "nik" in query_lower
        else INTERNAL_SOP_DOCS["cuti"]
    )
    response_text = (
        "Pertanyaan keamanan diproses dengan merujuk SOP internal."
        if retrieved_context == INTERNAL_SOP_DOCS["keamanan"]
        else "Pertanyaan cuti diproses dengan merujuk SOP internal."
    )

    return QueryResponse(
        status="SUCCESS",
        governed_by="UU PDP No. 27/2022 & Enterprise AI Governance",
        ai_final_response=response_text,
    )