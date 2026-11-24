"""FastAPI SOC Web API and Dashboard for sentinel-logs."""

from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from sentinel_logs import __version__
from sentinel_logs.engine import analyze_log_text, export_alerts_csv

STATIC_DIR = Path(__file__).parent / "static"
MAX_LOG_BYTES = 2 * 1024 * 1024  # 2 MiB DoS guard


def _resolve_samples_dir() -> Path:
    """Locate bundled sample logs both in editable dev mode and inside Docker (/app/samples)."""
    for candidate in (
        Path(__file__).resolve().parents[2] / "samples",
        Path.cwd() / "samples",
    ):
        if candidate.is_dir():
            return candidate
    return Path.cwd() / "samples"


SAMPLES_DIR = _resolve_samples_dir()

app = FastAPI(
    title="sentinel-logs SOC",
    version=__version__,
    description="Mini-SIEM defensivo: análisis de logs SSH/Nginx con reglas YAML, correlación /24 y anomalías.",
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


class AnalyzeRequest(BaseModel):
    log_text: str = Field(min_length=1)


def _check_size(text: str) -> None:
    if len(text.encode("utf-8")) > MAX_LOG_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="El log supera el límite máximo permitido de 2 MB.",
        )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "sentinel-logs", "version": __version__}


@app.get("/api/v1/samples/{sample_name}")
def get_sample_log(sample_name: str) -> dict[str, str]:
    """Return one of the bundled RFC 5737 synthetic sample logs."""
    allowed = {"nginx": "sample_nginx.log", "ssh": "sample_ssh.log"}
    filename = allowed.get(sample_name)
    if not filename:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Log de ejemplo no encontrado.")
    path = SAMPLES_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Archivo de ejemplo no disponible.")
    return {"name": sample_name, "log_text": path.read_text(encoding="utf-8")}


@app.post("/api/v1/analyze")
def api_analyze(payload: AnalyzeRequest) -> dict:
    _check_size(payload.log_text)
    report = analyze_log_text(payload.log_text)
    return asdict(report)


@app.post("/api/v1/analyze/csv")
def api_analyze_csv(payload: AnalyzeRequest) -> Response:
    _check_size(payload.log_text)
    report = analyze_log_text(payload.log_text)
    return Response(
        content=export_alerts_csv(report),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="alertas_soc.csv"'},
    )


@app.get("/", include_in_schema=False)
def serve_dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
