"""CLI entry point for sentinel-logs (Typer + Rich)."""

from dataclasses import asdict
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table
import typer
import uvicorn

from sentinel_logs.engine import analyze_log_text, export_alerts_csv
from sentinel_logs.models import AnalysisReport

app = typer.Typer(
    name="sentinel",
    help="Mini-SIEM defensivo: analiza logs SSH/Nginx con reglas YAML, correlación /24 y anomalías.",
    no_args_is_help=True,
)
console = Console()


def _render_report(report: AnalysisReport) -> None:
    console.print(
        f"\nLíneas analizadas: [bold]{report.total_lines}[/bold] | "
        f"IPs únicas: [bold]{report.unique_ips}[/bold] | "
        f"Alertas: [red bold]{report.high_count} HIGH[/red bold], "
        f"[yellow bold]{report.medium_count} MEDIUM[/yellow bold], "
        f"[cyan]{report.low_count} LOW[/cyan]"
    )
    if not report.alerts:
        console.print("[bold green]✔ Sin alertas de seguridad detectadas.[/bold green]")
        return

    table = Table(title="Alertas SOC detectadas")
    table.add_column("Severidad", style="bold")
    table.add_column("Regla", style="cyan")
    table.add_column("Título", style="bold")
    table.add_column("IP Origen")
    table.add_column("Subred /24")
    table.add_column("Detalle")

    colors = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}
    for a in report.alerts:
        c = colors.get(a.severity, "white")
        table.add_row(
            f"[{c}]{a.severity}[/{c}]",
            a.rule_id,
            a.title,
            a.source_ip,
            a.subnet_24,
            a.detail,
        )
    console.print(table)


@app.command("analyze")
def analyze_file(
    logfile: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
        help="Archivo de log (Nginx/Apache o SSH auth.log) a analizar.",
    ),
    rules: Path | None = typer.Option(None, "--rules", "-r", help="Archivo YAML personalizado de reglas."),
    json_out: Path | None = typer.Option(None, "--json-out", help="Exportar reporte completo a JSON."),
    csv_out: Path | None = typer.Option(None, "--csv-out", help="Exportar alertas a CSV (Excel)."),
) -> None:
    """Analiza un archivo de log y genera alertas correlacionadas."""
    log_text = logfile.read_text(encoding="utf-8", errors="replace")
    report = analyze_log_text(log_text, rules_path=rules)
    _render_report(report)

    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(asdict(report), indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"[dim]Reporte JSON guardado en {json_out}[/dim]")

    if csv_out:
        csv_out.parent.mkdir(parents=True, exist_ok=True)
        csv_out.write_text(export_alerts_csv(report), encoding="utf-8")
        console.print(f"[dim]Alertas CSV guardadas en {csv_out}[/dim]")

    if report.high_count > 0:
        raise typer.Exit(code=1)


@app.command("web")
def run_web(
    host: str = typer.Option("127.0.0.1", "--host", help="Dirección de escucha."),
    port: int = typer.Option(8000, "--port", help="Puerto HTTP."),
) -> None:
    """Levanta el Dashboard SOC web de sentinel-logs."""
    console.print(f"[cyan]Iniciando sentinel-logs SOC Dashboard en http://{host}:{port}[/cyan]")
    uvicorn.run("sentinel_logs.web:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    app()
