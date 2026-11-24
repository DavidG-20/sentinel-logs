# Reglas del proyecto `sentinel-logs`

- Stack: **Python 3.12+**, **`uv`**, **Typer**, **Rich**, **FastAPI**, **PyYAML** y biblioteca estándar (`re`, `ipaddress`, `statistics`).
- Código interno en **inglés técnico**; CLI, Dashboard SOC y `README.md` en **español**.
- Usa siempre `yaml.safe_load()` (nunca `yaml.load()`), escapa toda salida HTML con `escapeHtml` (los logs contienen payloads XSS reales) y sanitiza celdas CSV contra inyección de fórmulas.
- Consulta `.agents/skills/siem-seguro/SKILL.md` para reglas de detección y seguridad.
