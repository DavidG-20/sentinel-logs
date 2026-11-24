---
name: siem-seguro
description: Reglas de diseño, parsing seguro de logs y prevención de XSS/DoS para sentinel-logs.
---

# Reglas de Mini-SIEM Seguro

- Carga reglas YAML únicamente con `yaml.safe_load()`.
- Limita el tamaño máximo de logs enviados por la API web (`<= 2 MB`) para evitar denegación de servicio (DoS).
- Escapa siempre cualquier fragmento de log (`sample_line`, `detail`, `source_ip`) antes de mostrarlo en el Dashboard web (los logs analizados contienen payloads `<script>` y SQLi reales).
- Sanitiza las celdas CSV que empiecen por `=`, `+`, `-`, `@`.
- En los logs de ejemplo (`samples/`), usa exclusivamente IPs de documentación RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
