# sentinel-logs — Mini-SIEM Analizador de Logs de Seguridad

Herramienta defensiva de **Ciberseguridad (Blue Team / SOC)** en Python que analiza logs de servidores (**SSH** y **Nginx/Apache**) usando **reglas YAML configurables**, correlación de ataques coordinados por **subred `/24`**, detección estadística de **picos anómalos de tráfico**, CLI, **Dashboard SOC web** y **Docker**.

## Qué detecta automáticamente

1. **Ataques Web (reglas YAML editables en `default_rules.yaml`)**:
   - **SQL Injection** (`UNION SELECT`, `' OR 1=1`, `SLEEP(`) → `HIGH`
   - **Cross-Site Scripting / XSS** (`<script>`, `onerror=`, `javascript:`) → `HIGH`
   - **Path Traversal** (`../`, `/etc/passwd`) → `HIGH`
   - **Reconocimiento / Escaneo** (`/.env`, `/.git/`, `/wp-admin`, `/phpmyadmin`) → `MEDIUM`
2. **Fuerza bruta SSH (`SSH-BRUTE-001`)**:
   - Correlaciona intentos `Failed password` / `Invalid user` por IP y dispara alerta `HIGH` al superar el umbral configurado.
3. **Correlación por subred `/24` (`NET-SUBNET-001`)**:
   - Agrupa IPs atacantes por su red `/24` para detectar campañas coordinadas desde el mismo bloque de red.
4. **Detección estadística de anomalías (`ANOM-SPIKE-001`)**:
   - Calcula media y desviación estándar de peticiones por IP y alerta cuando una IP supera el umbral dinámico (`media + 2σ`).

## Arquitectura

```text
sentinel-logs/
├── .agents/skills/siem-seguro/          # Reglas de parsing seguro y prevención XSS/DoS
├── AGENTS.md                            # Reglas del proyecto
├── Dockerfile & docker-compose.yml      # Despliegue en contenedor
├── samples/
│   ├── sample_nginx.log                 # Log sintético Nginx (IPs RFC 5737)
│   └── sample_ssh.log                   # Log sintético SSH (IPs RFC 5737)
├── src/sentinel_logs/
│   ├── rules/default_rules.yaml         # Reglas YAML cargadas con yaml.safe_load
│   ├── models.py                        # Dataclasses tipados
│   ├── engine.py                        # Motor SIEM, correlación /24, anomalías y CSV
│   ├── main.py                          # CLI (Typer + Rich)
│   ├── web.py                           # API FastAPI + cabeceras de seguridad + límite 2 MB
│   └── static/index.html                # Dashboard SOC (con escapeHtml contra XSS)
└── tests/
    └── test_siem.py                     # Pruebas del motor SIEM y API SOC
```

## Instalación

```bash
git clone https://github.com/DavidG-20/sentinel-logs.git
cd sentinel-logs
uv sync
```

## Uso rápido

```bash
# 1. Analizar el log de ejemplo Nginx desde consola
uv run sentinel analyze samples/sample_nginx.log --csv-out alertas.csv

# 2. Analizar el log de ejemplo SSH
uv run sentinel analyze samples/sample_ssh.log

# 3. Abrir el Dashboard SOC en el navegador (http://127.0.0.1:8000)
uv run sentinel web
```

### Con Docker
```bash
docker compose up --build
```

## Ejecutar pruebas

```bash
uv run pytest -v
```

## Licencia

MIT
