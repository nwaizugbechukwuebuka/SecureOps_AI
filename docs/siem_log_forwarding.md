# SIEM & External Log Forwarding

## Overview
SecureOps now supports forwarding logs to external SIEM and monitoring platforms, including ELK/Elasticsearch, Datadog, and syslog. This enables real-time log aggregation, security monitoring, and compliance reporting in enterprise environments.

## Requirements

- Python dependencies:
  - `structlog` (already required)
  - `sentry-sdk` (already required)
  - `cmreslogging` (for ELK/Elasticsearch log forwarding)
  - `datadog` (for Datadog log forwarding)

Add these to your environment:
```sh
pip install cmreslogging datadog
```

Or add to `requirements.txt`:
```
cmreslogging
cmreslogging[elastic6]  # If using Elasticsearch 6+
datadog
```

## Configuration

Set the following environment variables (or add to your `.env` file) to enable and configure log forwarding:

### ELK / Elasticsearch
- `LOG_FORWARD_ELK_ENABLED=true`
- `LOG_FORWARD_ELK_HOST=<elk_host>`
- `LOG_FORWARD_ELK_PORT=<elk_port>`

### Datadog
- `LOG_FORWARD_DATADOG_ENABLED=true`
- `LOG_FORWARD_DATADOG_API_KEY=<your_datadog_api_key>`

### Syslog
- `LOG_FORWARD_SYSLOG_ENABLED=true`
- `LOG_FORWARD_SYSLOG_HOST=<syslog_host>`
- `LOG_FORWARD_SYSLOG_PORT=<syslog_port>`

## How It Works
- When enabled, SecureOps will automatically add the appropriate log handler(s) at startup.
- All logs (including security, audit, and performance logs) will be forwarded to the configured external sink(s).
- If a handler fails to initialize, a warning will be logged to the console and file.

## Example `.env` for SIEM Integration
```
LOG_FORWARD_ELK_ENABLED=true
LOG_FORWARD_ELK_HOST=elk.example.com
LOG_FORWARD_ELK_PORT=9200

LOG_FORWARD_DATADOG_ENABLED=true
LOG_FORWARD_DATADOG_API_KEY=your_datadog_api_key

LOG_FORWARD_SYSLOG_ENABLED=true
LOG_FORWARD_SYSLOG_HOST=syslog.example.com
LOG_FORWARD_SYSLOG_PORT=514
```

## Troubleshooting
- Ensure all required Python packages are installed in your environment.
- Check logs for errors about handler initialization.
- For ELK, ensure the Elasticsearch host/port is reachable from the backend.
- For Datadog, ensure your API key is valid and the agent is running if required.
- For syslog, ensure the syslog server is reachable and accepting remote logs.

## References
- [cmreslogging documentation](https://github.com/cmanaha/python-elasticsearch-logger)
- [Datadog Python logging](https://docs.datadoghq.com/logs/log_collection/python/)
- [Python SysLogHandler docs](https://docs.python.org/3/library/logging.handlers.html#sysloghandler)

---

For more details, see `src/api/utils/logger.py` and `src/api/utils/config.py`.
