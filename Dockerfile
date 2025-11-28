FROM python:3.11-slim as base
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential git curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

EXPOSE 8000

ENV PYTHONPATH=/app/src

CMD ["uvicorn", "api.fastapi_app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
