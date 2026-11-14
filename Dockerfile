# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY requirements.txt .
RUN python -m venv /opt/venv && /opt/venv/bin/pip install -r requirements.txt

FROM python:3.12-slim
ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN useradd --system --uid 10001 --home /app --shell /usr/sbin/nologin app
COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY --chown=app:app app ./app
COPY --chown=app:app migrations ./migrations
COPY --chown=app:app alembic.ini ./
USER app
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=2).status == 200 else 1)"
# --proxy-headers so rate limits and logs see the real client behind a reverse proxy; list the proxy's address.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*", "--workers", "2"]
