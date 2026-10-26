FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_PATH=/data/portal.sqlite3

WORKDIR /app

RUN useradd --create-home --uid 10001 portal
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./
COPY config.py ./
COPY templates ./templates
COPY static ./static
RUN mkdir -p /data && chown portal:portal /data

USER portal
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]
