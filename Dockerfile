FROM python:3.11.9-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# System libs: curl for the container healthcheck; libGL/glib for opencv if you
# install the full ML stack.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl libglib2.0-0 libgl1 && rm -rf /var/lib/apt/lists/*

# Default to the lighter core set; swap to requirements.txt for full ML.
COPY requirements-core.txt .
RUN pip install -r requirements-core.txt

COPY imposter_shield ./imposter_shield
COPY seed.py example.py ./

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 appuser && chown -R appuser /app
USER appuser

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/api/healthz || exit 1

CMD ["uvicorn", "imposter_shield.api:app", "--host", "0.0.0.0", "--port", "8000"]
