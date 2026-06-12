FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# System libs for opencv/reportlab fonts if you install the full stack.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libglib2.0-0 libgl1 && rm -rf /var/lib/apt/lists/*

# Default to the lighter core set; swap to requirements.txt for full ML.
COPY requirements-core.txt .
RUN pip install -r requirements-core.txt

COPY imposter_shield ./imposter_shield
COPY seed.py example.py ./

EXPOSE 8000
CMD ["uvicorn", "imposter_shield.api:app", "--host", "0.0.0.0", "--port", "8000"]
