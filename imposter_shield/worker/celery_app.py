"""Celery application factory.

The broker and result backend both default to Redis on localhost. Override with
  ISHLD_CELERY_BROKER_URL and ISHLD_CELERY_RESULT_BACKEND env vars.

Workers are started separately:
  celery -A imposter_shield.worker.celery_app worker --loglevel=info

The FastAPI process never imports celery unless tasks are actually submitted, so
the app boots fine with no Redis present (tasks are enqueued only when a suspect
is created through the API and a broker is available).
"""
from __future__ import annotations

import os

from celery import Celery

broker  = os.environ.get("ISHLD_CELERY_BROKER_URL",  "redis://localhost:6379/0")
backend = os.environ.get("ISHLD_CELERY_RESULT_BACKEND", "redis://localhost:6379/1")

celery_app = Celery(
    "imposter_shield",
    broker=broker,
    backend=backend,
    include=["imposter_shield.worker.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,           # don't ack until the task finishes — safe retry on crash
    worker_prefetch_multiplier=1,  # one task at a time; face-match is CPU-heavy
    task_soft_time_limit=120,      # 2 min: should be plenty for a single candidate
    task_time_limit=180,
)
