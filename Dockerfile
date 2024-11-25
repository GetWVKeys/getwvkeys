FROM python:3.12.4-slim-bookworm AS base

ARG DEVELOPMENT

ENV DEVELOPMENT=${DEVELOPMENT} \
  PYTHONFAULTHANDLER=1 \
  PYTHONUNBUFFERED=1 \
  PYTHONHASHSEED=random \
  PIP_NO_CACHE_DIR=off \
  PIP_DISABLE_PIP_VERSION_CHECK=on \
  PIP_DEFAULT_TIMEOUT=100 \
  POETRY_NO_INTERACTION=1 \
  POETRY_VIRTUALENVS_CREATE=false \
  POETRY_CACHE_DIR='/var/cache/pypoetry' \
  POETRY_HOME='/usr/local' \
  POETRY_VERSION=1.8.3

RUN apt-get update && apt-get install -y --no-install-recommends curl build-essential libmariadb-dev-compat libmariadb-dev git
RUN curl -sSL https://install.python-poetry.org | python3 -

FROM base AS getwvkeys
WORKDIR /app

# Creating folders, and files for a project:
COPY . /app

# Project initialization:
RUN poetry install --no-interaction --no-ansi -E mariadb

ENTRYPOINT ["./entrypoint.sh"]