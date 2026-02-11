FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd -g 10001 cortex && useradd -m -u 10001 -g cortex -s /usr/sbin/nologin cortex

WORKDIR /workspace

COPY . /tmp/cortexsec
RUN pip install --no-cache-dir /tmp/cortexsec && rm -rf /tmp/cortexsec

USER 10001:10001

ENTRYPOINT ["cortexsec"]
