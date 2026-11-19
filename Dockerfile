FROM python:3.12-alpine

ENV PYTHONUNBUFFERED=1 \
    PORT=8080 \
    TZ=UTC

WORKDIR /app

# Install tzdata for local TZ 3:00 AM backups and create non-root UID 1000 user
RUN apk add --no-cache tzdata && \
    addgroup -g 1000 journalgroup && \
    adduser -u 1000 -G journalgroup -s /bin/sh -D journaluser && \
    mkdir -p /app/data /app/public /app/quizzes

COPY server.py /app/
COPY public /app/public
COPY quizzes /app/quizzes

RUN chown -R journaluser:journalgroup /app

USER journaluser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python3 -c 'import os, urllib.request; port = os.environ.get("PORT", "8080"); urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health")' || exit 1

CMD ["python3", "server.py"]
