FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends sqlite3 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dyndns.py config.py models.py auth.py forms.py web_routes.py getpwd.py rate_limiter.py health_checker.py ./
COPY lib/ lib/
COPY templates/ templates/
COPY static/ static/
COPY entrypoint.sh .

RUN addgroup --system app && adduser --system --ingroup app app

RUN mkdir -p /app/instance && chown app:app /app/instance
VOLUME /app/instance

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:80/health')"

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["gunicorn", "--bind", "0.0.0.0:80", "--workers", "2", "--timeout", "30", "--preload", "--access-logfile", "-", "--access-logformat", "%(h)s %(l)s %(u)s %(t)s \"%(m)s %(U)s %(H)s\" %(s)s %(b)s", "dyndns:create_app()"]
