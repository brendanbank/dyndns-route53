FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dyndns.py config.py models.py auth.py forms.py web_routes.py getpwd.py init_db.py migrate_env.py ./
COPY lib/ lib/
COPY templates/ templates/
COPY static/ static/

RUN mkdir -p /app/instance
VOLUME /app/instance

EXPOSE 80

CMD ["gunicorn", "--bind", "0.0.0.0:80", "--workers", "2", "--access-logfile", "-", "--access-logformat", "%(h)s %(l)s %(u)s %(t)s \"%(m)s %(U)s %(H)s\" %(s)s %(b)s", "dyndns:app"]
