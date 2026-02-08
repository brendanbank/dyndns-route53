FROM tiangolo/uwsgi-nginx-flask:python3.12

COPY ./requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

COPY ./dyndns.py /app/main.py
COPY ./lib /app/lib
COPY ./uwsgi.ini /app/uwsgi.ini
RUN unlink /var/log/nginx/access.log && ln -s /dev/null /var/log/nginx/access.log
