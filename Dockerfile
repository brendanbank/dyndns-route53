FROM tiangolo/uwsgi-nginx-flask:python3.12

COPY ./requirements.txt /app/requirements.txt
COPY ./dyndns.py /app/main.py
COPY ./lib /app/lib
COPY ./uwsgi.ini /app/uwsgi.ini
RUN unlink /var/log/nginx/access.log
RUN ln -s /dev/null /var/log/nginx/access.log 


RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

