FROM tiangolo/uwsgi-nginx-flask:latest
VOLUME ["/app/pywishlist/static/img", "/app/config"]
ENV STATIC_URL /static
ENV STATIC_PATH /app/pywishlist/static
ENV PYWISHLIST_CFG /app/config/pywishlist.cfg
COPY ./requirements.txt /var/www/requirements.txt
# https://github.com/gliderlabs/docker-alpine/issues/181
RUN apt install -y libmariadb-dev default-libmysqlclient-dev libssl-dev libffi-dev &&\
    pip3 install mysqlclient
ENV LIBRARY_PATH=/lib:/usr/lib
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r /var/www/requirements.txt
COPY main.py /app/main.py
COPY config/ /app/config/
COPY pywishlist/ /app/pywishlist/
