FROM tiangolo/uwsgi-nginx-flask:latest
VOLUME ["/app/pywishlist/static/img", "/app/config"]
ENV STATIC_URL /static
ENV STATIC_PATH /app/pywishlist/static
ENV PYWISHLIST_CFG /app/config/pywishlist.cfg
COPY ./requirements.txt /var/www/requirements.txt
# https://github.com/gliderlabs/docker-alpine/issues/181
RUN apt install -y libmariadb-dev default-libmysqlclient-dev &&\
    pip3 install mysqlclient
RUN apk add --no-cache build-base python-dev py-pip openssl-dev libffi-dev
ENV LIBRARY_PATH=/lib:/usr/lib
RUN pip install --upgrade pip && pip install -r /var/www/requirements.txt
COPY main.py /app/main.py
COPY config/ /app/config/
COPY pywishlist/ /app/pywishlist/
