FROM tiangolo/uwsgi-nginx-flask:python3.6-alpine3.7
RUN apk --update add bash nano
VOLUME ["/app/pywishlist/static/img", "/app/config"]
ENV STATIC_URL /static
ENV STATIC_PATH /app/pywishlist/static
ENV PYWISHLIST_CFG /app/config/pywishlist.cfg
COPY ./requirements.txt /var/www/requirements.txt
# https://github.com/gliderlabs/docker-alpine/issues/181
RUN apk update &&\
    apk add python3 python3-dev mariadb-dev build-base &&\
    pip3 install mysqlclient &&\
    apk del python3-dev mariadb-dev build-base &&\
    apk add mariadb-client-libs
RUN apk add --no-cache build-base python-dev py-pip openssl-dev libffi-dev
ENV LIBRARY_PATH=/lib:/usr/lib
RUN pip install -r /var/www/requirements.txt
COPY main.py /app/main.py
COPY config/ /app/config/
COPY pywishlist/ /app/pywishlist/
