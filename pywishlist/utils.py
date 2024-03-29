#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import yaml
import logging
import sqlalchemy
import textwrap
import smtplib
import time
import datetime
from bs4 import BeautifulSoup

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage

from pywishlist.database import db_session


class YamlConfig (object):
    def __init__(self, filename=None):
        self.filename = filename
        self.values = {}
        if filename:
            self.load()

    def load(self):
        f = open(self.filename)
        self.values = yaml.safe_load(f)
        f.close()

    def get_values(self):
        return self.values

    def set_values(self, values):
        self.values = values


def timestampToString(ts):
    return datetime.datetime.fromtimestamp(int(ts)).strftime('%d.%m.%Y '
                                                             '%H:%M:%S')


def get_short_age(timestamp):
    return get_short_duration(time.time() - int(timestamp))


def get_short_duration(age):
    age = int(age)
    if age < 0:
        age = age * -1

    if age == 0:
        return ''
    elif age < 60:
        return '%ss' % (age)
    elif age > 59 and age < 3600:
        return '%sm' % (int(age / 60))
    elif age >= 3600 and age < 86400:
        return '%sh' % (int(age / 3600))
    elif age >= 86400 and age < 604800:
        return '%sd' % (int(age / 86400))
    elif age >= 604800 and age < 31449600:
        return '%sw' % (int(age / 604800))
    else:
        return '%sy' % (int(age / 31449600))


def get_long_age(timestamp):
    return get_long_duration(time.time() - int(timestamp))


def get_long_duration(age):
    intervals = (
        ('y', 31536000),  # 60 * 60 * 24 * 365
        ('w', 604800),  # 60 * 60 * 24 * 7
        ('d', 86400),    # 60 * 60 * 24
        ('h', 3600),    # 60 * 60
        ('m', 60),
        ('s', 1),
        )

    result = []

    for name, count in intervals:
        value = age // count
        if value:
            age -= value * count
            result.append("%s%s" % (int(value), name))
    return ' '.join(result)


# emailer functions
def load_image_file_to_email(app, msgRoot, filename):
    fp = open(os.path.join(app.root_path, 'static/img/', filename), 'rb')
    msgImage = MIMEImage(fp.read())
    newImageName = os.path.splitext(filename)[0]
    fp.close()
    msgImage.add_header('Content-Disposition', 'inline', filename=filename)
    msgImage.add_header('Content-ID', '<%s@pywishlist.local>' % (newImageName))
    msgRoot.attach(msgImage)
    return newImageName


def send_email(app, msgto, msgsubject, msgtext, image):
    try:
        msgRoot = MIMEMultipart('related', type="text/html")
        msgRoot['Subject'] = msgsubject
        msgRoot['From'] = app.config['EMAILFROM']
        msgRoot['To'] = msgto
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        if len(app.config['EMAILREPLYTO']):
            msgRoot.add_header('reply-to', app.config['EMAILREPLYTO'])
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)

        htmltext = """<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <title>%s</title>
        <style type="text/css" media="screen">
            body {
                margin: 0px;
                padding: 0px;
            }
            #background {
                left: 0px;
                top: 0px;
                position: relative;
                margin-left: auto;
                margin-right: auto;
                width: 601px;
                height: 500px;
                overflow: hidden;
                z-index:0;
            }
            #logo {
                left: 0px;
                top: 0px;
                position: absolute;
                width: 601px;
                height: 181px;
                z-index:2;
            }
            #content {
                top: 185px;
                width: 601px;
                position: absolute;
                font-size: x-large;
            }
            #footer {
                top: 480px;
                width: 601px;
                font-size: small;
                position: absolute;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <div id="background">
            <div id="logo"><img src="cid:%s@pywishlist.local"
                alt="Header Image"></div>
            <div id="content">%s</div>
            <div id="footer">PyWishlist <a
                href="https://github.com/oxivanisher/PyWishlist">github.com/oxivanisher/PyWishlist</a></div>
        </div>
    </body>
    </html>""" % (msgsubject,
                  load_image_file_to_email(app, msgRoot, image),
                  msgtext.replace('\n', '<br>').replace('\r', '').encode('ascii', 'xmlcharrefreplace').decode("utf-8"))

        soup = BeautifulSoup(msgtext, features="html.parser")
        part1 = MIMEText(soup.get_text().replace('\n', '\r\n').encode('UTF-8'),
                         'plain',
                         'UTF-8')
        msgAlternative.attach(part1)

        part2 = MIMEText(htmltext.encode('UTF-8'),
                         'html',
                         'UTF-8')
        msgAlternative.attach(part2)

        s = smtplib.SMTP(app.config['EMAILSERVER'])
        if app.config['EMAILTLS']:
            s.starttls()
        if len(app.config['EMAILLOGIN']) and len(app.config['EMAILPASSWORD']):
            s.login(app.config['EMAILLOGIN'], app.config['EMAILPASSWORD'])
        s.sendmail(app.config['EMAILFROM'], msgto, msgRoot.as_string())
        s.quit()
        return True
    except Exception as e:
        print('Email ERROR: %s' % (str(e)))
        return False


# database functions
def runQuery(f, retry=30):
    def retryCheck(retry):
        waitForDbConnection()
        if not retry:
            logging.error("[Utils] DB query retries exeeded. "
                          "Raising exception.")
            raise

    while retry:
        retry -= 1
        try:
            logging.debug("[Utils] DB query successful")
            return f()
            # "break" if query was successful and return any results
        except sqlalchemy.exc.DBAPIError as e:
            if e.connection_invalidated:
                logging.warning("[Utils] DB connection invalidated: %s" % (e))
                db_session.rollback()
            retryCheck(retry)
        except sqlalchemy.exc.OperationalError as e:
            logging.warning("[Utils] DB OperationalError: %s" % (e))
            db_session.rollback()
            retryCheck(retry)
        except sqlalchemy.exc.IntegrityError as e:
            logging.warning("[Utils] DB IntegrityError: %s" % (e))
            db_session.rollback()
            retryCheck(retry)
        except sqlalchemy.exc.InterfaceError as e:
            logging.warning("[Utils] DB InterfaceError: %s" % (e))
            db_session.rollback()
            retryCheck(retry)
        except sqlalchemy.exc.InvalidRequestError as e:
            logging.warning("[Utils] DB InvalidRequestError: %s" % (e))
            db_session.rollback()
            retryCheck(retry)

        time.sleep(0.1)


def waitForDbConnection(maxTries=0):
    connected = False
    retryCount = 0
    while not connected:
        try:
            db_session.execute(sqlalchemy.text('select 1')).fetchall()
            connected = True
        except sqlalchemy.exc.OperationalError as e:
            retryCount += 1
            db_session.remove()
            time.sleep(0.1)
        except sqlalchemy.exc.SQLAlchemyError as e:
            retryCount += 1
            db_session.remove()
            time.sleep(0.1)

        if maxTries:
            if retryCount >= maxTries:
                logging.warning("[Utils] DB connection check unable to "
                                "connect to DB after %s tries." % retryCount)
                return False

    if retryCount:
        logging.warning("[Utils] DB connection check connected to DB after "
                        "%s tries." % retryCount)

    return True
