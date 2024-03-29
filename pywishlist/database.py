#!/usr/bin/env python
# -*- coding: utf-8 -*-
# http://pythoncentral.io/understanding-python-sqlalchemy-session/

import os
import sys
import logging
from flask import Flask

try:
    from sqlalchemy import create_engine, schema
    from sqlalchemy.orm import scoped_session, sessionmaker
    from sqlalchemy.ext.declarative import declarative_base
except ImportError:
    log.error("[System] Please install the sqlalchemy")
    sys.exit(2)

try:
    os.environ['PYWISHLIST_CFG']
except KeyError:
    os.environ['PYWISHLIST_CFG'] = "../dist/pywishlist.cfg.example"

dbapp = Flask(__name__)
dbapp.config.from_envvar('PYWISHLIST_CFG', silent=False)

engine = create_engine(dbapp.config['SQLALCHEMY_DATABASE_URI'])
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()


def init_db():
    # import all modules here that might define models so that
    # they will be registered properly on the metadata.  Otherwise
    # you will have to import them first before calling init_db()
    import pywishlist.models
    Base.metadata.create_all(bind=engine)


def clear_db():
    # import all modules here that might define models so that
    # they will be registered properly on the metadata.  Otherwise
    # you will have to import them first before calling init_db()
    import pywishlist.models
    Base.metadata.drop_all(bind=engine)

# def get_db_tables():
#     return Base.metadata.reflect(bind=engine)
