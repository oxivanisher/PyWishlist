#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import time
import hashlib
import time
import string
import random

from sqlalchemy import Boolean, Column, Integer, String, UnicodeText, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship, backref

from pywishlist.utils import *
from pywishlist.database import db_session, Base

class Wish(Base):
    __tablename__ = 'wish'

    id = Column(Integer, primary_key=True)
    sourceId = Column(Integer, ForeignKey('user.id'))
    source = relationship('WishUser', backref=backref('links', lazy='dynamic'))
    creationDate = Column(Integer, unique=False)
    destination = relationship('WishUser', backref=backref('links', lazy='dynamic'))
    destinationId = Column(Integer, ForeignKey('user.id'))
    hiddenId = Column(Integer, ForeignKey('user.id'))
    hiddenBy = relationship('WishUser', backref=backref('links', lazy='dynamic'))
    hiddenDate = Column(Integer, unique=False)
    text = Column(String(512), unique=False)

    def __init__(self, sourceId, destinationId, text):
        self.log = logging.getLogger(__name__)
        self.log.debug("[User] Initializing Wish %s" % (self.id))
        self.sourceId = sourceId
        self.destinationId = destinationId
        self.hiddenId = None
        self.creationDate = int(time.time())
        self.hiddenDate = None
        self.text = text

    def __repr__(self):
        return '<Wish %r>' % self.id

    def hide(self, hiddenId):
        self.hiddenId = hiddenId
        self.hiddenDate = int(time.time())
