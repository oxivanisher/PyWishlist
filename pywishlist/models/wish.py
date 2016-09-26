#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import time

from sqlalchemy import Boolean, Column, Integer, String, UnicodeText
from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship, backref

from pywishlist.utils import *
from pywishlist.database import db_session, Base


class Wish(Base):
    __tablename__ = 'wish'

    id = Column(Integer, primary_key=True)
    sourceId = Column(Integer, ForeignKey('user.id'))
    source = relationship(
        'WishUser',
        foreign_keys=[sourceId],
        backref=backref('source', lazy='dynamic'))
    creationDate = Column(Integer, unique=False)
    destinationId = Column(Integer, ForeignKey('user.id'))
    destination = relationship(
        'WishUser',
        foreign_keys=[destinationId],
        backref=backref('destination', lazy='dynamic'))
    hiddenId = Column(Integer, ForeignKey('user.id'))
    hiddenBy = relationship(
        'WishUser',
        foreign_keys=[hiddenId],
        backref=backref('hiddenby', lazy='dynamic'))
    hiddenDate = Column(Integer, unique=False)
    text = Column(String(512), unique=False)

    def __init__(self, sourceId, destinationId, text):
        self.log = logging.getLogger(__name__)
        self.log.debug("[Wish] Initializing Wish %s" % (self.id))
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
