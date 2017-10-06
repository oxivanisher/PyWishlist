#!/usr/bin/env python
# -*- coding: utf-8 -*-

from sqlalchemy import Column, Integer, String
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship, backref

from pywishlist.database import Base
from pywishlist.utils import *


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

    def __init__(self, source_id, destination_id, text, hidden_id=None):
        self.log = logging.getLogger(__name__)
        self.log.debug("[Wish] Initializing Wish %s" % self.id)
        self.sourceId = source_id
        self.destinationId = destination_id
        self.hiddenId = hidden_id
        self.creationDate = int(time.time())
        self.hiddenDate = None
        self.text = text

    def __repr__(self):
        return '<Wish %r>' % self.id

    def hide(self, hidden_id):
        self.hiddenId = hidden_id
        self.hiddenDate = int(time.time())

    def unhide(self):
        self.hiddenId = None
        self.hiddenDate = None

    def is_authorized_to_edit(self, user_id):
        return user_id == self.sourceId

    def is_authorized_to_unhide(self, user_id):
        return user_id == self.hiddenId
