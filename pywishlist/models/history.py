#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging

from sqlalchemy import Boolean, Column, Integer, String, UnicodeText
from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship, backref

from pywishlist.utils import *
from pywishlist.database import db_session, Base


class History(Base):
    __tablename__ = 'history'

    id = Column(Integer, primary_key=True)
    donatorId = Column(Integer, ForeignKey('user.id'))
    donator = relationship(
        'WishUser',
        foreign_keys=[donatorId],
        backref=backref('donator', lazy='dynamic'))
    recieverId = Column(Integer, ForeignKey('user.id'))
    reciever = relationship(
        'WishUser',
        foreign_keys=[recieverId],
        backref=backref('reciever', lazy='dynamic'))
    date = Column(Integer, unique=False)

    def __init__(self, donatorId, recieverId):
        self.log = logging.getLogger(__name__)
        self.log.debug("[History] Initializing history %s - %s" % (donatorId,
                                                                   recieverId))
        self.donatorId = donatorId
        self.recieverId = recieverId
        self.date = int(time.time())

    def __repr__(self):
        return '<History %r (%s - %s)>' % (self.id,
                                           self.donatorId,
                                           self.recieverId)
