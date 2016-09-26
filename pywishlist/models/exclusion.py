#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging

from sqlalchemy import Boolean, Column, Integer, String, UnicodeText
from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship, backref

from pywishlist.utils import *
from pywishlist.database import db_session, Base


class Exclusion(Base):
    __tablename__ = 'exclusion'

    id = Column(Integer, primary_key=True)
    userIdA = Column(Integer, ForeignKey('user.id'))
    userA = relationship(
        'WishUser',
        foreign_keys=[userIdA],
        backref=backref('userA', lazy='dynamic'))
    userIdB = Column(Integer, ForeignKey('user.id'))
    userB = relationship(
        'WishUser',
        foreign_keys=[userIdB],
        backref=backref('userB', lazy='dynamic'))

    def __init__(self, userIdA, userIdB):
        self.log = logging.getLogger(__name__)
        self.log.debug("[Exclusion] Initializing exclusion %s - %s" % (userIdA,
                                                                       userIdB))
        self.userIdA = userIdA
        self.userIdB = userIdB

    def __repr__(self):
        return '<Exclusion %r (%s - %s)>' % (self.id,
                                             self.userIdA,
                                             self.userIdB)

    def check(self, userIdA, userIdB):
        if userIdA == self.userIdA and userIdB == self.userIdB:
            return True
        if userIdB == self.userIdA and userIdA == self.userIdB:
            return True

        return False
