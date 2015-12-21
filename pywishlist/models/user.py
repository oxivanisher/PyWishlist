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

class WishUser(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(20), unique=False)
    email = Column(String(120), unique=True)
    password = Column(String(512), unique=False)
    joinedDate = Column(Integer, unique=False)
    lastLoginDate = Column(Integer, unique=False)
    lastRefreshDate = Column(Integer, unique=False)
    verifyKey = Column(String(32), unique=False)
    admin = Column(Boolean)
    locked = Column(Boolean)
    veryfied = Column(Boolean)

    def __init__(self, email, name = None):
        self.log = logging.getLogger(__name__)
        self.name = name
        self.email = email
        self.log.debug("[User] Initializing WishUser %s" % self.getDisplayName())
        self.password = None
        self.linkedNetworks = []
        self.joinedDate = int(time.time())
        self.lastLoginDate = 0
        self.lastRefreshDate = 0
        self.admin = False
        self.locked = True
        self.veryfied = False
        self.verifyKey = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
        self.load()

    def __repr__(self):
        return '<WishUser %r>' % self.email

    def load(self):
        self.log = logging.getLogger(__name__)
        self.log.debug("[User] Loaded WishUser %s" % (self.getDisplayName()))

    def lock(self):
        self.log.debug("[User] Lock WishUser %s" % (self.getDisplayName()))
        self.locked = True

    def unlock(self):
        self.log.debug("[User] Unlock WishUser %s" % (self.getDisplayName()))
        self.locked = False

    def verify(self, key):
        if key == self.verifyKey:
            self.veryfied = True
            self.locked = False
            return True
        else:
            return False

    def getDisplayName(self):
        if self.name:
            return self.name + " (" + self.email + ")"
        else:
            return self.email

    def setPassword(self, password):
        self.log.info("[User] Setting new Password for WishUser %s" % (self.getDisplayName()))
        hash_object = hashlib.sha512(password)
        self.password = hash_object.hexdigest()

    def checkPassword(self, password):
        self.log.info("[User] Checking password for WishUser %s" % (self.getDisplayName()))
        hash_object = hashlib.sha512(password)
        if self.password == hash_object.hexdigest():
            return True
        else:
            return False
