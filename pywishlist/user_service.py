from pywishlist.models import WishUser
from pywishlist.utils import runQuery

from flask import logging

log = logging.getLogger(__name__)


def get_user_by_id(user_id):
    return runQuery(WishUser.query.filter_by(id=user_id).first)


def get_active_users():
    users = WishUser.query.filter_by(veryfied=True, locked=False).all()
    return sorted(users, key=lambda x: x.name, reverse=False)
