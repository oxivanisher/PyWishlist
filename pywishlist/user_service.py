from pywishlist.models import WishUser
from pywishlist.utils import runQuery

from flask import logging

log = logging.getLogger(__name__)


def get_user_by_id(user_id):
    return runQuery(WishUser.query.filter_by(id=user_id).first)

def get_users():
    return runQuery(WishUser.query.all)
    # Fixme this is a duplicated method which is also available in the base __init__.py
    # Also check if it needs to be filtered
    # return runQuery(WishUser.query.filter(WishUser.veryfied.is_(True)).filter(WishUser.locked.is_(False)).all())
