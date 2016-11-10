from pywishlist.models import WishUser
from pywishlist.utils import runQuery

from flask import logging

log = logging.getLogger(__name__)


def get_user_by_id(user_id):
    return runQuery(WishUser.query.filter_by(id=user_id).first)
