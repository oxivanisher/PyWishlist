from pywishlist.models.wish import Wish
from pywishlist.utils import runQuery


def get_wish_by_id(wish_id):
    return runQuery(Wish.query.filter_by(id=wish_id).first)
