from pywishlist.database import db_session
from pywishlist.models.wish import Wish
from pywishlist.utils import runQuery


class WishesService:
    def __init__(self):
        pass

    @staticmethod
    def get_wish_by_id(wish_id):
        return runQuery(Wish.query.filter_by(id=wish_id).first)

    @staticmethod
    def hide_wish_by_id(wish_id, hidden_by_user_id):
        wish = WishesService.get_wish_by_id(wish_id)
        wish.hide(hidden_by_user_id)
        runQuery(db_session.commit)

    @staticmethod
    def get_all_active_wishes_for_user_id(destination_user_id):
        return runQuery(Wish.query.filter_by(destinationId=destination_user_id).filter_by(hiddenId=None).all)

    @staticmethod
    def get_all_hidden_wishes_for_user_id(destination_user_id, current_user_id):
        if destination_user_id == current_user_id:
            return runQuery(
                Wish.query.filter_by(destinationId=destination_user_id).filter_by(hiddenId=current_user_id).all)
        else:
            return runQuery(
                Wish.query.filter_by(destinationId=destination_user_id).filter(Wish.hiddenId.isnot(None)).all)

    @staticmethod
    def add_wish(new_wish):
        db_session.add(new_wish)
        runQuery(db_session.commit)
