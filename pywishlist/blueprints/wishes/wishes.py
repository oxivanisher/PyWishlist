from gettext import gettext

from flask import Blueprint, render_template
from flask import flash
from flask import logging
from flask import redirect
from flask import request
from flask import session
from flask import url_for

from pywishlist.blueprints.wishes.wishes_service import WishesService
from pywishlist.login_required import login_required
from pywishlist.models.wish import Wish
from pywishlist.user_service import get_user_by_id

log = logging.getLogger(__name__)

wishes_blueprint = Blueprint('wishes_blueprint', __name__, template_folder='templates')


@wishes_blueprint.route('/Wish/Enter', methods=['POST'])
@login_required
def enter_wish_post():
    new_wish = Wish(session.get('userid'),
                    request.form['userid'],
                    request.form['text'])

    WishesService.add_wish(new_wish)
    return render_template('enter_wish.html')


@wishes_blueprint.route('/Wish/Enter', methods=['GET'])
@login_required
def enter_wish():
    return render_template('enter_wish.html')


@wishes_blueprint.route('/Wishlists/Show/<int:user_id>', methods=['GET'])
@login_required
def show_wishes(user_id):
    active_wishes = WishesService.get_all_active_wishes_for_user_id(user_id)
    hidden_wishes = WishesService.get_all_hidden_wishes_for_user_id(user_id, session.get('userid'))

    total_wish_count = len(active_wishes) + len(hidden_wishes)
    if total_wish_count == 0:
        flash(gettext("No wishes found."), 'info')

    log.info("Found %s wishes for user %s" % (total_wish_count, user_id))
    return render_template('show_wishes.html',
                           wishes=active_wishes,
                           hiddenWishes=hidden_wishes,
                           user=get_user_by_id(user_id))


@wishes_blueprint.route('/Wish/Hide/<int:wish_id>/<int:user_id>', methods=['GET'])
@login_required
def hide_wish(wish_id, user_id):
    WishesService.hide_wish_by_id(wish_id, hidden_by_user_id=session.get('userid'))

    return redirect(url_for('wishes_blueprint.show_wishes', user_id=user_id))
