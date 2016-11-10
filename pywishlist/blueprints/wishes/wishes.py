from gettext import gettext

from flask import Blueprint, render_template
from flask import flash
from flask import logging
from flask import redirect
from flask import request
from flask import session

from flask import url_for

from pywishlist.blueprints.wishes.wishes_service import get_wish_by_id
from pywishlist.database import db_session
from pywishlist.user_service import get_user_by_id
from pywishlist.utils import runQuery
from pywishlist.models.wish import Wish

log = logging.getLogger(__name__)

wishes_blueprint = Blueprint('wishes_blueprint', __name__, template_folder='templates')


@wishes_blueprint.route('/Wish/Enter', methods=['GET', 'POST'])
def enter_wish():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    if request.method == 'POST':
        new_wish = Wish(session.get('userid'),
                        request.form['userid'],
                        request.form['text'])

        db_session.add(new_wish)
        try:
            runQuery(db_session.commit)
        except Exception as e:
            log.warning("[Wish] SQL Alchemy Error on enter wish"
                        ": %s" % e)
            flash(gettext("The wish could not be saved"), 'error')
    return render_template('enter_wish.html')


@wishes_blueprint.route('/Wishlists/Show/<int:user_id>', methods=['GET'])
def show_wishes(user_id):
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    active_wishes = []
    hidden_wishes = []
    for wish in runQuery(Wish.query.all):
        if wish.destinationId == user_id:
            if wish.destinationId != session.get('userid'):
                # show wishes for anothe user
                if wish.hiddenId:
                    hidden_wishes.append(wish)
                else:
                    active_wishes.append(wish)
            elif wish.sourceId == session.get('userid'):
                # shwo wishes for the user himself
                if wish.hiddenId == session.get('userid'):
                    # check if the wish was hidden by the user himself,
                    # if it is hidden by someone else, don't show it
                    hidden_wishes.append(wish)
                else:
                    active_wishes.append(wish)

    if len(active_wishes) + len(hidden_wishes) == 0:
        flash(gettext("No wishes found."), 'info')

    log.info("Found %s wishes for user %s" % (len(active_wishes), user_id))
    return render_template('show_wishes.html',
                           wishes=active_wishes,
                           hiddenWishes=hidden_wishes,
                           user=get_user_by_id(user_id))


@wishes_blueprint.route('/Wish/Hide/<int:wish_id>/<int:user_id>', methods=['GET'])
def hide_wish(wish_id, user_id):
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    wish = get_wish_by_id(wish_id)

    try:
        wish.hide(session.get('userid'))
        db_session.merge(wish)
        log.info("Wish %s successfully hidden by %s"
                 % (wish.id, session.get('userid')))
    except Exception as e:
        flash(gettext("Unable to hide wish"), 'error')
        log.warning("Unable to hide wish because %s" % e)

    try:
        runQuery(db_session.commit)
    except Exception as e:
        log.warning("[Wish] SQL Alchemy Error on hide wish"
                    ": %s" % e)

    return redirect(url_for('wishes_blueprint.show_wishes', user_id=user_id))
