from gettext import gettext

from flask import Blueprint, render_template
from flask import flash
from flask import logging
from flask import redirect
from flask import request
from flask import session

from flask import url_for
from pywishlist.database import db_session
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
