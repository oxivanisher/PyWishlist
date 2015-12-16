#!/usr/bin/env python
# -*- coding: utf-8 -*-

# imports
import sys
import os
import logging

from utils import *
from models import *
# from base import *

# logging to file
myPath = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../')
logPath = os.path.join(myPath, 'log/pywishlist.log')
logging.basicConfig(filename=logPath, format='%(asctime)s %(levelname)-7s %(message)s', datefmt='%Y-%d-%m %H:%M:%S', level=logging.INFO)

log = logging.getLogger(__name__)
log.info("[System] PyWishlist system is starting up")

# flask imports
try:
    from flask import Flask, request, session, g, redirect, url_for, abort, render_template, flash, make_response, send_from_directory, current_app, jsonify, Markup
except ImportError:
    log.error("[System] Please install flask")
    sys.exit(2)

try:
    from flask.ext.compress import Compress
except ImportError:
    log.error("[System] Please install the flask extension: Flask-Compress")
    sys.exit(2)

try:
    from flask.ext.babel import Babel, gettext
except ImportError:
    log.error("[System] Please install the babel extension for flask")
    sys.exit(2)

# load database
from pywishlist.database import db_session, init_db, engine

# setup flask app
app = Flask(__name__)

# setup logging
log = app.logger

Compress(app)
app.config['scriptPath'] = os.path.dirname(os.path.realpath(__file__))
app.config['startupDate'] = time.time()

try:
    os.environ['PYWISHLIST_CFG']
    log.info("[System] Loading config from: %s" % os.environ['PYWISHLIST_CFG'])
except KeyError:
    log.warning("[System] Loading config from dist/pywishlist.cfg.example becuase PYWISHLIST_CFG environment variable is not set.")
    os.environ['PYWISHLIST_CFG'] = "../dist/pywishlist.cfg.example"

try:
    app.config.from_envvar('PYWISHLIST_CFG', silent=False)
except RuntimeError as e:
    log.error(e)
    sys.exit(2)

with app.test_request_context():
    if app.debug:
        app.logger.setLevel(logging.DEBUG)
    else:
        app.logger.setLevel(logging.INFO)
        from logging.handlers import SMTPHandler
        mail_handler = SMTPHandler(app.config['EMAILSERVER'], app.config['EMAILFROM'], app.config['ADMINS'], current_app.name + ' failed!')
        mail_handler.setLevel(logging.ERROR)
        app.logger.addHandler(mail_handler)

# initialize stuff
app.config['networkConfig'] = YamlConfig(os.path.join(app.config['scriptPath'], "../config/pywishlist.yml")).get_values()
if not len(app.config['APPSECRET']):
    log.warning("[System] Generating random secret_key. All older cookies will be invalid, but i will NOT work with multiple processes (WSGI).")
    app.secret_key = os.urandom(24)
else:
    app.secret_key = app.config['APPSECRET']

# jinja2 methods
app.jinja_env.globals.update(timestampToString=timestampToString)
app.jinja_env.globals.update(get_short_duration=get_short_duration)
app.jinja_env.globals.update(get_short_age=get_short_age)

# initialize database
with app.test_request_context():
    init_db()
    babel = Babel(app)

# helper methods
def getUserByEmail(email = None):
    with app.test_request_context():
        try:
            ret = runQuery(WishUser.query.filter(WishUser.email.ilike(email)).first)
        except Exception as e:
            self.log.warning("[System] SQL Alchemy Error on getUserByEmail: %s" % (e))
            ret = False

        if ret:
            return ret
        else:
            return False

def checkPassword(password1, password2):
    valid = True
    if password1 != password2:
        flash(gettext("Passwords do not match!"), 'error')
        valid = False

    if len(password1) < 8:
        flash(gettext("Password is too short"), 'error')
        valid = False

    #and further checks for registration plz
    # - user needs to be uniq!
    # - minimal field length
    # - is the website a website?
    # - max length (cut oversize)
    return valid

# localization methods
@babel.localeselector
def get_locale():
    sessionLang = session.get('displayLanguage')
    if sessionLang:
        session['currentLocale'] = sessionLang
        return sessionLang
    else:
        browserLang = request.accept_languages.best_match(app.config['LANGUAGES'].keys())
        session['currentLocale'] = browserLang
        return browserLang

# flask error handlers
@app.errorhandler(400)
def error_bad_request(error):
    flash(gettext("Bad Request"), 'error')
    log.warning("[System] 400 Bad Request: %s" % (request.path))
    return redirect(url_for('index'))

@app.errorhandler(401)
def error_unauthorized_request(error):
    flash(gettext("Unauthorized request"), 'error')
    log.warning("[System] 401 Page not found: %s" % (request.path))
    return redirect(url_for('index'))

@app.errorhandler(403)
def error_forbidden_request(error):
    flash(gettext("Forbidden request"), 'error')
    log.warning("[System] 403 Page not found: %s" % (request.path))
    return redirect(url_for('index'))

@app.errorhandler(404)
def error_not_found(error):
    flash(gettext("Page not found"), 'error')
    log.warning("[System] 404 Page not found: %s" % (request.path))
    return redirect(url_for('index'))

@app.errorhandler(500)
def error_internal_server_error(error):
    flash(gettext("The server encountered an internal error, probably a bug in the program. The administration was automatically informed of this problem."), 'error')
    log.warning("[System] 500 Internal error: %s" % (request.path))
    return index()

# app routes
@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()


@app.before_request
def before_request():
    if not waitForDbConnection(20):
        return render_template('epic_fail.html')

    try:
        session['requests'] += 1
    except KeyError:
        session['requests'] = 0

    if session.get('logmeout') == True:
        log.warning("[System] Forcing logout of '%s' because '%s'" % (session.get('nick'), session.get('logmeoutreason')))
        session['logmeout'] = False
        session['logmeoutreason'] = False
        session.pop('logmeout', None)
        session.pop('logmeoutreason', None)
        return redirect(url_for('profile_logout'))

    if session.get('logged_in'):
        try:
            if time.time() - session.get('last_lock_check') > 300:
                log.debug("[System] Lock check for user '%s'" % (session.get('nick')))
                myUser = getUserById(session.get('userid'))
                if myUser.locked == True:
                    session['logmeout'] = True
                    session['logmeoutreason'] = "User is locked"
                if myUser.admin != session.get('admin'):
                    session['logmeout'] = True
                    session['logmeoutreason'] = "Admin rights changed"
                if myUser.nick != session.get('nick'):
                    session['logmeout'] = True
                    session['logmeoutreason'] = "Nickname changed"
                session['last_lock_check'] = time.time()
        except TypeError:
            session['logmeout'] = True
            session['logmeoutreason'] = "No last check value found"

@app.after_request
def add_header(response):
    response.cache_control.max_age = 2
    response.cache_control.min_fresh = 1
    return response

# main routes
@app.route('/About')
def about():
    return render_template('about.html')

@app.route('/Development')
def dev():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    if not session.get('admin'):
        log.warning("[System] <%s> tried to access admin without permission!")
        abort(403)
    ret = []
    return render_template('dev.html', result = ret)

# language route
@app.route('/Lang/')
@app.route('/Lang/<language>')
@app.route('/Lang/<language>/')
@app.route('/Lang/<language>/<path:path>')
def set_lang(language=None, path = None):
    if not path:
        path = request.script_root
    session['displayLanguage'] = language
    log.info("[System] Set lang to %s and redirect to %s" % (session['displayLanguage'], path))
    return redirect(path)

# support routes
@app.route('/favicon.ico')
def favicon():
    return redirect(url_for('static', filename=app.config['FAVICON']))

@app.route('/Images/<imgType>/', methods = ['GET', 'POST'])
@app.route('/Images/<imgType>/<imgId>', methods = ['GET', 'POST'])
def get_image(imgType, imgId = None):
    filePath = os.path.join(app.config['scriptPath'], 'static', imgType)
    fileName = ""
    log.debug("[System] Requesting img type <%s> id <%s>" % (imgType, imgId))

    try:
        if imgType == 'avatar':
            fileName = pywishlist[int(imgId)].avatar
        elif imgType == 'network':
            if imgId == 'System':
                fileName = app.config['SYSTEMLOGO']
                filePath = os.path.join(app.config['scriptPath'], 'static')
            elif imgId == 'OpenGraph':
                fileName = app.config['OPENGRAPHLOGO']
                filePath = os.path.join(app.config['scriptPath'], 'static')
            else:
                fileName = app.config['PLACEHOLDER']
                filePath = os.path.join(app.config['scriptPath'], 'static')
        elif imgType == 'cache':
            fileName = imgId
        elif imgType == 'flag':
            fileName = imgId + '.png'
        elif imgType == 'product':
            fileName = imgId + '.png'

        if os.path.isfile(os.path.join(filePath, fileName)):
            return send_from_directory(filePath, fileName)
        else:
            log.warning("[System] Image not found: %s/%s" % (filePath, fileName))

    except (IndexError, AttributeError, KeyError):
        log.warning("[System] Unknown ID for img type %s: %s" % (imgType, imgId))
    abort(404)

@app.route('/robots.txt')
def get_robots_txt():
    ret = []
    ret.append('User-agent: *')
    ret.append('Allow: /')
    ret.append('Sitemap: %s' % (url_for('get_sitemap_xml', _external=True)))
    return '\n'.join(ret)

@app.route('/sitemap.xml')
def get_sitemap_xml():
    methodsToList = [ 'index', 'about', 'profile_register', 'profile_login' ]
    ret = []
    ret.append('<?xml version="1.0" encoding="UTF-8"?>')
    ret.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')

    for method in methodsToList:
        ret.append('    <url>')
        ret.append('      <loc>%s</loc>' % (url_for(method, _external=True)))
        ret.append('    </url>')

    ret.append('</urlset>')
    return '\n'.join(ret)

# admin routes
def check_admin_permissions():
    if not session.get('logged_in'):
        abort(401)
    if not session.get('admin'):
        log.warning("[System] <%s> tried to access admin without permission!")
        abort(403)

@app.route('/Administration/User_Management')
def admin_user_management():
    registredUsers = []
    with app.test_request_context():
        try:
            users = runQuery(WishUser.query.all)
        except Exception as e:
            self.log.warning("[System] SQL Alchemy Error on Admin user management: %s" % (e))

        for user in users:
            registredUsers.append({ 'id': user.id,
                                    'nick': user.nick,
                                    'name': user.name,
                                    'email': user.email,
                                    'website': user.website,
                                    'admin': user.admin,
                                    'locked': user.locked,
                                    'veryfied': user.veryfied })

    infos = {}
    infos['registredUsers'] = registredUsers
    return render_template('admin_user_management.html', infos = infos)

@app.route('/Administration/User_Management/ToggleLock/<userId>')
def admin_user_management_togglelock(userId):
    check_admin_permissions()
    myUser = getUserById(userId)
    if myUser:
        myUser.load()
        myUser.locked = not myUser.locked
        log.info("[System] Lock state of '%s' was changed to: %s" % (myUser.nick, myUser.locked))
        db_session.merge(myUser)
        try:
            runQuery(db_session.commit)
        except Exception as e:
            self.log.warning("[System] SQL Alchemy Error on Admin toggle lock: %s" % (e))
    return redirect(url_for('admin_user_management'))

@app.route('/Administration/User_Management/ToggleAdmin/<userId>')
def admin_user_management_toggleadmin(userId):
    check_admin_permissions()
    if int(userId) != session.get('userid'):
        myUser = getUserById(userId)
        if myUser:
            myUser.load()
            myUser.admin = not myUser.admin
            log.info("[System] Admin state of '%s' was changed to: %s" % (myUser.nick, myUser.admin))
            db_session.merge(myUser)
        try:
            runQuery(db_session.commit)
        except Exception as e:
            self.log.warning("[System] SQL Alchemy Error on Admin toggle admin: %s" % (e))
    return redirect(url_for('admin_user_management'))

@app.route('/Administration/BulkEmail', methods = ['GET', 'POST'])
def admin_bulk_email():
    check_admin_permissions()
    retMessage = ""
    if request.method == 'POST':
        if request.form['message'] and request.form['subject']:
            okCount = 0
            nokCount = 0
            try:
                for user in runQuery(WishUser.query.all):
                    user.load()
                    if user.nick != "oxi":
                        continue
                    if send_email(app, user.email, request.form['subject'],
                        "<h3>%s %s</h3>" % (gettext("Hello"), user.nick) + request.form['message'] + gettext("<br><br>Have fun and see you soon ;)"),
                        app.config['EMAILBANNER']):
                        okCount += 1
                    else:
                        nokCount += 1
            except Exception as e:
                self.log.warning("[System] SQL Alchemy Error on Admin bulk email: %s" % (e))

            retMessage = gettext("Messages sent: %(okCount)s; Messages not sent: %(nokCount)s", okCount=okCount, nokCount=nokCount)

    return render_template('admin_bulk_email.html', retMessage = retMessage)

# profile routes
@app.route('/Profile/Register', methods=['GET', 'POST'])
def profile_register():
    if request.method == 'POST':
        if request.form['nick'] and \
            request.form['password'] and \
            request.form['password2'] and \
            request.form['email']:

            if len(request.form['nick']) < 3:
                flash(gettext("Nickname is too short"), 'error')
                valid = False
            else:
                valid = checkPassword(request.form['password'], request.form['password2'])

        else:
            valid = False
            flash(gettext("Please fill out all the fields!"), 'error')

        if valid:
            newUser = WishUser(request.form['nick'])
            newUser.email = request.form['email']
            newUser.name = request.form['name']
            if request.form['website'].startswith("http"):
                newUser.website = request.form['website']
            elif len(request.form['website']):
                newUser.website = "http://" + request.form['website']
            else:
                newUser.website = ""
            newUser.setPassword(request.form['password'])
            if request.form['nick'] == app.config['ROOTUSER']:
                log.info("[System] Registred root user: %s" % request.form['nick'])
                newUser.admin = True
                newUser.locked = False
                newUser.veryfied = True

            db_session.add(newUser)
            try:
                runQuery(db_session.commit)
                actUrl = url_for('profile_verify', userId=newUser.id, verifyKey=newUser.verifyKey, _external=True)
                if send_email(app, newUser.email,
                              gettext("PyWishlist Activation Email"),
                              "<h3>%s %s</h3>" % (gettext("Hello"), request.form['nick']) + gettext("We are happy to welcome you to PyWishlist!<br>Please verify your account with <a href='%(url)s'>this link</a>.<br><br><b>To remove the recurring message in Teamspeak, you have to connect yout TS3 user in the 'Network Connections' box.", url=actUrl) + gettext("<br><br>Have fun and see you soon ;)"),
                              app.config['EMAILBANNERWELCOME']):
                    flash(gettext("Please check your mails at %(emailaddr)s", emailaddr=newUser.email), 'info')
                else:
                    flash(gettext("Error sending the email to you."), 'error')
                # return redirect(url_for('profile_login'))
                return redirect(url_for('index'))

            except Exception as e:
                flash("%s: %s" % (gettext("SQL Alchemy Error"), e), 'error')
                log.warning("[System] SQL Alchemy Error: %s" % e)
            # db_session.expire(newUser)
    
    return render_template('profile_register.html', values = request.form)

@app.route('/Profile/Show', methods=['GET', 'POST'])
def profile_show(do = None):
    # gravatar: https://de.gravatar.com/site/implement/images/python/
    if not session.get('logged_in'):
        abort(401)
    myUser = getUserById(session.get('userid'))
    myUser.load()
    userChanged = False
    if request.method == 'POST':
        if request.form['do'] == "pwchange":
            if myUser.checkPassword(request.form['oldpassword']):
                if checkPassword(request.form['newpassword1'], request.form['newpassword2']):
                    myUser.setPassword(request.form['newpassword1'])
                    userChanged = True
            else:
                flash(gettext("Old password not correct!"), 'error')
        elif request.form['do'] == "editprofile":
            if request.form['website'].startswith("http"):
                myUser.website = request.form['website']
            else:
                myUser.website = "http://" + request.form['website']
            myUser.name = request.form['name']
            userChanged = True
    if userChanged:
        db_session.merge(myUser)
        try:
            runQuery(db_session.commit)
        except Exception as e:
            self.log.warning("[System] SQL Alchemy Error on profile show: %s" % (e))
        flash(gettext("Profile changed"), 'success')

    size = 80
    gravatar_url = "//www.gravatar.com/avatar/" + hashlib.md5(myUser.email.lower()).hexdigest() + "?"
    gravatar_url += urllib.urlencode({'d':url_for('static', filename=app.config['PLACEHOLDER'], _external=True), 's':str(size)})

    return render_template('profile_show.html', values = myUser, nicknames = myUser.nicks.all(), userAvatar = gravatar_url)

@app.route('/Profile/Verify/<userId>/<verifyKey>', methods=['GET'])
def profile_verify(userId, verifyKey):
    log.info("[System] Verify userid %s" % userId)
    verifyUser = getUserById(userId)
    if not verifyUser:
        flash(gettext("User not found to verify."))
    elif verifyUser.verify(verifyKey):
        db_session.merge(verifyUser)
        try:
            runQuery(db_session.commit)
        except Exception as e:
            self.log.warning("[System] SQL Alchemy Error on verify key: %s" % (e))
        if verifyUser.veryfied:
            flash(gettext("Verification ok. Please log in."), 'success')
            return redirect(url_for('index'))
        else:
            flash(gettext("Verification NOT ok. Please try again."), 'error')
    return redirect(url_for('index'))

@app.route('/Profile/Login', methods=['GET', 'POST'])
@app.route('/Login', methods=['GET', 'POST'])
def profile_login():
    if request.method == 'POST':
        log.info("[System] Trying to login user: %s" % request.form['nick'])
        myUser = False
        try:
            myUser = getUserByNick(request.form['nick'])
        except Exception as e:
            log.warning('[System] Error finding user: "%s" -> %s' % (request.form['nick'], e))
            flash(gettext('Error locating your user'), 'error')
            
            return redirect(url_for('profile_logout'))

        if myUser:
            myUser.load()
            if not myUser.veryfied:
                flash(gettext("User not yet verified. Please check your email for the unlock key."), 'info')
                return redirect(url_for('index'))
            elif myUser.locked:
                flash(gettext("User locked. Please contact an administrator."), 'info')
                return redirect(url_for('index'))
            elif myUser.checkPassword(request.form['password']):
                log.info("[System] <%s> logged in" % myUser.nick)
                session['logged_in'] = True
                session['userid'] = myUser.id
                session['nick'] = myUser.nick
                session['admin'] = myUser.admin
                session['logindate'] = time.time()
                session['networks'] = []
                session['last_lock_check'] = time.time()
                session['requests'] = 0
            else:
                log.info("[System] Invalid password for %s" % myUser.nick)
                flash(gettext('Invalid login'), 'error')
        else:
            flash(gettext('Invalid login'), 'error')

    return redirect(url_for('index'))

@app.route('/Profile/Logout')
@app.route('/Logout')
def profile_logout():
    session.pop('logged_in', None)
    session.pop('nick', None)
    session.pop('admin', None)
    session.pop('logindate', None)
    session.clear()
    return redirect(url_for('index'))

# password reset routes
@app.route('/PasswordReset/Request/', methods=['POST'])
def profile_password_reset_request():
    if session.get('logged_in'):
        return redirect(url_for('index'))
    log.info('[System] Password reset request (step 1/2) for email: %s' % (request.form['email']))
    myUser = getUserByEmail(request.form['email'])
    if myUser:
        myUser.load()
        myUser.verifyKey = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
        db_session.merge(myUser)
        try:
            runQuery(db_session.commit)
        except Exception as e:
            self.log.warning("[System] SQL Alchemy Error on password reset: %s" % (e))
        actUrl = url_for('profile_password_reset_verify', userId=myUser.id, verifyKey=myUser.verifyKey, _external=True)
        if send_email(app, myUser.email,
                      gettext("PyWishlist Password Reset"),
                      gettext("<h3>Hello %(nick)s</h3>You can reset your password with <a href='%(url)s'>this link</a>. If you did not request this password reset, you can just ignore it. Your current password is still valid.</b>", nick=myUser.nick, url=actUrl) + gettext("<br><br>Have fun and see you soon ;)"),
                      app.config['EMAILBANNER']):
            flash(gettext("Please check your mails at %(emailaddr)s", emailaddr=myUser.email), 'info')
    else:
        flash(gettext("No user found with this email address"))
    return redirect(url_for('index'))

@app.route('/PasswordReset/Verify/<userId>/<verifyKey>', methods=['GET'])
def profile_password_reset_verify(userId, verifyKey):
    if session.get('logged_in'):
        return redirect(url_for('index'))
    log.info('[System] Password reset request (step 2/2) for user id: %s' % (userId))
    myUser = getUserById(userId)
    if myUser:
        myUser.load()
        if myUser.verifyKey == verifyKey:
            newPassword = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))
            myUser.setPassword(newPassword)
            if send_email(app, myUser.email,
                          gettext("PyWishlist New Password"),
                          gettext("<h3>Hello %(nick)s</h3>Your new password is now <b>%(password)s</b>. Please change it right after you logged in.", nick=myUser.nick, password=newPassword) + gettext("<br><br>Have fun and see you soon ;)"),
                          app.config['EMAILBANNER']):
                flash(gettext("Please check your mails at %(emailaddr)s", emailaddr=myUser.email), 'info')
        else:
            myUser.verifyKey = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
            flash(gettext("Wrong verification link. Please request a new one."))
        db_session.merge(myUser)
        try:
            runQuery(db_session.commit)
        except Exception as e:
            self.log.warning("[System] SQL Alchemy Error on password reset verify key: %s" % (e))
    return redirect(url_for('index'))

# Dashboard routes
@app.route('/')
def index():
    boxes = []
    if session.get('logged_in'):
        linked = False
        links = fetchNetworkLinks(session['userid'])
        for link in links:
            if links[link]:
                linked = True
        if not linked:
            flash(gettext("You have no network connected. Please do so in the 'Network Connections' box."), 'info')
        return render_template('index.html', boxes = boxes)
    return render_template('login.html', boxes = boxes)
