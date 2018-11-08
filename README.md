# PyWishlist [![Build Status](https://travis-ci.org/oxivanisher/PyWishlist.svg?branch=master)](https://travis-ci.org/oxivanisher/PyWishlist) [![Coverage Status](https://coveralls.io/repos/github/oxivanisher/PyWishlist/badge.svg)](https://coveralls.io/github/oxivanisher/PyWishlist)
This is a web based wishlist and secret santa implementation. The secret santa implementation is thanks to @phylomeno way more intelligent since the fall of 2018. It takes past calculations into consideration to maximise the randomness.


## Installation on a debian 8 based linux
### Install required libraries
```bash
apt-get install python3-pip python3-dev libmysqlclient-dev
pip install virtualenv
```

### Create and install virtual environment
```bash
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate
```

### Optional library for uwsgi (if used with apache or nginx)
```bash
source venv/bin/activate
pip install uwsgi
deactivate
```

## Application setup
After setting up the environment, you should copy ```dist/pywishlist.cfg.example``` to ```dist/pywishlist.cfg``` and configure at least the following options:
* DEBUG: Debug should be disabled in production. It configures if errors are only logged or sent via email to the admin.
* APPSECRET: This is used to encrypt also cookies for the client. Set this to a random string. If you change this, all cookies are invalid and users have to login again.
* SITETITLE: Give your installation a custom name like "Smith's Secret Santa".
* Multiple pictures: Change them to customize your installation further.
* ADMINS: Users added to this list are granted administrative privileges. Example: ['admin1@domain.tld', 'admin2@domain.tld']
* EMAIL*: You have to configure a working email server. Without it, users can not verify their accounts!

## Important notes
* The secret santa emails are sent in the language the admin has set in his browser at the time the "Go" button is pressed.

## Administrator manual
* You can send emails to all users with the **Bulk Email** function.
* **Secret Santa Management** allows you to add exclusions. They are bidirectional, so you don't have to add two rules if i.e. partners should not gift to each other.
* Also in **Secret Santa Management**, you can execute the calculation which sends out emails to all users with who they have to gift to. Users can always check past calculations on their profile page.

## ToDo
* Multi tennant?
* Be able to block/lockout user of everything
* Delete user capability
* Make URLs nicer in the wishlist display. They pretty much destroy the design at the moment.
* Dockerfile or even dockerhub images should be provided for a much easier installation process.
* Document how to configure the app behind Apache2 or Ngingx (the "originally intended" way to use this).
