# PyWishlist [![Build Status](https://travis-ci.org/oxivanisher/PyWishlist.svg?branch=master)](https://travis-ci.org/oxivanisher/PyWishlist) [![Coverage Status](https://coveralls.io/repos/github/oxivanisher/PyWishlist/badge.svg)](https://coveralls.io/github/oxivanisher/PyWishlist)
A web based web wishlist and secret santa implementation.


## Installation on a debian based linux
### Install required libraries
```bash
apt-get install python-pip python-dev libmysqlclient-dev
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

## ToDo
* Multi tennant?
* Be able to block/lockout user of everything
* Delete user capability
