import os
import sys

os.environ['PYWISHLIST_CFG'] = "USERHOME/www_data/wsgi/pywishlist.cfg"

sys.path.insert(0, 'USERHOME/git_checkouts/PyWishlist/')

from pywishlist import app as application
