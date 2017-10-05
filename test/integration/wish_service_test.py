import unittest

import os

from pywishlist.blueprints.wishes.wishes_service import WishesService

from pywishlist.database import init_db, clear_db
from pywishlist.models.wish import Wish


class TestWishService(unittest.TestCase):
    def setUp(self):
        os.environ['PYWISHLIST_CFG'] = "pywishlist_test.cfg"
        clear_db()
        init_db()

    def test_add_wish(self):
        wish = Wish(1, 2, "test")
        WishesService.add_wish(wish)

        wishes = Wish.query.all()

        self.assertEqual(1, len(wishes))
        self.assertEqual("test", wishes[0].text)

