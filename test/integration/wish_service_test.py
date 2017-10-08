import unittest

import os

from pywishlist.blueprints.wishes.wishes_service import WishesService

from pywishlist.database import init_db, clear_db
from pywishlist.models.wish import Wish


class TestWishService(unittest.TestCase):
    def setUp(self):
        clear_db()
        init_db()

        self.me = 1
        self.someone_else = 2

    def test_add_wish(self):
        wish = Wish(1, 2, "test")
        WishesService.add_wish(wish)

        wishes = Wish.query.all()

        self.assertEqual(1, len(wishes))
        self.assertEqual("test", wishes[0].text)

    def add_all_wishes_combinations(self):
        me = self.me
        someone_else = self.someone_else
        active_wish_created_by_me_for_me = Wish(me, me, "active_wish_created_by_me_for_me")
        active_wish_created_by_someone_else_for_me = Wish(someone_else, me, "active_wish_created_by_someone_else_for_me")
        active_wish_created_by_me_for_someone_else = Wish(me, someone_else, "active_wish_created_by_me_for_someone_else")
        wish_created_by_me_for_me_hidden_by_me = Wish(me, me, "wish_created_by_me_for_me_hidden_by_me", hidden_id=me)
        # following should not exist as I never see others wishes and thus can't hide them
        invalid_wish_created_by_someone_else_for_me_hidden_by_me = Wish(someone_else, me, "invalid_wish_created_by_someone_else_for_me_hidden_by_me", hidden_id=me)
        wish_created_by_me_for_someone_else_hidden_by_me = Wish(me, someone_else, "wish_created_by_me_for_someone_else_hidden_by_me", hidden_id=me)
        wish_created_by_me_for_me_hidden_by_someone_else = Wish(me, me, "wish_created_by_me_for_me_hidden_by_someone_else", hidden_id=someone_else)
        wish_created_by_someone_else_for_me_hidden_by_someone_else = Wish(someone_else, me, "wish_created_by_someone_else_for_me_hidden_by_someone_else", hidden_id=someone_else)
        # this should not exists as the other person should not see my wish and can't hide it
        invalid_wish_created_by_me_for_someone_else_hidden_by_someone_else = Wish(me, someone_else, "invalid_wish_created_by_me_for_someone_else_hidden_by_someone_else", hidden_id=someone_else)

        WishesService.add_wish(active_wish_created_by_me_for_me)
        WishesService.add_wish(active_wish_created_by_someone_else_for_me)
        WishesService.add_wish(active_wish_created_by_me_for_someone_else)
        WishesService.add_wish(wish_created_by_me_for_me_hidden_by_me)
        WishesService.add_wish(invalid_wish_created_by_someone_else_for_me_hidden_by_me)
        WishesService.add_wish(wish_created_by_me_for_someone_else_hidden_by_me)
        WishesService.add_wish(wish_created_by_me_for_me_hidden_by_someone_else)
        WishesService.add_wish(wish_created_by_someone_else_for_me_hidden_by_someone_else)
        WishesService.add_wish(invalid_wish_created_by_me_for_someone_else_hidden_by_someone_else)

    def test_get_all_active_wishes_for_user_id_called_by_myself_shows_only_wishes_created_by_me_and_not_hidden_by_me(self):
        self.add_all_wishes_combinations()

        wishes = WishesService.get_all_active_wishes_for_user_id(self.me, self.me)

        self.assertEqual(2, len(wishes))
        self.AssertWishExists("active_wish_created_by_me_for_me", wishes)
        self.AssertWishExists("wish_created_by_me_for_me_hidden_by_someone_else", wishes)

    def test_get_all_active_wishes_for_user_id_called_from_other_user_shows_all_my_wishes_not_hidden(self):
        self.add_all_wishes_combinations()

        wishes = WishesService.get_all_active_wishes_for_user_id(self.me, self.someone_else)

        self.assertEqual(2, len(wishes))
        self.AssertWishExists("active_wish_created_by_me_for_me", wishes)
        self.AssertWishExists("active_wish_created_by_someone_else_for_me", wishes)

    def test_get_all_hidden_wishes_for_user_id_called_by_myself_only_shows_wishes_created_and_hidden_by_me(self):
        self.add_all_wishes_combinations()

        wishes = WishesService.get_all_hidden_wishes_for_user_id(self.me, self.me)

        self.assertEqual(1, len(wishes))
        self.AssertWishExists("wish_created_by_me_for_me_hidden_by_me", wishes)

    def test_get_all_hidden_wishes_for_user_id_called_from_other_user_shows_all_my_wishes_hidden(self):
        self.add_all_wishes_combinations()

        wishes = WishesService.get_all_hidden_wishes_for_user_id(self.me, self.someone_else)

        self.assertEqual(4, len(wishes))
        self.AssertWishExists("wish_created_by_me_for_me_hidden_by_me", wishes)
        self.AssertWishExists("invalid_wish_created_by_someone_else_for_me_hidden_by_me", wishes)
        self.AssertWishExists("wish_created_by_me_for_me_hidden_by_someone_else", wishes)
        self.AssertWishExists("wish_created_by_someone_else_for_me_hidden_by_someone_else", wishes)

    def AssertWishExists(self, v, wishes):
        self.assertTrue(any(wish.text == v for wish in wishes))
