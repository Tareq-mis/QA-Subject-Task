'''Exercise  3:
Create a Password verifications class called “PasswordVerifier”.
Add the following verifications to a master function called “Verify()”
- password should be larger than 8 chars
- password should not be null
- password should have one uppercase letter at least
- password should have one lowercase letter at least
- password should have one number at least
    Each one of these should throw an exception with a different message of your choosing
    2. Add feature: Password is OK if at least three of the previous conditions is true
    3. Add feature: password is never OK if item 1.4 is not true.
Assume Each verification takes 1 second to complete. How would you solve that tests can run faster?
'''
import unittest


class PasswordVerifier:
    def verify(password):
        password_Ok = False
        password_neverOk = False
        okRate = 0
        if password:
            notnull_ok = True
        else:
            notnull_ok = False
        length_ok = len(password) > 8
        has_number = any(c.isdigit() for c in password)
        has_lower = bool(set(password) & set(password.lower()))
        has_upper = bool(set(password) & set(password.upper()))

        if not has_lower:
            password_neverOk = True
        if length_ok or has_number or has_lower or has_upper or notnull_ok:
            okRate = okRate + 1
        if okRate >= 3 and not password_neverOk:
            password_Ok = True
        return notnull_ok and length_ok and has_number and has_lower and has_upper and password_neverOk and password_Ok


class TestPasswordVerifier(unittest.TestCase):

    def test_empty(self):
        self.assertFalse(PasswordVerifier.verify(''))

    def test_too_short(self):
        self.assertFalse(PasswordVerifier.verify('aAbB1!?'))

    def test_no_number(self):
        self.assertFalse(PasswordVerifier.verify("aAbBcC!?"))

    def test_no_upper(self):
        self.assertFalse(PasswordVerifier.verify("aabbzz()"))

    def test_no_lower(self):
        self.assertFalse(PasswordVerifier.verify("%&AABBCC"))

    def test_neverOk(self):
        self.assertFalse(PasswordVerifier.verify("%&AC4BACA"))

    def test_Ok1(self):
        self.assertFalse(PasswordVerifier.verify("aAbmMC"))

    def test_Ok2(self):
        self.assertFalse(PasswordVerifier.verify("aAbmMC1"))

    def test_Ok3(self):
        self.assertFalse(PasswordVerifier.verify("ascmcts1"))

    def test_Ok4(self):
        self.assertFalse(PasswordVerifier.verify("ascmcts1"))


if __name__ == '__main__':
    unittest.main()
    # main()
