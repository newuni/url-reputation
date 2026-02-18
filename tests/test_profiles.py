import unittest

from url_reputation.profiles import PROFILES, get_profile


class TestProfiles(unittest.TestCase):
    def test_profiles_exist(self):
        for name in ["free", "fast", "privacy", "thorough"]:
            self.assertIn(name, PROFILES)

    def test_get_profile(self):
        p = get_profile("free")
        self.assertEqual(p.name, "free")
        self.assertTrue(len(p.providers) >= 1)


if __name__ == "__main__":
    unittest.main()
