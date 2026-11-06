from appsleuth import banner as _mod
import io
import os
import sys
import unittest
from unittest import mock

PKG = _mod


def _banner():
    return PKG


class BannerTests(unittest.TestCase):
    def test_strip_flag(self):
        argv = ["info", "--no-banner", "x.apk"]
        self.assertTrue(PKG.strip_flag(argv))
        self.assertEqual(argv, ["info", "x.apk"])

    def test_env_suppresses(self):
        with mock.patch.dict(os.environ, {"NO_BANNER": "1"}):
            self.assertTrue(PKG.strip_flag([]))

    def test_silent_when_not_a_terminal(self):
        buf = io.StringIO()
        PKG._shown = False
        with mock.patch.object(sys, "stderr", buf):
            PKG.show("Tool", "1.0", "https://github.com/x/y", "tag")
        self.assertEqual(buf.getvalue(), "")

    def test_prints_links_and_version_on_a_terminal(self):
        class Tty(io.StringIO):
            def isatty(self):
                return True
        buf = Tty()
        PKG._shown = False
        with mock.patch.object(sys, "stderr", buf), mock.patch.dict(os.environ, {"NO_ANIM": "1", "NO_COLOR": "1"}):
            PKG.show("Tool", "9.9.9", "https://github.com/x/y", "tag")
        out = buf.getvalue()
        for needle in ("v9.9.9", "https://github.com/x/y", "https://rudranetra.com/tools"):
            self.assertIn(needle, out)
