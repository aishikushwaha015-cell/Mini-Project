"""Theme toggle tests: shared shell markup, light stylesheet and client logic.

Run from the project root:

    .venv\\Scripts\\python -m unittest discover -s tests -v
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from app import app
from phishing import history

PAGES = ["/", "/analysis", "/analysis/url", "/history", "/reports",
         "/settings", "/about"]


class ThemeTestCase(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.tmp = Path(tempfile.mkdtemp(prefix="phishguard-theme-"))
        history.set_database_path(self.tmp / "history.db")
        self.addCleanup(history.set_database_path, None)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def get(self, path):
        response = self.client.get(path)
        return response, response.get_data(as_text=True)


class TestThemeShell(ThemeTestCase):
    def test_base_shell_sets_light_default_before_stylesheets(self):
        _, html = self.get("/")
        self.assertIn('<html lang="en" data-theme="light">', html)
        self.assertIn('content="#f3f7fb"', html)
        self.assertIn("var theme = 'light';", html)
        self.assertIn("drishti.theme", html)
        self.assertIn('id="theme-color-meta"', html)

        # The anti-flash script must run before the first stylesheet link.
        first_script = html.index("drishti.theme")
        first_stylesheet = html.index("css/app.css")
        self.assertLess(first_script, first_stylesheet)

    def test_light_stylesheet_is_loaded_last(self):
        _, html = self.get("/")
        offsets = [html.index("css/%s" % name) for name in
                   ("app.css", "analysis.css", "records.css", "theme-light.css")]
        self.assertEqual(offsets, sorted(offsets))

    def test_sidebar_contains_accessible_theme_switch(self):
        _, html = self.get("/")
        self.assertIn('id="theme-toggle"', html)
        self.assertIn('role="switch"', html)
        self.assertIn('aria-checked="true"', html)
        self.assertIn('aria-label="Switch to dark mode"', html)
        self.assertIn("theme-icon-sun", html)
        self.assertIn("theme-icon-moon", html)
        self.assertIn("Appearance", html)

    def test_every_page_uses_the_shared_theme_shell(self):
        for path in PAGES:
            with self.subTest(path=path):
                response, html = self.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn('id="theme-toggle"', html)
                self.assertIn("css/theme-light.css", html)


class TestThemeAssets(ThemeTestCase):
    def test_light_stylesheet_defines_light_theme(self):
        response = self.client.get("/static/css/theme-light.css")
        self.addCleanup(response.close)
        css = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(':root[data-theme="light"]', css)
        self.assertIn("color-scheme: light", css)
        self.assertIn("--cyan-fill", css)

    def test_app_script_applies_and_persists_theme(self):
        response = self.client.get("/static/js/app.js")
        self.addCleanup(response.close)
        js = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("drishti.theme", js)
        self.assertIn("applyTheme", js)
        self.assertIn("'storage'", js)


if __name__ == "__main__":
    unittest.main()
