"""Canonical private link identity; assertions never dump credential values."""
import json
import secrets
import unittest
from test_safety import s


class WebLinkTests(unittest.TestCase):
    def setUp(self):
        self.host = 'proxy.example.com'
        self.secret = secrets.token_hex(16)
        self.manifest = json.dumps(dict(schema=1, domain=self.host,
                                       unit_sha256='a'*64, nginx_sha256='b'*64)).encode()
        self.config = (f'[access.users]\nweb-user = "{self.secret}"\n'
                       '[web]\nenabled = true\n[[web.vhosts]]\n'
                       f'host = "{self.host}"\n[[web.vhosts.profiles]]\n'
                       'user = "web-user"\nsecret_mode = "dd"\n').encode()
        self.link = f'tg://webproxy?server={self.host}&secret=dd{self.secret}\n'.encode()

    def test_exact_identity_without_runtime_or_certificate_health(self):
        value = s.web_link_value(self.manifest, self.config, self.link)
        self.assertTrue(value.encode() == self.link[:-1], 'canonical link identity')

    def test_noncanonical_link_bytes_refused(self):
        cases = [self.link[:-1], self.link+b'\n', self.link+b'extra',
                 self.link.replace(b'\n', b'\r\n'), b'\0'+self.link, b'\x1b'+self.link,
                 self.link.replace(b'tg://', b'https://'),
                 self.link.replace(b'proxy.example.com', b'foreign.example.com'),
                 self.link.replace(self.secret.encode(), secrets.token_hex(16).encode()),
                 self.link.replace(b'&secret=', b'&other=x&secret='),
                 self.link.replace(b'secret=dd', b'secret=ee')]
        for index, value in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ValueError):
                s.web_link_value(self.manifest, self.config, value)

    def test_manifest_rejection(self):
        for value in [b'{}', b'[]', b'{', self.manifest.replace(b'"schema": 1', b'"schema": 2'),
                      self.manifest.replace(b'"schema": 1', b'"schema": true'),
                      b'{"schema":1,'+self.manifest[1:],
                      self.manifest.replace(b'proxy.example.com', b'foreign.example.com'),
                      self.manifest.replace(b'"domain":', b'"domain": null, "old_domain":')]:
            with self.assertRaises((ValueError, KeyError, TypeError)):
                s.web_link_value(value, self.config, self.link)

    def test_toml_identity_and_includes_refused(self):
        cases = [self.config.replace(b'enabled = true', b'enabled = false'),
                 self.config.replace(b'secret_mode = "dd"', b'secret_mode = "plain"'),
                 self.config.replace(b'proxy.example.com', b'foreign.example.com'),
                 self.config.replace(self.secret.encode(), secrets.token_hex(16).encode()),
                 self.config.replace(b'web-user', b'foreign-user'),
                 b'include = "foreign.toml"\n'+self.config,
                 b'includes = []\n'+self.config, b'not TOML',
                 self.config+b'\n[access.user_enabled]\nweb-user = false\n']
        for index, value in enumerate(cases):
            with self.subTest(case=index), self.assertRaises((ValueError, KeyError)):
                s.web_link_value(self.manifest, value, self.link)


if __name__ == '__main__':
    unittest.main()
