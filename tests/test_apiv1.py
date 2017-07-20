#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2017 Óscar García Amor <ogarcia@connectical.com>
#
# Distributed under terms of the GNU GPLv3 license.

from shutil import rmtree
from tempfile import mkdtemp

import unittest

from pgpapi.app import apiv1


class ApiTestCase(unittest.TestCase):
    def setUp(self):
        apiv1.SKS_KEYSERVER = 'keys.connectical.com'
        self.gnupg_home = mkdtemp()
        apiv1.GNUPG_HOME = self.gnupg_home

    def tearDown(self):
        rmtree(self.gnupg_home)

    def test_search_not_found(self):
        search = apiv1.gpg_search('N0T_3X1ST3NT_K3Y_1N_SKS_S3RV3R')
        self.assertEqual(search, (404, {'result': [], 'error': False, 'message': 'No keys found'}))

    def test_search_too_much_results(self):
        search = apiv1.gpg_search('Bob Brown')
        self.assertEqual(search, (400, {'result': [], 'error': True, 'message': 'Too much results, try redefine your search'}))

    def test_search_for_good_key(self):
        search = apiv1.gpg_search('D7D615B69DFC688E06120164BD41447DE05755B9')
        self.assertEqual(search[0], 200)
        self.assertEqual(search[1]['result']['good'][0]['type'], 'pub')
        self.assertEqual(search[1]['result']['good'][0]['trust'], '-')
        self.assertEqual(search[1]['result']['good'][0]['length'], '4096')
        self.assertEqual(search[1]['result']['good'][0]['keyid'], 'BD41447DE05755B9')
        self.assertEqual(search[1]['result']['good'][0]['date'], '1434476898')
        self.assertEqual(search[1]['result']['good'][0]['fingerprint'], 'D7D615B69DFC688E06120164BD41447DE05755B9')
        self.assertEqual(search[1]['result']['bad'], [])

    def test_search_for_revoked_key(self):
        search = apiv1.gpg_search('05CE457C4C603DC61E0D73D9DF07A52E48EDE31F')
        self.assertEqual(search[0], 200)
        self.assertEqual(search[1]['result']['good'][0]['trust'], 'r')

    def test_search_for_bad_key(self):
        search = apiv1.gpg_search('DC6E1684ED5DEE87')
        self.assertEqual(search[1]['result']['bad'][0]['keyid'], 'DC6E1684ED5DEE87')

    def test_get_not_found(self):
        key = apiv1.gpg_get('BAD')
        self.assertEqual(key, (404, {'result': {}, 'error': True, 'message': 'Key not found'}))

    def test_get_not_valid(self):
        key = apiv1.gpg_get('DC6E1684ED5DEE87')
        self.assertEqual(key, (400, {'result': {}, 'error': True, 'message': 'Key DC6E1684ED5DEE87 is not valid PGP-2 key and cannot be used'}))

    def test_get_key(self):
        key = apiv1.gpg_get('05CE457C4C603DC61E0D73D9DF07A52E48EDE31F')
        self.assertEqual(key[0], 200)
        self.assertEqual(key[1]['result']['id'], '05CE457C4C603DC61E0D73D9DF07A52E48EDE31F')
        self.assertEqual(key[1]['message'], 'Key found')

    def test_get_key_raw(self):
        key = apiv1.gpg_get('05CE457C4C603DC61E0D73D9DF07A52E48EDE31F', True)
        self.assertEqual(key[0], 200)
        self.assertIn('-----BEGIN PGP PUBLIC KEY BLOCK-----', key[1])
        self.assertIn('-----END PGP PUBLIC KEY BLOCK-----', key[1])

    def test_add_bad_key(self):
        add_key = apiv1.gpg_add('NOT VALID')
        self.assertEqual(add_key, (415, {'error': True, 'message': 'Key cannot be imported. Please check that it is a valid OpenPGP armor format'}))


if __name__ == '__main__':
    unittest.main()
