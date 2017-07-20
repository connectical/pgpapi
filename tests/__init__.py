#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2017 Óscar García Amor <ogarcia@connectical.com>
#
# Distributed under terms of the GNU GPLv3 license.

import unittest

from .test_apiv1 import ApiTestCase

def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(ApiTestCase))
    return suite
