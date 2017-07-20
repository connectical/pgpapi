#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2017 Óscar García Amor <ogarcia@connectical.com>
#
# Distributed under terms of the GNU GPLv3 license.

from tempfile import mkdtemp

import bottle
import gnupg
import os


SKS_KEYSERVER = os.environ.get('PGPAPI_KEYSERVER', 'pgp.mit.edu')
GNUPG_HOME = os.environ.get('PGPAPI_GNUPG_HOME', None)
MAX_SEARCH_KEYS = os.environ.get('PGPAPI_MAX_SEARCH_KEYS', '40')

# If GNUPG_HOME is None then create temp directory
if GNUPG_HOME is None:
    GNUPG_HOME = mkdtemp()

# Setup MAX_SEARCH_KEYS
try:
    MAX_SEARCH_KEYS = int(MAX_SEARCH_KEYS)
except ValueError:
    MAX_SEARCH_KEYS = 40

# Configure GPG
gpg = gnupg.GPG(gnupghome=GNUPG_HOME)
gpg.encoding = 'utf-8'


def gpg_search(string):
    """
    Seek in SKS server for string

    :param string: string to search for
    :return: search results
    :rtype: tuple(int, dict)
    """
    keys = gpg.search_keys(string, SKS_KEYSERVER)
    if keys == []:
        return (404, {'result': [], 'error': False, 'message': 'No keys found'})
    else:
        if len(keys) > MAX_SEARCH_KEYS:
            return (400, {'result': [], 'error': True, 'message': 'Too much results, try redefine your search'})
        good_keys = []
        bad_keys = []
        for key in keys:
            # Download the key from server
            gpg.recv_keys(SKS_KEYSERVER, key['keyid'])
            # Read key from local store
            local_key = gpg.list_keys(keys=key['keyid'], sigs=True)
            if local_key == []:
                # Key cannot be imported because are insecure, store in bad keys
                bad_keys.append(key)
            else:
                # Key can be imported
                for sig in local_key[0]['sigs']:
                    # Search for key sigs without info
                    if sig[1][0] is '[' and sig[1][-1:] is ']':
                        gpg.recv_keys(SKS_KEYSERVER, sig[0])
                # Read key again from store with updated sigs and store it un good keys
                good_keys.append(gpg.list_keys(keys=key['keyid'], sigs=True)[0])
        return (200, {'result': {'good': good_keys, 'bad': bad_keys},
                'error': False,
                'message': '{} good keys. {} bad keys. {} total keys'.format(len(good_keys), len(bad_keys), len(keys))})


def gpg_get(keyid, raw=False):
    """
    Get key from SKS server

    :param keyid: key id to search for
    :return: armored key
    :rtype: tuple(int, dict) or tuple(int, string)
    """
    gpg.recv_keys(SKS_KEYSERVER, keyid)
    key = gpg.export_keys(keyid)
    if key:
        if raw:
            return (200, key)
        else:
            return (200, {'result': {'id': keyid, 'key': key}, 'error': False, 'message': 'Key found'})
    else:
        if gpg.search_keys(keyid, SKS_KEYSERVER) == []:
            return (404, {'result': {}, 'error': True, 'message': 'Key not found'})
        else:
            return (400, {'result': {}, 'error': True, 'message': 'Key {} is not valid PGP-2 key and cannot be used'.format(keyid)})


def gpg_add(keytext):
    """
    Add key to SKS server
    :param keytext: armored key
    :return: add result
    :rtype: tuple(int, dict)
    """
    import_result = gpg.import_keys(keytext)
    if import_result.count > 0:
        # Send key to SKS
        gpg.send_keys(SKS_KEYSERVER, import_result.fingerprints[0])
        # Search for key in SKS
        keys = gpg.search_keys(import_result.fingerprints[0], SKS_KEYSERVER)
        if keys != [] and keys[0]['keyid'] == import_result.fingerprints[0]:
            return (201, {'error': False, 'message': 'Key imported into keyserver'})
        else:
            return (503, {'error': True, 'message': 'The key is valid, but SKS server does not import it. Please, try again'})
    else:
        return (415, {'error': True, 'message': 'Key cannot be imported. Please check that it is a valid OpenPGP armor format'})


@bottle.get('/api/1/search/<string>')
def search(string):
    search = gpg_search(string)
    bottle.response.status = search[0]
    return search[1]


@bottle.get('/api/1/get/<keyid>')
def get(keyid):
    raw = bottle.request.query.get('raw')
    raw = False if raw is None else True
    get = gpg_get(keyid, raw=raw)
    if get[0] == 200 and raw:
        bottle.response.content_type = 'text/plain'
    bottle.response.status = get[0]
    return get[1]


@bottle.post('/api/1/add')
def add():
    keytext = bottle.request.forms.get('keytext')
    if keytext:
        add = gpg_add(keytext)
        bottle.response.status = add[0]
        return add[1]
    else:
        bottle.response.status = 400
        return {'error': True, 'message': 'You must send a valid OpenPGP armored key'}
