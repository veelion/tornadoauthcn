#!/usr/bin/env python


"""This module contains implementations of various third-party
authentication schemes.

"""


import re
import functools

from tornado import httpclient
from tornado import escape
from tornado.auth import OAuth2Mixin, _auth_return_future, AuthError


try:
    import urllib.parse as urllib_parse  # py3
except ImportError:
    import urllib as urllib_parse  # py2

try:
    long  # py2
except NameError:
    long = int  # py3


class QQOAuth2Mixin(OAuth2Mixin):
    """QQ authentication using OAuth2.

    In order to use, register your application with QQ and copy the
    relevant parameters to your application settings.

    """
    _OAUTH_AUTHORIZE_URL = 'https://graph.qq.com/oauth2.0/authorize'
    _OAUTH_ACCESS_TOKEN_URL = 'https://graph.qq.com/oauth2.0/token'
    _OAUTH_SETTINGS_KEY = 'qq_oauth'

    @_auth_return_future
    def get_authenticated_user(self, redirect_uri, client_id, client_secret,
            code, callback):
        """Handles the login for the QQ user, returning a user object.

        Example usage::

            class QQOAuth2LoginHandler(tornado.web.RequestHandler,
                                           QQOAuth2Mixin):
                @tornado.gen.coroutine
                def get(self):
                    if self.get_argument('code', False):
                        user = yield self.get_authenticated_user(
                            redirect_uri='http://your.site.com/auth/qq',
                            client_id='your_qq_app_id',
                            client_secret='your_qq_app_secret'
                            code=self.get_argument('code'))
                        # Save the user with e.g. set_secure_cookie
                    else:
                        yield self.authorize_redirect(
                            redirect_uri='http://your.site.com/auth/qq',
                            client_id='your_qq_app_id',
                            )
        """
        http = self.get_auth_http_client()
        args = {
            "redirect_uri": redirect_uri,
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "extra_params": {"grant_type": "authorization_code"},
        }
        # body = urllib_parse.urlencode(args)

        http.fetch(self._oauth_request_token_url(**args),
                   functools.partial(self._on_access_token, callback, client_id))
        # http.fetch(self._OAUTH_ACCESS_TOKEN_URL,
        #            functools.partial(self._on_access_token, callback, fields),
        #            method="POST", headers={'Content-Type': 'application/x-www-form-urlencoded'}, body=body)


    def _on_access_token(self, future, client_id, response):
        """Callback function for the exchange to the access token."""
        if response.error:
            future.set_exception(AuthError('QQ auth access_token error: %s' % str(response)))
            return

        print 'response:', response.body
        if 'error' in response.body:
            future.set_exception(AuthError('QQ auth access_token error: %s' % str(response.body)))
            return
        args = escape.native_str(response.body).split('&')
        access_token = ''
        for a in args:
            print a
            k,v = a.split('=')
            if k == 'access_token':
                access_token = v
                break
        http = self.get_auth_http_client()
        url = 'https://graph.qq.com/oauth2.0/me?access_token=%s' % access_token
        http.fetch(url,
                functools.partial(self._on_get_openid, future, client_id, access_token))

    def _on_get_openid(self, future, client_id, access_token, response):
        if response.error:
            future.set_exception(AuthError('QQ auth get_openid error: %s' % str(response)))
            return
        print 'response:', response.body
        m = re.findall(r'"openid":"(.*?)"', response.body)
        if not m:
            future.set_exception(AuthError('QQ get openid bad return: %s' % str(response)))
            return
        openid = m[0]
        print 'openid:', openid
        args = {
            'access_token': access_token,
            'oauth_consumer_key': client_id,
            'openid': openid,
            }

        self.qq_request(
            callback=functools.partial(
                self._on_get_user_info, future, args),
            args=args
        )


    def _on_get_user_info(self, future, args, user):
        if user is None:
            future.set_result(None)
            return

        fieldmap = user
        fieldmap.update(args)
        future.set_result(fieldmap)


    @_auth_return_future
    def qq_request(self, callback, args):
        url = "https://graph.qq.com/user/get_user_info?"
        url += urllib_parse.urlencode(args)
        callback = functools.partial(self._on_weibo_request, callback)
        http = self.get_auth_http_client()
        http.fetch(url, callback=callback)

    def _on_weibo_request(self, future, response):
        if response.error:
            future.set_exception(AuthError("Error response %s fetching %s" %
                (response.error, response.request.url)))
            return
        future.set_result(escape.json_decode(response.body))

    def get_auth_http_client(self):
        """Returns the `.AsyncHTTPClient` instance to be used for auth requests.

        May be overridden by subclasses to use an HTTP client other than
        the default.
        """
        return httpclient.AsyncHTTPClient()



