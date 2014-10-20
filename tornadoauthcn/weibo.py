#!/usr/bin/env python


"""This module contains implementations of various third-party
authentication schemes.

"""


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


class WeiboOAuth2Mixin(OAuth2Mixin):
    """Weibo authentication using OAuth2.

    In order to use, register your application with Weibo and copy the
    relevant parameters to your application settings.

    """
    _OAUTH_ACCESS_TOKEN_URL = 'https://api.weibo.com/oauth2/access_token'
    _OAUTH_AUTHORIZE_URL = 'https://api.weibo.com/oauth2/authorize?'
    _OAUTH_SETTINGS_KEY = 'weibo_oauth'

    @_auth_return_future
    def get_authenticated_user(self, redirect_uri, client_id, client_secret,
            code, callback):
        """Handles the login for the Weibo user, returning a user object.

        Example usage::

            class WeiboOAuth2LoginHandler(tornado.web.RequestHandler,
                                           WeiboOAuth2Mixin):
                @tornado.gen.coroutine
                def get(self):
                    if self.get_argument('code', False):
                        user = yield self.get_authenticated_user(
                            redirect_uri='http://your.site.com/auth/weibo',
                            client_id='your_weibo_app_id',
                            client_secret='your_weibo_app_secret',
                            code=self.get_argument('code'))
                        # Save the user with e.g. set_secure_cookie
                    else:
                        yield self.authorize_redirect(
                            redirect_uri='http://your.site.com/auth/weibo',
                            client_id='your_weibo_app_id',
                            )
        """
        http = self.get_auth_http_client()
        args = {
            "redirect_uri": redirect_uri,
            "code": code,
            "client_id": self.settings[self._OAUTH_SETTINGS_KEY]['key'],
            "client_secret": self.settings[self._OAUTH_SETTINGS_KEY]['secret'],
            "extra_params": {"grant_type": "authorization_code"},
        }
        body = urllib_parse.urlencode(args)

        # http.fetch(self._oauth_request_token_url(**args),
        #            functools.partial(self._on_access_token, callback, fields))
        http.fetch(self._OAUTH_ACCESS_TOKEN_URL,
                   functools.partial(self._on_access_token, callback),
                   method="POST", headers={'Content-Type': 'application/x-www-form-urlencoded'}, body=body)


    def _on_access_token(self, future, response):
        """Callback function for the exchange to the access token."""
        if response.error:
            future.set_exception(AuthError('Weibo auth error: %s' % str(response)))
            return

        args = escape.json_decode(escape.native_str(response.body))
        print 'args:', args
        session = {
            'access_token': args['access_token'],
            'uid': args['uid'],
            'session_expires': args['expires_in'],
            }

        self.weibo_request(
            path='/users/show.json',
            callback=functools.partial(
                self._on_get_user_info, future, session),
            access_token=session['access_token'],
            uid=session['uid'],
            )

    def _on_get_user_info(self, future, session, user):
        if user is None:
            future.set_result(None)
            return

        fieldmap = user
        fieldmap.update({"access_token": session["access_token"], "session_expires": session.get("expires")})
        future.set_result(fieldmap)


    @_auth_return_future
    def weibo_request(self, path, callback, access_token, uid):
        url = "https://api.weibo.com/2" + path
        all_args = {
                'access_token': access_token,
                'uid': uid,
                }
        url += "?" + urllib_parse.urlencode(all_args)
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



