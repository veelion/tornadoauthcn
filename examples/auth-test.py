#!/usr/bin/env python
# coding:utf8


import json
import tornado.ioloop
import tornado.web

from tornado import gen

import sys
sys.path.insert(0, '..')

import tornadoauthcn.weibo
import tornadoauthcn.qq
import config

class WeiboAuthHandler(tornado.web.RequestHandler, tornadoauthcn.weibo.WeiboOAuth2Mixin):
    @tornado.web.asynchronous
    @gen.coroutine
    def get(self):
        if self.get_argument('code', None):
            user = yield self.get_authenticated_user(
                redirect_uri=config.weibo_redirect_uri,
                client_id=self.settings['weibo_oauth']['key'],
                client_secret=self.settings['weibo_oauth']['secret'],
                code=self.get_argument('code'))
            self.write(json.dumps(user, ensure_ascii=False, indent=2))
        else:
            self.authorize_redirect(
                redirect_uri=config.weibo_redirect_uri,
                client_id=self.settings['weibo_oauth']['key']
                )


class QQAuthHandler(tornado.web.RequestHandler, tornadoauthcn.qq.QQOAuth2Mixin):
    @tornado.web.asynchronous
    @gen.coroutine
    def get(self):
        if self.get_argument('code', None):
            user = yield self.get_authenticated_user(
                redirect_uri=config.qq_redirect_uri,
                client_id=self.settings['qq_oauth']['key'],
                client_secret=self.settings['qq_oauth']['secret'],
                code=self.get_argument('code'))
            print user
            self.write(json.dumps(user, ensure_ascii=False, indent=2))
        else:
            self.authorize_redirect(
                redirect_uri=config.qq_redirect_uri,
                client_id=self.settings['qq_oauth']['key']
                )


app = tornado.web.Application(
        [
            ('/auth/login/weibo', WeiboAuthHandler),
            ('/auth/login/qq', QQAuthHandler),
        ],
        weibo_oauth=config.weibo_oauth,
        qq_oauth=config.qq_oauth,
        debug=True)

if __name__ == '__main__':
    port = 9998
    print 'listen:', 9998
    app.listen(port)
    tornado.ioloop.IOLoop.instance().start()
