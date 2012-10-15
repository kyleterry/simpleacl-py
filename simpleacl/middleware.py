from __future__ import absolute_import, unicode_literals
#######################################################################
# Simpleacl Middleware - A small access control list
# Copyright (C) 2010  Kyle Terry <kyle@fiverlabs.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#######################################################################

def class_maker(name, classname):
    """
    This will dynamically make a class object from a
    dynamically imported module. This is so a user
    can call the class whatever they want.
    """
    mod = __import__(name)
    comps = name.split('.')
    for comp in comps[1:]:
        mod = getattr(mod, comp)
    _class = getattr(mod, classname)
    return _class

class AclMiddleware(object):
    def __init__(self, app, config):
        self.app = app
        self.config = config

    def __call__(self, environ, start_response):
        acl_builder = class_maker(self.config['simpleacl.build.module'], self.config['simpleacl.build.class'])
        acl_builder = acl_builder()
        acl = acl_builder()
        environ['simpleacl'] = acl
        return self.app(environ, start_response)


class AclMiddlewareException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)
