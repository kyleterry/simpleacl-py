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
