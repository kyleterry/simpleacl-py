Simpleacl
---------

Instructions for simpleacl Acl class
====================================

    >>> import simpleacl
    >>> acl = simpleacl.Acl()
    >>> acl.add_role('admin')
    >>> acl.add_role('member')
    >>> acl.add_role('guest')
    >>> acl.add_resource('view_page')
    >>> acl.add_resource('edit_page')
    >>> acl.add_resource('delete_page')
    >>> acl.allow('admin', 'all')
    >>> acl.allow('member', ['view_page', 'edit_page'])
    >>> acl.allow('guest', 'view_page')
    >>> # set who the active role based on what the user is.
    >>> acl.active_role_is('member')
    >>> # check if the user is allowed to the resource
    >>> acl.is_allowed('edit_page')
    True
    >>> acl.is_allowed('delete_page')
    False

Instructions for simpleacl middleware - Pylons - DEPRICATED
==============================================

Currently these instructions cover using the middleware with Pylons 0.9.x

Simpleacl middleware requires you create a build class for building the 
access control list. You specify the class location using two config variables
in your paster .ini

PJT = your pylons project name

Open your projects development.ini and somewhere inside app:main put...

    simpleacl.build.module = PJT.lib.acl
    simpleacl.build.class = BuildAcl

Now create a file in lib/ called acl.py

This is just a general idea of how you can build simpleacl...

    import simpleacl

    class BuildAcl(object):
        def __init__(self):
            pass

        def __call__(self):
            acl = simpleacl.Acl()
            acl.add_role('admin')
            acl.add_role('member')
            acl.add_role('guest')
            acl.add_resource('view_page')
            acl.add_resource('edit_page')
            acl.add_resource('delete_page')
            acl.allow('admin', 'all')
            acl.allow('member', ['view_page', 'edit_page'])
            acl.allow('guest', 'view_page')

            return acl

Now in PJT/config/middleware.py add the following import...

    from simpleacl.middleware import AclMiddleware

... then in the section where it says # CUSTOM MIDDLEWARE HERE add...
    
    app = AclMiddleware(app, config)

You can now access your built simpleacl object from...
    
    request.environ.get('simpleacl')

Instructions for simpleacl middleware - Bottle
==============================================

Middleware instructions for bottle are coming soon...
