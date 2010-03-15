Simpleacl
---------

Instructions for simpleacl Acl class
====================================

    >>> import simpleacl
    >>> acl = simpleacl.Acl()
    >>> acl.addRole('admin')
    >>> acl.addRole('member')
    >>> acl.addRole('guest')
    >>> acl.addResource('view_page')
    >>> acl.addResource('edit_page')
    >>> acl.addResource('delete_page')
    >>> acl.allow('admin', 'all')
    >>> acl.allow('member', ['view_page', 'edit_page'])
    >>> acl.allow('guest', 'view_page')
    >>> # set who the active role based on what the user is.
    >>> acl.activeRoleIs('member')
    >>> # check if the user is allowed to the resource
    >>> acl.isAllowed('edit_page')
    True
    >>> acl.isAllowed('delete_page')
    False

Instructions for simpleacl middleware
=====================================

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
            acl.addRole('admin')
            acl.addRole('member')
            acl.addRole('guest')
            acl.addResource('view_page')
            acl.addResource('edit_page')
            acl.addResource('delete_page')
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
