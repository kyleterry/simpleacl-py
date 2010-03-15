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

