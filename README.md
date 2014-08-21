[![Build Status](https://travis-ci.org/kyleterry/simpleacl-py.svg?branch=master)](https://travis-ci.org/kyleterry/simpleacl-py)

# Simpleacl


Instructions for simpleacl Acl class
====================================

    >>> import simpleacl
    >>> acl = simpleacl.Acl()
    >>> acl.add_role('admin')
    >>> acl.add_role('member')
    >>> acl.add_role('guest')
    >>> acl.add_privilege('view_page')
    >>> acl.add_privilege('edit_page')
    >>> acl.add_privilege('delete_page')
    >>> acl.allow('admin', 'all')
    >>> acl.allow('member', ['view_page', 'edit_page'])
    >>> acl.allow('guest', 'view_page')
    >>> # set who the active role based on what the user is.
    >>> acl.active_role_is('member')
    >>> # check if the user is allowed to the privilege
    >>> acl.is_allowed('edit_page')
    True
    >>> acl.is_allowed('delete_page')
    False
