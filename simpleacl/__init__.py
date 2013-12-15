#######################################################################
# Simpleacl - A small access control list
# Copyright (C) 2010-2013  Ivan Zakrevsky <ivzak [at] yandex [dot] ru>
# Copyright (C) 2010-2013  Kyle Terry <kyle [at] kyleterry [dot] com>
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
from __future__ import absolute_import, unicode_literals
try:
    import simplejson as json
except:
    import json

from simpleacl.exceptions import MissingRole, MissingActiveRole,\
    MissingPrivilege

try:
    str = unicode  # Python 2.* compatible
except NameError:
    pass


ALL_PRIVILEGES = 'all'


class Role(object):
    """Holds a role value"""

    _parents = None  # Order is important, so use the list(), not set
    acl = None

    def __init__(self, name):
        self.name = name
        self._parents = []

    def __repr__(self):
        return '<Role %s>' % self.name

    def __str__(self):
        return self.name

    def __unicode__(self):
        return unicode(self)

    def __eq__(self, other):
        return self.name.__eq__(getattr(other, 'name', other))

    def __ne__(self, other):
        return self.name.__ne__(getattr(other, 'name', other))

    def __hash__(self):
        return self.name.__hash__()

    def __bytes__(self):
        return str(self.name).encode('utf-8')

    def __str__(self):
        return str(self.name)

    def get_name(self):
        return self.name

    def add_parent(self, parent):
        if self.acl is None:
            raise MissingACLObject(
                'Role: %s has not set ACL object.' % \
                    format(type(self).__name__)
            )
        parent = self.acl.add_role(parent)
        if parent not in self._parents:
            self._parents.append(parent)
    
    def remove_parent(self, parent=None):
        if self.acl is None:
            raise MissingACLObject(
                'Role: %s has not set ACL object.' % \
                    format(type(self).__name__)
            )
            
        if parent is None:
            self._parents = None
            return True
        
        parent = self.acl.add_role(parent)
        if parent in self._parents:
            self._parents.remove(parent)
            return True
        else:
            return False

    def get_parents(self):
        return self._parents


class Privilege(object):
    """Holds a privilege value"""

    def __init__(self, name):
        self.name = name

    def __eq__(self, other):
        return self.name.__eq__(getattr(other, 'name', other))

    def __ne__(self, other):
        return self.name.__ne__(getattr(other, 'name', other))

    def __hash__(self):
        return self.name.__hash__()

    def __bytes__(self):
        return str(self.name).encode('utf-8')

    def __str__(self):
        return str(self.name)

    def get_name(self):
        return self.name


class Context(object):
    """Holder for context value.

    Sometimes apposite for usege as context wrapper."""

    _parents = []  # Order is important, so use the list(), not set

    def __init__(self, base):
        self.base = base

    def __eq__(self, other):
        return self.base.__eq__(getattr(other, 'base', other))

    def __ne__(self, other):
        return self.base.__ne__(getattr(other, 'base', other))

    def __hash__(self):
        return self.base.__hash__()

    def add_parent(self, parent):
        if parent not in self._parents:
            self._parents.append(parent)

    def get_parents(self):
        return self._parents


class SimpleBackend(object):
    """A simple storage."""
    _roles = None
    _privileges = None
    _acl = None
    role_class = Role
    privilege_class = Privilege

    def __init__(self):
        """Constructor."""
        self._roles = {}
        self._privileges = {}
        self._acl = {}

    def add_role(self, role, parents=None):
        """Adds role"""
        self._roles.setdefault(role.get_name(), role)
        return self

    def get_role(self, role_name):
        """Returns a role instance"""
        try:
            return self._roles[role_name]
        except KeyError:
            raise MissingRole(
                'Role must be added before requested.'
            )

    def add_privilege(self, privilege):
        """Adds privilege"""
        self._privileges.setdefault(privilege.get_name(), privilege)
        return self

    def get_privilege(self, privilege_name):
        """Returns a privilege instance"""
        try:
            return self._privileges[privilege_name]
        except KeyError:
            raise MissingPrivilege(
                'Privilege must be added before requested.'
            )

    def add_rule(self, role, privilege=ALL_PRIVILEGES,
                 context=None, allow=True):
        """Adds rule to the ACL"""
        acl = self._acl.setdefault(context, {})
        role_rules = acl.setdefault(role, {})
        role_rules[privilege] = allow
        return self

    def remove_rule(self, role, privilege=ALL_PRIVILEGES,
                    context=None, allow=True):
        """Removes rule from ACL"""
        try:
            if self._acl[context][role][privilege] == allow:
                del self._acl[context][role][privilege]
        except KeyError:
            pass
        return self

    def role_has_privilege(self, role, privilege, context=None, allow=True):
        """Removes rule from ACL"""
        try:
            return self._acl[context][role][privilege] == allow
        except KeyError:
            return False

    def is_allowed(self, role, privilege, context=None, undef=None):
        """Returns True if active role is allowed

        for given privilege in given given context
        """
        try:
            return self._acl[context][role][privilege]
        except KeyError:
            return undef


class Acl(object):
    """Access control list."""

    active_role = None

    def __init__(self, backend_class=None):
        """Constructor."""
        if backend_class is None:
            backend_class = SimpleBackend
        self._backend = backend_class()
        self.add_privilege(ALL_PRIVILEGES)

    def add_role(self, name_or_instance, parents=None):
        """Adds a role to the ACL"""
        if isinstance(name_or_instance, bytes):
            name_or_instance = str(name_or_instance)
        if isinstance(name_or_instance, str):
            instance = self._backend.role_class(name_or_instance)
        elif isinstance(name_or_instance, self._backend.role_class):
            instance = name_or_instance
        else:
            raise Exception(
                'Unable to add a role of type: {0}'\
                    .format(type(name_or_instance).__name__)
            )
        self._backend.add_role(instance)
        
        if instance.acl is None:
            instance.acl = self
        
        # Parents support for roles
        if parents is not None:
            for parent in parents:
                parent = self.add_role(parent)
                if instance.acl is None:
                    instance.acl = self
                instance.add_parent(parent)

        # Hierarchical support for roles
        if '.' in instance.get_name():
            parent = instance.get_name().rsplit('.', 1).pop(0)
            parent = self.add_role(parent)  # Recursive
        return instance

    def get_role(self, name_or_instance):
        """Returns the identified role instance"""
        
        if isinstance(name_or_instance, self._backend.role_class):
            instance = name_or_instance
        else:
            instance = self._backend.get_role(name_or_instance)
        
        if instance.acl is None:
            instance.acl = self
        
        return instance

    def add_privilege(self, name_or_instance):
        """Adds a privilege to the ACL"""
        if isinstance(name_or_instance, bytes):
            name_or_instance = str(name_or_instance)
        if isinstance(name_or_instance, str):
            instance = self._backend.privilege_class(name_or_instance)
        elif isinstance(name_or_instance, self._backend.privilege_class):
            instance = name_or_instance
        else:
            raise Exception(
                'Unable to add a privilege of type: {0}'\
                    .format(type(name_or_instance).__name__)
            )
        self._backend.add_privilege(instance)

        # Hierarchical support for instances
        if '.' in instance.get_name():
            parent = instance.get_name().rsplit('.', 1).pop(0)
            parent = self.add_instance(parent)  # Recursive
        return instance

    def get_privilege(self, name_or_instance):
        """Returns the identified privilege instance"""
        if isinstance(name_or_instance, bytes):
            name_or_instance = str(name_or_instance)
        if isinstance(name_or_instance, str):
            return self._backend.get_privilege(name_or_instance)
        if isinstance(name_or_instance, self._backend.privilege_class):
            return name_or_instance
        raise Exception(
            'Unable to get a Privelege of type: {0}'\
                .format(type(name_or_instance).__name__)
        )

    def add_rule(self, role, privileges=ALL_PRIVILEGES,
                 context=None, allow=True):
        """Adds rule to the ACL"""
        if not hasattr(privileges, '__iter__'):
            privileges = (privileges, )
        for priv in privileges:
            self._backend.add_rule(
                self.get_role(role), self.get_privilege(priv), context, allow
            )
        return self

    def remove_rule(self, role, privileges=ALL_PRIVILEGES,
                    context=None, allow=True):
        """Removes rule from ACL"""
        if not hasattr(privileges, '__iter__'):
            privileges = (privileges, )
        for priv in privileges:
            self._backend.remove_rule(
                self.get_role(role), self.get_privilege(priv), context, allow
            )
        return self

    def allow(self, role, privileges=ALL_PRIVILEGES, context=None):
        """Adds an "allow" rule to the ACL"""
        return self.add_rule(role, privileges, context, True)

    def remove_allow(self, role, privileges=ALL_PRIVILEGES, context=None):
        """Removes an "allow" rule from the ACL"""
        return self.remove_rule(role, privileges, context, True)

    def deny(self, role, privileges=ALL_PRIVILEGES, context=None):
        """Adds a "deny" rule to the ACL"""
        return self.add_rule(role, privileges, context, False)

    def remove_deny(self, role, privileges=ALL_PRIVILEGES, context=None):
        """Removes a "deny" rule from the ACL"""
        return self.remove_rule(role, privileges, context, False)

    def role_has_privilege(self, role, privilege, context=None, allow=True):
        """Returns True if role has privilege"""
        try:
            return self._backend.role_has_privilege(
                self.get_role(role), self.get_privilege(privilege),
                context, allow
            )
        except MissingPrivilege:
            return False

    def active_role_is(self, role):
        """Sets active role"""
        self.active_role = self.get_role(role)
        return self

    def set_active_role(self, role):
        """Just alias for self.active_role_is()"""
        return self.active_role_is(role)

    def is_allowed(self, privilege, context=None, undef=False):
        """Returns True if active role is allowed

        for given privilege in given given context
        """
        if not self.active_role:
            raise MissingActiveRole(
                "A role must be set active before checking permissions"
            )

        role = self.active_role
        privilege = self.get_privilege(privilege)

        allow = self._backend.is_allowed(role, privilege, context, None)
        if allow is not None:
            return allow

        allow = self._backend.is_allowed(
            role, self.get_privilege(ALL_PRIVILEGES), context, None
        )
        if allow is not None:
            return allow

        # Parents support for roles
        for parent in role.get_parents():
            self.active_role_is(parent)
            allow = self.is_allowed(privilege, context, None)
            if allow is not None:
                return allow

        # Hierarchical support for roles
        if '.' in role.get_name():
            parent = self.get_role(role.get_name().rsplit('.', 1).pop(0))
            self.active_role_is(parent)
            allow = self.is_allowed(privilege, context, None)
            if allow is not None:
                return allow

        self.active_role_is(role)

        # Hierarchical support for privileges
        if '.' in privilege.get_name():
            parent = self.get_privilege(
                privilege.get_name().rsplit('.', 1).pop(0)
            )
            allow = self.is_allowed(parent, context, None)
            if allow is not None:
                return allow

        # Parents support for context
        if hasattr(context, 'get_parents'):
            for parent in context.get_parents():
                allow = self.is_allowed(privilege, parent, None)
                if allow is not None:
                    return allow

        return undef

    def bulk_load(self, json_or_dict, context=None):
        """You can store your roles, privileges and allow list (many to many)
        in a json encoded string and pass it into this method to build
        the object without having to call add_role or add_privilege for each
        one. TODO: make better documentation for this method.
        """
        if isinstance(json_or_dict, bytes):
            json_or_dict = str(json_or_dict)
        if isinstance(json_or_dict, str):
            clean = json.loads(json_or_dict)
        else:
            clean = json_or_dict

        if 'roles' in clean:
            for value in clean['roles']:
                if hasattr(value, '__iter__'):
                    self.add_role(*value)
                elif isinstance(value, dict):
                    self.add_role(**value)
                else:
                    self.add_role(value)

        if 'privileges' in clean:
            for value in clean['privileges']:
                self.add_privilege(value)

        if 'acl' in clean:
            for row in clean['acl']:
                self.allow(row['role'], row['privilege'],
                           context, row['allow'])
        return self

    @classmethod
    def create_instance(cls, json_or_dict):
        """You can store your roles, privileges and allow list (many to many)
        in a json encoded string and pass it into this method to build
        the object without having to call add_role or add_privilege for each
        one. TODO: make better documentation for this method.
        """
        obj = cls()
        obj.bulk_load(json_or_dict)
        return obj

# Python 2.* compatible
try:
    unicode
except NameError:
    pass
else:
    for cls in (Role, Privilege, ):
        cls.__unicode__ = cls.__str__
        cls.__str__ = cls.__bytes__
