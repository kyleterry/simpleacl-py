#######################################################################
# Simpleacl - A small access control list
# Copyright (C) 2010  Ivan Zakrevsky <ivzak [at] yandex [dot] ru>
# Copyright (C) 2010  Kyle Terry <kyle [at] fiverlabs [dot] com>
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
try:
    import simplejson as json
except:
    import json

from simpleacl.exceptions import MissingRole, MissingActiveRole,\
    MissingPrivilege

ALL_PRIVILEGES = 'all'


class Role:
    """Holds a role value"""

    _parents = []  # Order is important, so use the list(), not set

    def __init__(self, name):
        self.name = name

    def get_name(self):
        return self.name

    def add_parent(self, parent):
        if parent not in self._parents:
            self._parents.append(parent)

    def get_parents(self):
        return self._parents


class Privilege:
    """Holds a privilege value"""

    def __init__(self, name):
        self.name = name

    def get_name(self):
        return self.name


class Acl:
    """A simple class to manage an
       access control list.
    """
    roles = {}
    privileges = {}
    allow_list = {}
    active_role = None

    role_class = Role
    privilege_class = Privilege

    def add_role(self, role, parents=[]):
        """Adds a role by instantiating a new Role object.
        "role" can be a string or Role object when calling
        this method.
        """
        if not isinstance(role, self.role_class):
            if not isinstance(role, (basestring,)):
                raise Exception(
                    'Unable to add role of type: {0}'\
                        .format(type(role).__name__)
                )
            if role in self.roles:
                role = self.roles[role]
            else:
                role = self.role_class(role)

        if role.get_name() not in self.roles:
            self.roles[role.get_name()] = role

        # Parents support for roles
        for parent in parents:
            parent = self.add_role(parent)
            role.add_parent(parent)

        # Hierarchical support for roles
        if '.' in role.get_name():
            parent = role.get_name().rsplit('.', 1).pop(0)
            parent = self.add_role(parent)  # Recursive
        return role

    def add_privilege(self, privilege):
        """Adds a privilege to the list of privileges by
        instantiating a new Privilege object. "privilege"
        can be a string or Privilege object when calling
        this method.
        """
        if not isinstance(privilege, self.privilege_class):
            if not isinstance(privilege, (basestring,)):
                raise Exception(
                    'Unable to add privilege of type: {0}'\
                        .format(type(privilege).__name__)
                )
            if privilege in self.privileges:
                privilege = self.privileges[privilege]
            else:
                privilege = self.privilege_class(privilege)

        if privilege.get_name() not in self.privileges:
            self.privileges[privilege.get_name()] = privilege

        # Hierarchical support for privileges
        if '.' in privilege.get_name():
            parent = privilege.get_name().rsplit('.', 1).pop(0)
            parent = self.add_privilege(parent)  # Recursive
        return privilege

    def allow(self, role, privilege=ALL_PRIVILEGES, context=None, allow=True):
        """Use this method to allow a role access to a
        specific privilege or list of privileges.
        """
        if context not in self.allow_list:
            self.allow_list[context] = {}
        allow_list = self.allow_list[context]

        if isinstance(role, self.role_class):
            role = role.get_name()

        if role not in self.roles:
            raise MissingRole(
                'Roles must be defined before adding them to the allow list'
            )

        if role not in allow_list:
            allow_list[role] = {}

        if not hasattr(privilege, '__iter__'):
            privilege = [privilege]

        for priv in privilege:
            if isinstance(priv, self.privilege_class):
                priv = priv.get_name()
            if priv not in self.privileges and priv != ALL_PRIVILEGES:
                raise MissingPrivilege(
                    'Privileges must be defined before assigning them to roles'
                )
            allow_list[role][priv] = allow
        return self

    def deny(self, role, privilege=ALL_PRIVILEGES, context=None):
        """Use this method to allow a role access to a
        specific privilege or list of privileges.
        """
        return self.allow(role, privilege, context, allow=False)

    def role_has_privilege(self, role, privilege, context=None):
        if context not in self.allow_list:
            self.allow_list[context] = {}
        allow_list = self.allow_list[context]
        if isinstance(role, self.role_class):
            role = role.get_name()
        if isinstance(privilege, self.privilege_class):
            privilege = privilege.get_name()
        return privilege in allow_list[role]

    def active_role_is(self, role):
        """You must use this method to set the active role
        before calling Acl.isAllowed(privilege). This method
        should be called when the acl object is built with
        roles, privileges and it's allow list.
        """
        if isinstance(role, self.role_class):
            role = role.get_name()

        if role not in self.roles:
            raise MissingRole('Roles must be defined before ' \
            'setting them active')

        self.active_role = role

        return self

    def set_active_role(self, role):
        """Just alias for self.active_role_is()"""
        return self.active_role_is(role)

    def is_allowed(self, privilege, context=None, undef=False):
        """This method returns a True or False based on the allow
        list if a role has access to that privilege. If Guest (role)
        has access to Page1 (privilege), then calling
        Acl.isAllowed('Page1') will return True. If Guest doesn't have
        access - it will return False.
        """
        if context not in self.allow_list:
            self.allow_list[context] = {}

        allow_list = self.allow_list[context]

        if not self.active_role:
            raise MissingActiveRole('A role must be set active ' \
            'before checking permissions')

        role = self.active_role
        if isinstance(role, self.role_class):
            role = role.get_name()

        if isinstance(privilege, self.privilege_class):
            privilege = privilege.get_name()

        if privilege in allow_list[role]:
            # Denied also supports
            return allow_list[role][privilege] == True

        if ALL_PRIVILEGES in allow_list[role]:
            # Denied also supports
            return allow_list[role][ALL_PRIVILEGES] == True

        # Parents support for roles
        for parent in self.roles[role].get_parents():
            self.active_role_is(parent)
            allow = self.is_allowed(privilege, context, None)
            if allow is not None:
                return allow

        # Hierarchical support for roles
        if '.' in role:
            parent = role.rsplit('.', 1).pop(0)
            self.active_role_is(parent)
            allow = self.is_allowed(privilege, context, None)
            if allow is not None:
                return allow

        self.active_role_is(role)

        # Hierarchical support for privileges
        if '.' in privilege:
            parent = privilege.rsplit('.', 1).pop(0)
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

    def add_from_json(self, json_data, context=None):
        """You can store your roles, privileges and allow list (many to many)
        in a json encoded string and pass it into this method to build
        the object without having to call add_role or add_privilege for each
        one. TODO: make better documentation for this method.
        """

        clean = json.loads(json_data)
        if 'roles' in clean:
            for value in clean['roles']:
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
    def obj_from_json(cls, json_data):
        """You can store your roles, privileges and allow list (many to many)
        in a json encoded string and pass it into this method to build
        the object without having to call add_role or add_privilege for each
        one. TODO: make better documentation for this method.
        """

        obj = cls()
        obj.add_from_json(json_data)
        return obj
