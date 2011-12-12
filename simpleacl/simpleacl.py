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

from exceptions import MissingRole, MissingResource, MissingActiveRole


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


class Resource:
    """Holds a resource value"""

    def __init__(self, name):
        self.name = name

    def get_name(self):
        return self.name


class Acl:
    """A simple class to manage an
       access control list.
    """
    roles = {}
    resources = {}
    allow_list = {}
    active_role = None

    role_class = Role
    resource_class = Resource

    def add_role(self, role, parents=[]):
        """Adds a role by instantiating a new Role object.
        "role" can be a string or Role object when calling
        this method.
        """
        if not isinstance(role, self.role_class):
            if not isinstance(role, (str, unicode)):
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

        for parent in parents:
            parent = self.add_role(parent)
            role.add_parent(parent)

        return role

    def add_resource(self, resource):
        """Adds a resource to the list of resources by
        instantiating a new Resource object. "resource"
        can be a string or Resource object when calling
        this method.
        """
        if not isinstance(resource, self.resource_class):
            if not isinstance(resource, (str, unicode)):
                raise Exception(
                    'Unable to add resource of type: {0}'\
                        .format(type(resource).__name__)
                )
            if resource in self.resources:
                resource = self.resources[resource]
            else:
                resource = self.resource_class(resource)

        if resource.get_name() not in self.resources:
            self.resources[resource.get_name()] = resource

        return resource

    def allow(self, role, resource='all', context=None, allow=True):
        """Use this method to allow a role access to a
        specific resource or list of resources.
        """
        if context not in self.allow_list:
            self.allow_list[context] = {}
        allow_list = self.allow_list[context]

        if isinstance(role, self.role_class):
            role = role.get_name()

        if role not in self.roles:
            raise MissingRole('Roles must be defined before adding ' \
            'them to the allow list')

        if role not in allow_list:
            allow_list[role] = {}

        if not hasattr(resource, '__iter__'):
            resource = [resource]

        for res in resource:
            if isinstance(res, self.resource_class):
                res = res.get_name()
            if res not in self.resources:
                raise MissingResource('Resources must be defined ' \
                'before assigning them to roles')
            allow_list[role][res] = allow
        return self

    def deny(self, role, resource='all', context=None):
        """Use this method to allow a role access to a
        specific resource or list of resources.
        """
        return self.allow(role, resource, context, allow=False)

    def role_has_resource(self, role, resource, context=None):
        if context not in self.allow_list:
            self.allow_list[context] = {}
        allow_list = self.allow_list[context]
        if isinstance(role, self.role_class):
            role = role.get_name()
        if isinstance(resource, self.resource_class):
            resource = resource.get_name()
        return resource in allow_list[role]

    def active_role_is(self, role):
        """You must use this method to set the active role
        before calling Acl.isAllowed(resource). This method
        should be called when the acl object is built with
        roles, resources and it's allow list.
        """
        if isinstance(role, self.role_class):
            role = role.get_name()

        if role not in self.roles:
            raise MissingRole('Roles must be defined before ' \
            'setting them active')

        self.active_role = role

        return self

    def is_allowed(self, resource, context=None, undef=False):
        """This method returns a True or False based on the allow
        list if a role has access to that resource. If Guest (role)
        has access to Page1 (resource), then calling
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

        if isinstance(resource, self.resource_class):
            resource = resource.get_name()

        if resource in allow_list[role]:
            # Denied also supports
            return allow_list[role][resource] == True

        if 'all' in allow_list[role]:
            # Denied also supports
            return allow_list[role]['all'] == True

        # Parents support for roles
        for parent in role.get_parents():
            self.active_role_is(parent)
            allow = self.is_allowed(resource, context, None)
            if allow is not None:
                return allow

        # Hierarchical support for roles
        if '.' in role:
            parent = role.rsplit('.', 1).pop(0)
            self.active_role_is(parent)
            allow = self.is_allowed(resource, context, None)
            if allow is not None:
                return allow

        self.active_role_is(role)

        # Hierarchical support for resources
        if '.' in resource:
            parent = resource.rsplit('.', 1).pop(0)
            allow = self.is_allowed(parent, context, None)
            if allow is not None:
                return allow

        # Parents support for context
        if hasattr(context, 'get_parents'):
            for parent in context.get_parents():
                allow = self.is_allowed(resource, parent, None)
                if allow is not None:
                    return allow

        return undef

    @classmethod
    def obj_from_json(cls, json_data):
        """You can store your roles, resources and allow list (many to many)
        in a json encoded string and pass it into this method to build
        the object without having to call add_role or add_resource for each
        one. TODO: make better documentation for this method.
        """

        clean = json.loads(json_data)
        obj = cls()
        for value in clean['roles']:
            obj.add_role(value)

        for value in clean['resources']:
            obj.add_resource(value)
        return obj
