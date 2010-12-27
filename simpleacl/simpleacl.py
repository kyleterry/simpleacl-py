#######################################################################
# Simpleacl - A small access control list
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
import string
import sys
version = string.split(string.split(sys.version)[0], ".")
if map(int, version) < [2, 6, 0]:
    try:
        import simplejson as json
    except:
        raise Exception("""This method will work natively
        with Python 2.6.x+. In order to use it with versions 
        under 2.6.x, you must install the simplejson lib.""")

else:
    import json

from exceptions import MissingRole, MissingResource, MissingActiveRole

class Role:
    """Holds a role value"""

    def __init__(self, name):
        self.name = name

    def get_name(self):
        return self.name

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

    def add_role(self, role):
        """Adds a role by instantiating a new Role object.
        "role" can be a string or Role object when calling
        this method.
        """
        if (type(role).__name__=='str') or (type(role).__name__=='unicode'):
            self.roles[role] = Role(role)
            self.allow_list[role] = {}
        elif (type(role).__name__=='instance') and \
        (role.__class__.__name__=='Role'):
            self.roles[role.get_name()] = role
            self.allow_list[role] = {}
        else:
            raise Exception('Unable to add role of type: %s' % \
            (type(role).__name__))

        return self

    def add_resource(self, resource):
        """Adds a resource to the list of resources by
        instantiating a new Resource object. "resource"
        can be a string or Resource object when calling
        this method.
        """
        if (type(resource).__name__=='str') or \
        (type(resource).__name__=='unicode'):
            self.resources[resource] = Resource(resource)
        elif (type(resource).__name__=='instance') and \
        (resource.__class__.__name__=='Resource'):
            self.resources[resource.get_name()] = resource
        else:
            raise Exception('Unable to add role of type: %s' % \
            (type(resource).__name__))

        return self

    def allow(self, role, resource):
        """Use this method to allow a role access to a
        specific resource or list of resources.
        """
        if not self.roles.has_key(role):
            raise MissingRole('Roles must be defined before adding ' \
            'them to the allow list')
        if (type(resource).__name__=='str') and resource=='all':
            for res in self.resources:
                self.allow_list[role][res] = True
            return self
        if type(resource).__name__=='str':
            resource = [resource]
        for res in resource:
            if not self.resources.has_key(res):
                raise MissingResource('Resources must be defined ' \
                'before assigning them to roles')
            if self.allow_list[role].has_key(res):
                continue
            self.allow_list[role][res] = True
        return self

    def role_has_resource(self, role, resource):
        if isinstance(role, str):
            role = Role(role)
        if isinstance(resource, str):
            resource = Resource(resource)
        if self.allow_list[role.get_name()].has_key(resource.get_name()):
            return True
        return False

    def active_role_is(self, role):
        """You must use this method to set the active role
        before calling Acl.isAllowed(resource). This method
        should be called when the acl object is built with
        roles, resources and it's allow list.
        """
        if not self.roles.has_key(role):
            raise MissingRole('Roles must be defined before ' \
            'setting them active')

        self.active_role = role

        return self

    def is_allowed(self, resource):
        """This method returns a True or False based on the allow
        list if a role has access to that resource. If Guest (role)
        has access to Page1 (resource), then calling
        Acl.isAllowed('Page1') will return True. If Guest doesn't have
        access - it will return False.
        """
        if not self.active_role:
            raise MissingActiveRole('A role must be set active ' \
            'before checking permissions')

        if (self.allow_list[self.active_role].has_key(resource)) and \
        (self.allow_list[self.active_role][resource]==True):
            return True

        return False

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
