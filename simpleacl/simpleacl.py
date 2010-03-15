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


class Role:
    """Holds a role value"""
    def __init__(self, name):
        self.name = name

    def getName(self):
        return self.name


class Resource:
    """Holds a resource value"""
    def __init__(self, name):
        self.name = name

    def getName(self):
        return self.name

class MissingRole(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class MissingActiveRole(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class MissingResource(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class Acl:
    """A simple class to manage an 
       access control list"""
    roles = {}
    resources = {}
    allow_list = {}
    active_role = None

    def addRole(self, role):
        if (type(role).__name__=='str') or (type(role).__name__=='unicode'):
            self.roles[role] = Role(role)
            self.allow_list[role] = {}
        elif (type(role).__name__=='instance') and (role.__class__.__name__=='Role'):
            self.roles[role.getName()] = role
            self.allow_list[role] = {}
        else:
            raise Exception('Unable to add role of type: %s' % (type(role).__name__))

        return self

    def addResource(self, resource):
        if (type(resource).__name__=='str') or (type(resource).__name__=='unicode'):
            self.resources[resource] = Resource(resource)
        elif (type(resource).__name__=='instance') and (resource.__class__.__name__=='Resource'):
            self.resources[resource.getName()] = resource
        else:
            raise Exception('Unable to add role of type: %s' % (type(resource).__name__))

        return self

    def allow(self, role, resource):
        if not self.roles.has_key(role):
            raise MissingRole('Roles must be defined before adding them to the allow list')

        if not resource:
            return

        if (type(resource).__name__=='str') and resource=='all':
            for res in self.resources:
                self.allow_list[role][res] = True
            return self

        if type(resource).__name__=='str':
            resource = [resource]

        for res in resource:
            if not self.resources.has_key(res):
                raise MissingResource('Resources must be defined before assigning them to roles')
            if self.allow_list[role].has_key(res):
                continue
            self.allow_list[role][res] = True

        return self

    def activeRoleIs(self, role):
        if not self.roles.has_key(role):
            raise MissingRole('Roles must be defined before setting them active')

        self.active_role = role

        return self

    def isAllowed(self, resource):
        if not self.active_role:
            raise MissingActiveRole('A role must be set active before checking permissions')

        if (self.allow_list[self.active_role].has_key(resource)) and \
        (self.allow_list[self.active_role][resource]==True):
            return True

        return False

    def loadFromJson(self, json_data):
        import string
        import sys
        version = string.split(string.split(sys.version)[0], ".")
        if map(int, version) < [2, 6, 0]:
            try:
                import simplejson as json
            except:
                raise Exception('This method will work natively with Python 2.6.x+. In order to use it with\
                versions under 2.6.x, you must install the simplejson lib.')

        else:
            import json

        clean = json.loads(json_data)

        for value in clean['roles']:
            self.addRole(value)

        for value in clean['resources']:
            self.addResource(value)

        return self
