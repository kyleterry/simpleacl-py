import unittest

import simpleacl
from simpleacl.exceptions import MissingRole, MissingResource,\
        MissingActiveRole
from nose.tools import raises

class TestSimpleAcl(unittest.TestCase):

    def setUp(self):
        self.acl = simpleacl.Acl()

    def tearDown(self):
        self.acl = None

    def test_role_gets_added(self):
        self.acl.add_role('role1')
        assert len(self.acl.roles) > 0

    def test_role_object_gets_added(self):
        role = simpleacl.Role('role1')
        self.acl.add_role(role)
        assert len(self.acl.roles) > 0

    @raises(Exception)
    def test_only_role_objects_and_strings_get_added(self):
        self.acl.add_role(dict(a='b'))

    def test_resource_gets_added(self):
        self.acl.add_resource('resource1')
        assert len(self.acl.resources) > 0

    def test_resource_object_gets_added(self):
        resource = simpleacl.Resource('resource1')
        self.acl.add_resource(resource)
        assert len(self.acl.resources) > 0

    @raises(Exception)
    def test_only_resource_objects_and_strings_get_added(self):
        self.acl.add_resource(dict(a='b'))

    def test_role_stored_is_role_object(self):
        self.acl.add_role('role1')
        assert isinstance(self.acl.roles['role1'], simpleacl.Role)

    def test_resource_stored_is_resource_object(self):
        self.acl.add_resource('resource1')
        assert isinstance(self.acl.resources['resource1'], simpleacl.Resource)

    def test_setting_active_role(self):
        self.acl.add_role('role1')
        self.acl.add_role('role2')
        self.acl.add_resource('resource1')
        self.acl.active_role_is('role1')
        assert self.acl.active_role == 'role1'

    @raises(MissingRole)
    def test_cant_set_to_missing_role(self):
        self.acl.active_role_is('role666')

    def test_allow_role_to_resource(self):
        self.acl.add_role('role1')
        self.acl.add_resource('resource1')
        self.acl.allow('role1', 'resource1')
        assert self.acl.role_has_resource('role1', 'resource1')

    def test_role_does_not_have_resource(self):
        self.acl.add_role('role1')
        self.acl.add_resource('resource1')
        self.acl.allow('role1', 'resource1')
        assert not self.acl.role_has_resource('role1', 'resource666')

    def test_active_role_is_allowed(self):
        self.acl.add_role('role1')
        self.acl.add_role('role2')
        self.acl.add_resource('resource1')
        self.acl.add_resource('resource2')
        self.acl.allow('role1', 'resource2')
        self.acl.active_role_is('role1')
        assert self.acl.is_allowed('resource2')

    def test_active_role_is_not_allowed(self):
        self.acl.add_role('role1')
        self.acl.add_role('role2')
        self.acl.add_resource('resource1')
        self.acl.add_resource('resource2')
        self.acl.allow('role1', 'resource2')
        self.acl.active_role_is('role1')
        assert not self.acl.is_allowed('resource1')

    @raises(MissingRole)
    def test_cant_allow_missing_roles(self):
        self.acl.add_role('role1')
        self.acl.add_resource('resource2')
        self.acl.allow('role222', 'resource2')

    @raises(MissingResource)
    def test_cant_allow_missing_resources(self):
        self.acl.add_role('role1')
        self.acl.add_resource('resource1')
        self.acl.allow('role1', 'resource222')

    def test_allow_role_to_all_resources(self):
        self.acl.add_role('role1')
        self.acl.add_resource('r1')
        self.acl.add_resource('r2')
        self.acl.add_resource('r3')
        self.acl.allow('role1', 'all')
        self.acl.active_role_is('role1')
        assert self.acl.is_allowed('r1')
        assert self.acl.is_allowed('r2')
        assert self.acl.is_allowed('r3')

    def test_ignores_on_double_allow(self):
        self.acl.add_role('role1')
        self.acl.add_resource('r1')
        self.acl.add_resource('r2')
        self.acl.allow('role1', 'r1')
        self.acl.allow('role1', 'r1')

    @raises(MissingActiveRole)
    def test_cant_check_is_allowed_without_active_role(self):
        self.acl.add_role('role1')
        self.acl.add_resource('r1')
        self.acl.allow('role1', 'r1')
        self.acl.is_allowed('r1')

    def test_object_creation_from_json(self):
        import json
        test_dict = {'roles': ['role1', 'role2'], 'resources': ['r1', 'r2',
            'r3']}
        test_json = json.dumps(test_dict)
        acl = simpleacl.Acl.obj_from_json(test_json)
        assert isinstance(acl, simpleacl.Acl)
