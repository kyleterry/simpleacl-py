import unittest

import rpdb2; rpdb2.start_embedded_debugger('111')
import simpleacl
from exceptions import MissingRole, MissingPrivilege,\
    MissingActiveRole
from simpleacl import json


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

    def test_only_role_objects_and_strings_get_added(self):
        self.acl.add_role(dict(a='b'))

    def test_privilege_gets_added(self):
        self.acl.add_privilege('privilege1')
        assert len(self.acl.privileges) > 0

    def test_privilege_object_gets_added(self):
        privilege = simpleacl.Privilege('privilege1')
        self.acl.add_privilege(privilege)
        assert len(self.acl.privileges) > 0

    def test_only_privilege_objects_and_strings_get_added(self):
        self.acl.add_privilege(dict(a='b'))

    def test_role_stored_is_role_object(self):
        self.acl.add_role('role1')
        assert isinstance(self.acl.roles['role1'], simpleacl.Role)

    def test_privilege_stored_is_privilege_object(self):
        self.acl.add_privilege('privilege1')
        assert isinstance(self.acl.privileges['privilege1'], simpleacl.Privilege)

    def test_setting_active_role(self):
        self.acl.add_role('role1')
        self.acl.add_role('role2')
        self.acl.add_privilege('privilege1')
        self.acl.active_role_is('role1')
        assert self.acl.active_role == 'role1'

    def test_cant_set_to_missing_role(self):
        self.acl.active_role_is('role999')

    def test_allow_role_to_privilege(self):
        self.acl.add_role('role1')
        self.acl.add_privilege('privilege1')
        self.acl.allow('role1', 'privilege1')
        assert self.acl.role_has_privilege('role1', 'privilege1')

    def test_role_does_not_have_privilege(self):
        self.acl.add_role('role1')
        self.acl.add_privilege('privilege1')
        self.acl.allow('role1', 'privilege1')
        assert not self.acl.role_has_privilege('role1', 'privilege999')

    def test_active_role_is_allowed(self):
        self.acl.add_role('role1')
        self.acl.add_role('role2')
        self.acl.add_privilege('privilege1')
        self.acl.add_privilege('privilege2')
        self.acl.allow('role1', 'privilege2')
        self.acl.active_role_is('role1')
        assert self.acl.is_allowed('privilege2')

    def test_active_role_is_not_allowed(self):
        self.acl.add_role('role1')
        self.acl.add_role('role2')
        self.acl.add_privilege('privilege1')
        self.acl.add_privilege('privilege2')
        self.acl.allow('role1', 'privilege2')
        self.acl.active_role_is('role1')
        assert not self.acl.is_allowed('privilege1')

    def test_cant_allow_missing_roles(self):
        self.acl.add_role('role1')
        self.acl.add_privilege('privilege2')
        self.acl.allow('role222', 'privilege2')

    def test_cant_allow_missing_privileges(self):
        self.acl.add_role('role1')
        self.acl.add_privilege('privilege1')
        self.acl.allow('role1', 'privilege222')

    def test_allow_role_to_all_privileges(self):
        self.acl.add_role('role1')
        self.acl.add_privilege('r1')
        self.acl.add_privilege('r2')
        self.acl.add_privilege('r3')
        self.acl.allow('role1', 'all')
        self.acl.active_role_is('role1')
        assert self.acl.is_allowed('r1')
        assert self.acl.is_allowed('r2')
        assert self.acl.is_allowed('r3')

    def test_ignores_on_double_allow(self):
        self.acl.add_role('role1')
        self.acl.add_privilege('r1')
        self.acl.add_privilege('r2')
        self.acl.allow('role1', 'r1')
        self.acl.allow('role1', 'r1')

    def test_cant_check_is_allowed_without_active_role(self):
        self.acl.add_role('role1')
        self.acl.add_privilege('r1')
        self.acl.allow('role1', 'r1')
        self.acl.is_allowed('r1')

    def test_object_creation_from_json(self):
        test_dict = {'roles': ['role1', 'role2'], 'privileges': ['r1', 'r2',
            'r3']}
        test_json = json.dumps(test_dict)
        acl = simpleacl.Acl.obj_from_json(test_json)
        assert isinstance(acl, simpleacl.Acl)

if __name__ == '__main__':
    unittest.main()
