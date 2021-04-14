from ldap3 import Server, Connection, ALL, NTLM, Reader, ObjectDef, SUBTREE
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups as addUsersInGroups
from ldap3.extend.microsoft.removeMembersFromGroups import ad_remove_members_from_groups as removeUsersInGroups
from django.conf import settings
from django.utils import timezone
from .models import *


def check_grant_in_effect(grant_obj):
    if grant_obj.not_valid_before and grant_obj.not_valid_after:
        return grant_obj.not_valid_before <= timezone.now() <= grant_obj.not_valid_after
    else:
        return grant_obj.not_valid_before <= timezone.now()


class UserNotFoundException(Exception):
    def __init__(self, query, message="User was not found"):
        self.query = query
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f'{self.query} -> {self.message}'


class Sync(object):
    def __init__(self):
        uri = settings.REAL_IDM["LDAP_SERVER"]
        dn = settings.REAL_IDM.get("LDAP_BIND_USER")
        password = settings.REAL_IDM.get("LDAP_BIND_PASSWD")
        self.ldap_user_attr = settings.REAL_IDM.get("LDAP_USER_ATTRIBUTE", "sAMAccountName")
        self.ldap_group_attr = settings.REAL_IDM.get("LDAP_GROUP_ATTRIBUTE", "cn")
        self.search_base = settings.REAL_IDM["LDAP_SEARCH_BASE"]
        self.sync_mode = settings.REAL_IDM.get("LDAP_SYNC_MODE")
        self.conn = self.ldap_begin(uri, dn, password)
        self.user_def = ObjectDef([
            settings.REAL_IDM.get("LDAP_USER_OBJECTCLASS", "person"),
        ], self.conn)
        self.group_def = ObjectDef([
            settings.REAL_IDM.get("LDAP_GROUP_OBJECTCLASS", "group")
        ], self.conn)
        self.uid_attr = settings.REAL_IDM.get("LDAP_UNIQUE_ATTRIBUTE", "objectGUID")
        self.member_attr = settings.REAL_IDM.get("LDAP_MEMBER_ATTRIBUTE", "member")
        self.member_obj_attr = settings.REAL_IDM.get("LDAP_MEMBER_OBJECT_ATTRIBUTE", "dn")

    def ldap_begin(self, uri, dn=None, password=None, port=389, use_ssl=False):
        server = Server(uri, get_info=ALL)
        conn = Connection(server, dn, password, auto_bind=True)
        return conn

    def find_user_by_username(self, username: str):
        user_def = self.user_def
        user_def += [self.uid_attr, self.ldap_user_attr]
        person_reader = Reader(self.conn, user_def, self.search_base, "{}:{}".format(self.ldap_user_attr, username))
        results = person_reader.search()
        try:
            userUid = results[0][self.uid_attr]
        except Exception as e:
            print("User {} cannot be found".format(username), e)
            return

        return userUid

    def get_user_dn(self, user: User):
        uid = user.unique_id
        user_def = self.user_def
        user_def += self.uid_attr
        person_reader = Reader(self.conn, user_def, self.search_base, "({}={})".format(self.uid_attr, uid))
        results = person_reader.search()
        try:
            dn = results[0].entry_dn
            return dn
        except IndexError as e:
            print("User {} cannot be found".format(user), e)
            return

    def get_group_dn(self, group: Group):
        group_def = self.group_def
        group_def += [self.ldap_group_attr]
        results = Reader(self.conn, group_def, self.search_base, "({}={})".format(self.ldap_group_attr, group.name)).search()
        try:
            dn = results[0].entry_dn
            return dn
        except IndexError as e:
            print("User {} cannot be found".format(group), e)
            return

    def sync_user_unique_id(self, user: User, force=False):
        if user.unique_id is not None and not force:
            print("User: '{}' already has unique_id: '{}'".format(user.username, user.unique_id))
        else:
            uid = self.find_user_by_username(user.username)
            print("User: '{}' saved unique_id: '{}'".format(user.username, uid))
            user.unique_id = uid
            user.save()

    def user_attribute_map(self, value: str, from_attribute: str, to_attribute:str):
        user_def = self.user_def
        if from_attribute == "dn":
            reader = Reader(self.conn, user_def, value)
        else:
            user_def += from_attribute
            user_def += to_attribute
            query = "{}:{}".format(from_attribute, value)
            reader = Reader(self.conn, user_def, self.search_base, query)
        results = reader.search()
        try:
            userValue = results[0][to_attribute]
        except Exception as e:
            raise UserNotFoundException(value)

        return userValue

    def get_members_in_group(self, groupDn: str):
        group_def = self.group_def
        #group_def += [self.uid_attr, self.ldap_group_attr, "member", self.member_attr]

        results = Reader(self.conn, group_def, groupDn).search()
        try:
            print(results[0][self.member_attr])
            group_members = results[0][self.member_attr]
            membersUids = [str(self.user_attribute_map(userMemberAttr, self.member_obj_attr, self.uid_attr)) for userMemberAttr in group_members]
        except IndexError as e:
            print("Group {} cannot be found".format(groupDn), e)
            raise

        return membersUids

    def add_user_to_group(self, user: User, groupDn: str):
        userDn = self.get_user_dn(user)
        print("Adding user {} to group {}".format(userDn, groupDn))
        addUsersInGroups(self.conn, userDn, groupDn, raise_error=True)

    def remove_user_from_group(self, user: User, groupDn: str):
        userDn = self.get_user_dn(user)
        print("Removing user: '{}' from group '{}'".format(userDn, groupDn))
        removeUsersInGroups(self.conn, userDn, groupDn, fix=True, raise_error=True)

    def sync_users_single_group(self, users: [User], group: Group):
        group_dn = self.get_group_dn(group)
        users_in_group = self.get_members_in_group(group_dn)
        print("Users in group: '{}': {}".format(group, users_in_group))
        for user in users:
            if user.unique_id not in users_in_group:
                print(f"ID: '{user.unique_id} not in {users_in_group}")
                self.add_user_to_group(user, group_dn)

        group_diff = list(set(users_in_group) - set([user.unique_id for user in users])) # Users in LDAP group that shouldn't be
        for user_uid in group_diff:
            print(f"ID: '{user.unique_id} in {users_in_group}, should not be")
            user_obj = User.objects.get(unique_id=user_uid)
            self.remove_user_from_group(user_obj, group_dn)

    def sync_users_groups(self, users: [User], groups: [Group]):
        for group in groups:
            self.sync_users_single_group(users, group)
        return

