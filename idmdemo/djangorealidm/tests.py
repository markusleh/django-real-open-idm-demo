from django.test import TestCase, SimpleTestCase
from .models import User, Group, Grant
from river.models import State
import django.contrib.auth.models as authModels
from django.urls import reverse
from django.contrib.auth.models import Permission
from .views import superuser_or_approver
from django.contrib.auth.hashers import make_password
from django.utils import timezone
import datetime
from .utils import check_grant_in_effect, LDAPSync
import random


def random_name():
    return random.randint(1,10000000)


class IdmTests(TestCase):
    fixtures = ['newfixtures']

    def setUp(self):
        self.testUser = authModels.User(username="testuser", password=make_password("password"))
        self.testUser.is_staff = True
        self.testUser.save()
        self.approver_group = authModels.Group.objects.get(name="approver")
        self.testUser.groups.add(self.approver_group)
        self.state1 = State.objects.get(slug="needs-approval")
        self.user1 = User.objects.get(pk=1)
        self.group1 = Group.objects.get(pk=1)
        self.group2 = Group.objects.get(pk=2)
        self.grant1 = Grant.objects.create(group_id=self.group1.id, user_id=self.user1.id, status=self.state1)

class SiteTests(TestCase):
    fixtures = ['newfixtures']

    def setUp(self):
        self.testUser = authModels.User.objects.create(username="testuser")
        self.approver_group = authModels.Group.objects.get(name="approver")
        self.testUser.groups.add(self.approver_group)
        self.state1 = State.objects.get(slug="needs-approval")
        self.user1 = User.objects.get(pk=1)
        self.group1 = Group.objects.get(pk=1)
        self.grant1 = Grant.objects.create(group_id=self.group1.id, user_id=self.user1.id, status=self.state1)

    def testFixtureLoadedUserExists(self):
        self.user1 = User.objects.get(pk=1)
        self.assertEquals(self.user1.username, 'user1')

    def testFixtureLoadedGroupExists(self):
        self.group1 = Group.objects.get(pk=1)
        self.assertEquals(self.group1.name, 'group1')

    def testFixtureState1Exists(self):
        self.state1 = State.objects.get(slug="needs-approval")

    def testGrantNeedsApproval(self):
        approvals = Grant.river.status.get_available_approvals(as_user=self.testUser)
        self.assertEqual(approvals[0].groups.all()[0], self.approver_group)


class ReportIndexViewTests(TestCase):
    def test_index_no_error(self):
        response = self.client.get(reverse('index'))
        self.assertEqual(response.status_code, 200)


class ReportHistoryViewTests(IdmTests):
    def test_report_no_error(self):
        self.assertTrue(self.client.login(username='testuser', password="password"))
        response = self.client.get(reverse('history-report'))
        self.assertTrue(superuser_or_approver(self.testUser))
        self.assertEqual(response.status_code, 200)

    def test_report_bad_permission(self):
        anotherTestUser = authModels.User(username="testuser-normal", password=make_password("password"))
        anotherTestUser.is_staff = True
        anotherTestUser.save()
        self.assertTrue(self.client.login(username="testuser-normal", password="password"))
        response = self.client.get(reverse('history-report'), follow=True)
        SimpleTestCase.assertRedirects(self, response=response, expected_url="/admin/")

    def test_basic_report_contains_grant(self):
        self.assertTrue(self.client.login(username='testuser', password="password"))
        response = self.client.get(reverse('basic-report'))
        self.assertContains(response, "needs-approval")

    def test_history_report_not_contains_unapproved_grant(self):
        self.assertTrue(self.client.login(username='testuser', password="password"))
        response = self.client.get(reverse('history-report'))
        self.assertNotContains(response, "needs-approval")

    def test_history_report_contains_approved_grant(self):
        self.assertTrue(self.client.login(username='testuser', password="password"))
        self.grant1.river.status.approve(as_user=self.testUser)
        response = self.client.get(reverse('history-report'))
        self.assertContains(response, "approved")
        self.assertContains(response, "testuser")

    def test_basic_report_csv_no_error(self):
        self.assertTrue(self.client.login(username='testuser', password="password"))
        response = self.client.get(reverse('basic-report'), data={"csv": True})
        self.assertContains(response, "user1")

class UtilsTests(IdmTests):
    def test_grant_in_effect_not_before_fails(self):
        now = timezone.now()
        not_before = now + datetime.timedelta(hours=1)
        grant = Grant.objects.create(
            group_id=self.group2.id,
            user_id=self.user1.id,
            status=self.state1,
            not_valid_before=not_before)
        self.assertEquals(check_grant_in_effect(grant), False)

    def test_grant_in_effect_not_before_succeeds(self):
        now = timezone.now()
        not_before = now - datetime.timedelta(hours=1)
        grant = Grant.objects.create(
            group=Group.objects.create(name="yetanothergroup"),
            user_id=self.user1.id,
            status=self.state1,
            not_valid_before=not_before)
        self.assertEquals(check_grant_in_effect(grant), True)

    def test_grant_in_effect_not_after_fails(self):
        now = timezone.now()
        not_before = now - datetime.timedelta(hours=1)
        not_after = now - datetime.timedelta(minutes=1)
        grant = Grant.objects.create(
            group=Group.objects.create(name="group{}".format(random_name())),
            user_id=self.user1.id,
            status=self.state1,
            not_valid_before=not_before,
            not_valid_after=not_after
        )
        self.assertEquals(check_grant_in_effect(grant), False)

    def test_grant_in_effect_not_after_succeeds(self):
        now = timezone.now()
        not_before = now - datetime.timedelta(hours=1)
        not_after = now + datetime.timedelta(minutes=1)
        grant = Grant.objects.create(
            group=Group.objects.create(name="group{}".format(random_name())),
            user_id=self.user1.id,
            status=self.state1,
            not_valid_before=not_before,
            not_valid_after=not_after
        )
        self.assertEquals(check_grant_in_effect(grant), True)


class LdapTests(TestCase):
    fixtures = ['newfixtures']

    def setUp(self):
        self.user1 = User.objects.get(pk=1)
        self.user2 = User.objects.get(pk=2)
        self.group1 = Group.objects.get(pk=1)
        self.s = LDAPSync()
        self.s.sync_user_unique_id(self.user1)
        self.s.sync_user_unique_id(self.user2)

    def test_sync_user1_already_in_group(self):
        # Initial DB sync
        members = self.s.get_members_in_group("cn=group1,ou=Groups,dc=idptestbed")
        self.assertIn(User.objects.get(pk=1).unique_id, members)

    def test_sync_user2_add_in_group(self):
        members = self.s.get_members_in_group("cn=group1,ou=Groups,dc=idptestbed")
        self.assertNotIn(self.user2.unique_id, members)
        self.s.sync_users_groups([self.user2, self.user1], [self.group1])
        members = self.s.get_members_in_group("cn=group1,ou=Groups,dc=idptestbed")
        self.assertIn(self.user2.unique_id, members)



