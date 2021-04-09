# django-real-open-idm-demo
[![Build Status](https://travis-ci.com/markusleh/django-real-open-idm-demo.svg?branch=main)](https://travis-ci.com/markusleh/django-real-open-idm-demo) ![CodeQL](https://github.com/markusleh/django-real-open-idm-demo/workflows/CodeQL/badge.svg)

![Preview](img/demo.png)

# Demo
https://django-real-idm.herokuapp.com/admin

user: `demo`

password: `demodemo`

# Getting started

## Prerequisites

- python3.6 or newer
- Latest Ubuntu preferred. Tested with Ubuntu 20.04

## Install

1. Install requirements

```
pip install -r requirements/dev.txt
```

2. Initiate Django

```
# run in folder with manage.py
python manage.py makemigrations
python manage.py makemigrations djangorealidm
python manage.py migrate
python manage.py createsuperuser
```

3. Load demo data (optional)

```
# run in folder with manage.py

python manage.py loaddata */fixtures/*.json
```


4. Run

```
# run in folder with manage.py
python manage.py runserver
```

## Docker Install

1. install docker-compose

2. Run docker-compose build

3. Initiate Django
```
docker exec django-real-open-idm-demo_djangorealopenidmdemo_1 python manage.py makemigrations
docker exec django-real-open-idm-demo_djangorealopenidmdemo_1 python manage.py makemigrations
docker exec django-real-open-idm-demo_djangorealopenidmdemo_1 python manage.py migrate
docker exec -it django-real-open-idm-demo_djangorealopenidmdemo_1 python manage.py createsuperuser
```
4. docker-compose up -d

## Try out


1. Go to `http://localhost:8000/admin/auth/user/` and add your account (which you created using `createsuperuser` to django existing group `approver`

2. Navigate to `http://localhost:8000/admin/djangorealidm/grant/` and try to create a new grant.

# Utils

## AD: Sync approved Group membership to Active Directory

Example

Create new function in the admin-ui e.g. `function name: sync-ad`
```python
from djangorealidm.utils import Sync
from djangorealidm.models import Group, User, Grant
from river.models import State

def handle(context):
  s = Sync()
  approved_status = status=State.objects.get(slug="approved")
  groups = [group.name for group in Group.objects.all()]
  for group in groups:
  	users = [grant.user.username for grant in Grant.objects.filter(
  	    status=approved_status, 
  	    group__name=group,
  	    status_transition_approvals__isnull=False # Retrieve grants for which approval has been explicitly granted. Prevents creating grant objects with 'approved' status
  	    )]
 
  	s.sync_users_groups(users, [group])
```

Add LDAP configuration parameters in `settings.py`
```
REAL_IDM = {
    'LDAP_SERVER': "",          # required, server address e.g. '192.168.1.1'
    'SEARCH_BASE': "",          # required, where the groups and users are located e.g. 'dc=win,dc=local'
    'BIND_USER': "",            # optional, bind user e.g. bind@win.local
    'BIND_PASSWD': "",          # optional
    'LDAP_USER_ATTRIBUTE': ""   # optional, mapping for User.username and AD attribute name used to search the user from AD. Defaults to 'sAMAccountName'
}
```
Create a new `On-approved hook` to sync group membership status after new approvals have been made and attach it to your workflow.
![Preview](img/function-example.png)

# Other features
## Reports

Go to `http://localhost:8000/` for full list of reports available. Currently you are able to:

- View a basic report about current grants
- Export report to CSV

![Report-basic](img/reports-basic.png)
