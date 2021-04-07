# django-real-open-idm-demo

# Getting started

## Prerequisites

python3

## Install

1. Install requirements

```

pip install -r requirements.txt

```

2. Initiate Django

```
# run in folder with manage.py

python manage.py makemigrations
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

## Try out


1. Go to `http://localhost:8000/admin/auth/user/` and add your account (which you created using `createsuperuser` to django existing group `approver`

2. Navigate to `http://localhost:8000/admin/djangorealidm/grant/` and try to create a new grant.
