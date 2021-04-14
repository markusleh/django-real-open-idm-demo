from pathlib import Path

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-1c0j8auewfm#pazumw0(u(@r#8t!qdo*^6n_qmx+o1n_d=no&g'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []

BASE_DIR = Path(__file__).resolve().parent.parent
# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

REAL_IDM = {
    'LDAP_SERVER': "127.0.01",
    'LDAP_BIND_USER': "cn=Directory Manager",
    'LDAP_BIND_PASSWD': "password",
    'LDAP_SEARCH_BASE': "dc=idptestbed",
    'LDAP_SYNC_MODE': "TWO_WAY",
    'LDAP_USER_ATTRIBUTE': "uid",
    'LDAP_USER_OBJECTCLASS': "person",
    'LDAP_GROUP_ATTRIBUTE': "cn",
    'LDAP_GROUP_OBJECTCLASS': "posixGroup",
    'LDAP_UNIQUE_ATTRIBUTE': "nsuniqueid",
    'LDAP_MEMBER_ATTRIBUTE': "memberUid",
    'LDAP_MEMBER_OBJECT_ATTRIBUTE': "uid"
}
