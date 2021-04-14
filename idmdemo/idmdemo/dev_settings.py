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
        'NAME': Path.joinpath(BASE_DIR, "db", 'db.sqlite3'),
    }
}

REAL_IDM = {
    'LDAP_SERVER': "",              # required, server address e.g. '192.168.1.1'
    'LDAP_SEARCH_BASE': "",         # required, where the groups and users are located e.g. 'dc=win,dc=local'
    'LDAP_SYNC_MODE': "TWO_WAY",    # required TODO: description
    'LDAP_BIND_USER': "",           # optional, bind user e.g. bind@win.local
    'LDAP_BIND_PASSWD': "",         # optional
    'LDAP_USER_ATTRIBUTE': "",      # optional, mapping for User.username and AD attribute name used to search the user from AD. Defaults to 'sAMAccountName'
    'LDAP_USER_OBJECTCLASS': "",    # optional, e.g. posixGroup, default: 'group' (AD)
    'LDAP_GROUP_ATTRIBUTE': "",     # optional, mapping for Group.name and AD attribute name used to search the group from AD. Defaults to 'cn'
    'LDAP_GROUP_OBJECTCLASS': "",   # optional, e.g. person, default: 'person' (AD)
    'LDAP_UNIQUE_ATTRIBUTE': "",    # optional, e.g. 'objectSID', default: 'objectSID' (AD)
    'LDAP_MEMBER_ATTRIBUTE': "",     # optional, how to find LDAP_UNIQUE_ATTRIBUTE e.g. 'member', default: 'member' (AD)
    'LDAP_MEMBER_OBJECT_ATTRIBUTE': "" # optional, format of the user object inside LDAP_MEMBER_ATTRIBUTE e.g. 'dn', default: 'dn' (AD)
}
