from barbicanclient import orders
from barbicanclient import exceptions
from barbicanclient import client
from keystoneclient.auth import identity
from keystoneclient import session
from math import ceil
from configobj import ConfigObj
import base64
import re

ROOT_SECRET_CIPHER = u'AES'
ROOT_SECRET_LENGTH = 256
ROOT_SECRET_MODE = u'CBC'
ROOT_SECRET_NAME = u'Swift BYOK secret'
ROOT_SECRET_TYPE = u'symmetric'

auth = identity.v2.Password(auth_url='http://172.16.21.3:5000/v2.0',
                            username='barbican',
                            password='password',
                            tenant_name='service')
sess = session.Session(auth=auth)
barbican = client.Client(session=sess, endpoint='http://172.16.21.3:9311')
#'QW5fZXhhbXBsZV9vZl9BRVNfa2V5X2Zvcl9CWU9LeHg='

config = ConfigObj('/etc/swift/proxy-server.conf')

secret_ref = config['filter:keymaster']['encryption_root_secret_id']
secret_id = secret_ref[-36:]
uuid_pattern = re.compile(r'^[\da-f]{8}-([\da-f]{4}-){3}[\da-f]{12}$', re.IGNORECASE)

payload = raw_input("Enter root secret payload in base64: ")
if not uuid_pattern.match(secret_id):
    # A base64 secret must breakable in groups of 24-bit groups
    # of input bits  as output strings of 4 encoded charactersts
    # encoded on 6 bits, following recommendations from RFC 4648
    b64_pattern = re.compile(r'^[A-Za-z0-9+/]+[=]{0,2}$')
    while not b64_pattern.match(payload.strip()) or \
    len(payload)/4 != int(ceil(float(ROOT_SECRET_LENGTH)/24)):
        payload = raw_input("Enter root secret payload in base64: ")

    try:
        secret = barbican.secrets.create(name=ROOT_SECRET_NAME,
                                            algorithm=ROOT_SECRET_CIPHER,
                                            bit_length=ROOT_SECRET_LENGTH,
                                            mode=ROOT_SECRET_MODE,
                                            payload=payload,
                                            secret_type=ROOT_SECRET_TYPE,
                                            expiration=None)
        secret_ref = secret.store()
        config['filter:keymaster']['encryption_root_secret_id']=secret_ref
        config.write()
    except exceptions.PayloadException as err:
        print 'PayloadException:', err

root_secret_b64 = base64.b64encode(barbican.secrets.get(secret_ref).payload)
print root_secret_b64
