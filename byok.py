from barbicanclient import orders
from barbicanclient import exceptions
from barbicanclient import client
from keystoneclient.auth import identity
from keystoneclient import session
from math import ceil
from configobj import ConfigObj
import base64


ROOT_SECRET_CIPHER = u'AES'
ROOT_SECRET_LENGTH = 256
ROOT_SECRET_MODE = u'CBC'
ROOT_SECRET_NAME = u'Swift BYOK secret'
ROOT_SECRET_TYPE = u'symmetric'

auth = identity.v2.Password(auth_url='http://172.16.21.3:5000/v2.0',
                            username='admin',
                            password='password',
                            tenant_name='demo')
sess = session.Session(auth=auth)
barbican = client.Client(session=sess, endpoint='http://172.16.21.3:9311')
#'QW5fZXhhbXBsZV9vZl9BRVNfa2V5X2Zvcl9CWU9LeHg='

config = ConfigObj('/etc/swift/proxy-server.conf')
payload = ''
secret_ref = ''
#payload = raw_input("Enter root secret payload in base64: ")
if not barbican.secrets.list(name=ROOT_SECRET_NAME) or \
  config['filter:keymaster']['encryption_root_secret_id']=='':
    while payload=='' or \
      not type(payload) is str or \
      len(payload)/4 != ceil(float(ROOT_SECRET_LENGTH)/24) or \
      base64.b64encode(base64.b64decode(payload)).strip()!=payload.strip():
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
        if secret_ref != '':
    #        retrieved_secret = barbican.secrets.get(secret_ref)
            config['filter:keymaster']['encryption_root_secret_id']=secret_ref
            config.write()
            print "Stored: " + secret.payload
    except exceptions.PayloadException as err:
        print 'PayloadException:', err
else:
    retrieved_secret = config['filter:keymaster']['encryption_root_secret_id']
    root_secret_b64 = barbican.secrets.get(retrieved_secret).payload
    print "Retrieved: " + root_secret_b64
