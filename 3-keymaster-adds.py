from barbicanclient import orders
from barbicanclient import client
from keystoneclient.auth import identity
from keystoneclient import session
from math import ceil
from configobj import ConfigObj
import base64


ROOT_SECRET_CIPHER = u'AES'
ROOT_SECRET_LENGTH = 256
ROOT_SECRET_MODE = u'CBC'
ROOT_SECRET_NAME = u'Swift root secret'

auth = identity.v2.Password(auth_url='http://172.16.21.3:5000/v2.0',
                            username='admin',
                            password='password',
                            tenant_name='demo')
sess = session.Session(auth=auth)
barbican = client.Client(session=sess, endpoint='http://172.16.21.3:9311')
'''
class RootSecret(object):

    def __init__(self, algorithm, bit_length, mode, name=None):
        self.name = u'Swift root secret'
        self.algorithm = algorithm
        self.bit_length = bit_length
        self.mode = mode
'''
#def check_root_secret(self, secret):
def check_root_secret(secret):
    try:
        if type(secret) is str and secret != '':
            # A base64 secret must breakable in groups of 24-bit groups
            # of input bits  as output strings of 4 encoded charactersts
            # encoded on 6 bits, following recommendations from RFC 4648
#            if not base64.decodestring(secret) or len(secret)/4 != ceil(float(ROOT_SECRET_LENGTH)/24):
            if base64.b64encode(base64.b64decode(secret)).strip()!=secret.strip() or \
              len(secret)/4 != ceil(float(ROOT_SECRET_LENGTH)/24):
                raise ValueError("Root secret must be length %s bits" % ROOT_SECRET_LENGTH)
    except (TypeError, ValueError):
        raise ValueError(
            'encryption_root_secret option in proxy-server.conf must be '
            'a base64 encoding of at least 32 raw bytes')
        print('Secret must be at least %s base-64 characters.', 4*ceil(float(ROOT_SECRET_LENGTH)/24))

#def create_root_secret(self, name=None):
def create_root_secret(name=None):
    root_secret_b64=''
    config = ConfigObj('/etc/swift/proxy-server.conf')
    try:
#        secret_list = barbican.secrets.list(ROOT_SECRET_NAME)
        if not barbican.secrets.list(name=ROOT_SECRET_NAME) or config['filter:keymaster']['encryption_root_secret_id']=='':
            order = barbican.orders.create_key(name=ROOT_SECRET_NAME,
                                               algorithm=ROOT_SECRET_CIPHER,
                                               bit_length=ROOT_SECRET_LENGTH,
                                               mode=ROOT_SECRET_MODE,
                                               payload_content_type=u'application/octet-stream',
                                               expiration=None)

            order_ref = order.submit()
            retrieved_order = barbican.orders.get(order_ref)
            generated_secret = barbican.secrets.get(retrieved_order.secret_ref)
            config['filter:keymaster']['encryption_root_secret_id']=retrieved_order.secret_ref
            config.write()
            root_secret_b64 = base64.b64encode(generated_secret.payload)
        else:
            #retrieved_secret = secret_list[0]
            retrieved_secret = config['filter:keymaster']['encryption_root_secret_id']
            root_secret_b64 = barbican.secrets.get(retrieved_secret).payload
#        self.check_root_secret(root_secret_b64)
        check_root_secret(root_secret_b64)
        return root_secret_b64
    except NameError as err:
        print 'NameError:', err

print create_root_secret()
#secret = RootSecret(CIPHER, ROOT_SECRET_LENGTH, MODE)
