#start
from barbicanclient import orders
from barbicanclient import client
from keystoneclient.auth import identity
from keystoneclient import session
import base64
def get_root_secret():
    auth = identity.v2.Password(auth_url='http://172.16.21.3:5000/v2.0',
                                username='admin',
                                password='password',
                                tenant_name='demo')
    sess = session.Session(auth=auth)
    barbican = client.Client(session=sess, endpoint='http://172.16.21.3:9311')
    root_secret=''
#    if not order.order_ref:
    if root_secret == '':
        order = barbican.orders.create_key(name=u'Swift root secret',
                                           algorithm=u'AES',
                                           bit_length=256,
                                           mode=u'CBC',
                                           payload_content_type=u'application/octet-stream',
                                           expiration=None)
        order_ref = order.submit()
        retrieved_order = barbican.orders.get(order_ref)
        generated_secret = barbican.secrets.get(retrieved_order.secret_ref)
        root_secret = base64.b64encode(generated_secret.payload)
    else:
        retrieved_secret = barbican.secrets.list(name='Swift root secret')[0]
        root_secret = base64.b64encode(generated_secret.payload)
    return root_secret
print get_root_secret()
#end
