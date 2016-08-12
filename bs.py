from barbicanclient import orders
from barbicanclient import client
from keystoneclient.auth import identity
from keystoneclient import session
import base64

class RootSecret(object):
    cipher = u'AES'
    root_secret_length=256
    mode = u'CBC'

    auth = identity.v2.Password(auth_url='http://172.16.21.3:5000/v2.0',
                                username='admin',
                                password='password',
                                tenant_name='demo')
    sess = session.Session(auth=auth)
    barbican = client.Client(session=sess, endpoint='http://172.16.21.3:9311')

    def __init__(self, algorithm, bit_length, mode):
        self.name = u'Swift root secret'
        self.algorithm = algorithm
        self.bit_length = bit_length
        self.mode = mode

    def create_root_secret(self, cipher, root_secret_length, mode):
        """
        Creates a root secret with barbican client
        :param cipher: symmetric-key algorithm
        :param root_secret_length: secret length in bits
        :param mode: cipher mode of operation
        :returns: a base64 encoded key
        """
        root_secret = RootSecret(cipher, root_secret_length, mode)
        order = barbican.orders.create_key(name=root_secret.name,
                                           algorithm=root_secret.algorithm,
                                           bit_length=root_secret.bit_length,
                                           mode=root_secret.mode,
                                           payload_content_type=u'application/octet-stream',
                                           expiration=None)

        order_ref = order.submit()
        retrieved_order = barbican.orders.get(order_ref)
        generated_secret = barbican.secrets.get(retrieved_order.secret_ref)
        root_secret_b64 = base64.b64encode(generated_secret.payload)
        try:
            if check_secret_length(root_secret_b64):
                return root_secret_b64
        except ValueError:
            check_root_secret(cipher, root_secret_length, mode)

    def check_root_secret(cipher, root_secret_length, mode):
        """
        Checks if a root secret already exists
        :param cipher: symmetric-key algorithm
        :param root_secret_length: secret length in bits
        :param mode: cipher mode of operation
        :returns: a base64 encoded key
        """
        try:
            root_secret
        except NameError:
            secret_list = barbican.secrets.list(name=root_secret.name)
            if secret_list:
                retrieved_secret = secret_list[0]
                root_secret_b64 = base64.b64encode(retrieved_secret.payload)
                return  root_secret_b64
            else:
                create_root_secret(cipher, root_secret_length, mode)

    def check_secret_length(self, root_secret):
        """
        Checks secret length matches recommended value
        :param root_secret: the secret to check
        """
        if len(root_secret) != self.root_secret_length:
            raise ValueError("Root secret must be length %s bytes" % self.root_secret_length)

    def main():
        print create_root_secret(cipher, root_secret_length, mode)
