import M2Crypto as m2crypto
import os
import tempfile

KEY_LENGTH = 4096
EXPONENT = 65537

def reseed():
    m2crypto.Rand.rand_seed(os.urandom(1024))

class Agent(object):
    def __init__(self):
        self.key = m2crypto.RSA.gen_key(KEY_LENGTH, EXPONENT)

        tmp = tempfile.NamedTemporaryFile(mode='w+t', delete=True)
        try:
            self.key.save_pub_key(tmp.name)
            tmp.seek(0)
            self.pub_key = m2crypto.RSA.load_pub_key(tmp.name)
        finally:
            tmp.close()

    def export_public_key(self, filename):
        self.key.save_pub_key(filename)

    def export_private_key(self, filename, use_passphrase=False):
        if not use_passphrase:
            self.key.save_key(filename, None)
        else:
            self.key.save_key(filename)

    def encrypt_message(self, message, key):
        cipher_text = key.public_encrypt(message, m2crypto.RSA.pkcs1_oaep_padding)
        digest = m2crypto.EVP.MessageDigest('sha512')
        digest.update(cipher_text)
        sig = self.key.sign_rsassa_pss(digest.digest())
        return cipher_text, sig

    def decrypt_message(self, message, signer_public_key=None, sig=None):
        digest = m2crypto.EVP.MessageDigest('sha512')
        digest.update(message)
        if sig and signer_public_key:
            if signer_public_key.verify_rsassa_pss(digest.digest(), sig) != 1:
                print('Signature is invalid!')
                return
        elif sig or signer_public_key:
            print('Both sig and public_key are required to verify signature')
            return

        plain_text = self.key.private_decrypt(message, m2crypto.RSA.pkcs1_oaep_padding)
        return plain_text

def main():
    reseed()
    alice = Agent()
    bob = Agent()

    message, sig = alice.encrypt_message('This is a secret', bob.pub_key)
    print message.encode('base64')

    plain_text = bob.decrypt_message(message,
                                     signer_public_key=alice.pub_key,
                                     sig=sig)
    print plain_text

if __name__ == '__main__':
    main()
