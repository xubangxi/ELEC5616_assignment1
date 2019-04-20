import struct

from dh import create_dh_key, calculate_dh_secret
from Crypto.Hash import HMAC
from Crypto.Cipher import AES
from Crypto import Random
import time
import sys

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.mac = None
        self.cache = [int(time.time()),""]
        self.key = None
        self.server = server
        self.verbose = verbose
        self.initiate_session()


    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret
        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the clientasdsad
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash,shared_secret = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(shared_hash.hex()))

        self.mac = HMAC.new(shared_hash[:16])
        # Default XOR algorithm can only take a key of length 32
        iv = Random.new().read(AES.block_size)
        self.key = shared_hash[:16]
        self.cipher =AES.new(shared_hash[:16], AES.MODE_CBC, iv)
        #record msg and recive timestemp to prevent replay attack
        self.cache = [int(time.time()),""]

    def send(self, data):
        if self.cipher:
            iv = Random.new().read(AES.block_size)
            self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
            length = 16 - (len(data) % 16)
            paddata =data+ bytes([length]) * length
            self.mac.update(data)
            hmac = self.mac.digest()
            encrypted_data = iv+self.cipher.encrypt(paddata)+hmac
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data
        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]
        encrypted_data = self.conn.recv(pkt_len)
        if self.cipher:
            iv = encrypted_data[:AES.block_size]
            self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
            data = self.cipher.decrypt(encrypted_data[AES.block_size:-16])
            hmac = encrypted_data[-16:]
            data = data[:-data[-1]]
            self.mac.update(data)
            if hmac != self.mac.digest():
                raise EnvironmentError("message hmac authentication failed")
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("IV:{}".format(iv))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        #if we got the same msg with more than 5 seconds or even earlier than the msg,shut down the link
        if encrypted_data[AES.block_size:-16] == self.cache[1] and int(time.time())-self.cache[0]>5:
            raise EnvironmentError("Replay attack authentication failed")
        if encrypted_data[AES.block_size:-16] == self.cache[1] and int(time.time())-self.cache[0]<0:
            raise EnvironmentError("Replay attack authentication failed")
        else:
            self.cache[0] = int(time.time())
            self.cache[1] = encrypted_data[AES.block_size:-16]
        return data

    def close(self):
        self.conn.close()
