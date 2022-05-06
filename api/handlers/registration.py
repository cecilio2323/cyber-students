import os
from des import DesKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine

from .base import BaseHandler

class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            salt = os.urandom(16)
            kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
            password = body['password']
            password_bytes = bytes(password, "utf-8")
            hashed_password = kdf.derive(password_bytes)

            if not isinstance(password, str):
                raise Exception()

            #TODO: Add adress, FULL NAME, DOB, Phone Number, Disabilities
            phone_number = body.get('phoneNumber')
            phone_number_bytes=bytes(phone_number, "utf-8")
            phone_number_cipher_bytes = self.key.encrypt(phone_number_bytes)
            phone_number_ciphertext = phone_number_cipher_bytes.hex()

            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
        except Exception as e:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        yield self.db.users.insert_one({
            'email': email,
            'password': hashed_password.hex(),
            'displayName': display_name,
            'phoneNumber': phone_number_ciphertext
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name

        self.write_json()
