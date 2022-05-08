from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine

from .base import BaseHandler
import os
from ..utils.myCrypt import myCrypt, aesInstance, encrypt, decrypt

class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
            address = body['address'].lower()
            date_of_birth = body['date_of_birth']
            phone_number = body['phone_number']
            disabilities = body['disabilities']
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

        salt = os.urandom(16)
        hashed_password = myCrypt(password, salt)

        aesinstance = aesInstance(salt)
        encryptor = aesinstance.encryptor()

        yield self.db.users.insert_one({
            'email': email,
            'password': hashed_password,
            'displayName': encrypt(encryptor, bytes(display_name,"utf-8")),
            'salt': salt.hex(),
            'address': encrypt(encryptor, bytes(address, "utf-8")),
            'date_of_birth': encrypt(encryptor, bytes(date_of_birth, "utf-8")),
            'phone_number': encrypt(encryptor, bytes(phone_number, "utf-8")),
            'disabilities': encrypt(encryptor, bytes(disabilities, "utf-8"))
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name

        self.write_json()

