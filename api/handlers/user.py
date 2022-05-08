from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from tornado.web import authenticated

from .auth import AuthHandler

from ..utils.myCrypt import aesInstance, decrypt

class UserHandler(AuthHandler):

    @authenticated
    def get(self):
        self.set_status(200)
        self.response['email'] = self.current_user['email']
        encrypted_display_name = self.current_user['encrypted_display_name']
        encrypted_address = self.current_user['encrypted_address']
        encrypted_date_of_birth = self.current_user['encrypted_date_of_birth']
        encrypted_phone_number = self.current_user['encrypted_phone_number']
        encrypted_disabilities = self.current_user['encrypted_disabilities']
        salt = self.current_user['salt']
        aesinstance = aesInstance(salt)
        decryptor = aesinstance.decryptor()
        self.response['displayName'] = decrypt(decryptor, encrypted_display_name)
        self.response['address'] = decrypt(decryptor, encrypted_address)
        self.response['date_of_birth'] = decrypt(decryptor, encrypted_date_of_birth)
        self.response['phone_number'] = decrypt(decryptor, encrypted_phone_number)
        self.response['disabilities'] = decrypt(decryptor, encrypted_disabilities)
        self.write_json()

    @coroutine
    @authenticated
    def put(self):
        try:
            body = json_decode(self.request.body)
            display_name = body['displayName']
            if not isinstance(display_name, str):
                raise Exception()
        except:
            self.send_error(400, message='You must provide a display name!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return



        yield self.db.users.update_one({
            'email': self.current_user['email'],
        }, {
            '$set': {
                'displayName': display_name
            }
        })

        self.current_user['display_name'] = display_name

        self.set_status(200)
        self.response['email'] = self.current_user['email']
        self.response['displayName'] = self.current_user['display_name']
        self.write_json()
