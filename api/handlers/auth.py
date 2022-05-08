from datetime import datetime
from time import mktime
from tornado.gen import coroutine

from .base import BaseHandler

class AuthHandler(BaseHandler):

    @coroutine
    def prepare(self):
        super(AuthHandler, self).prepare()

        if self.request.method == 'OPTIONS':
            return

        try:
            token = self.request.headers.get('X-Token')
            if not token:
              raise Exception()
        except:
            self.current_user = None
            self.send_error(400, message='You must provide a token!')
            return
        # verify the token and find the user
        user = yield self.db.users.find_one({
            'token': token
        }, {
            'email': 1,
            'displayName': 1,
            'expiresIn': 1,
            'salt': 1,
            'address': 1,
            'date_of_birth': 1,
            'phone_number': 1,
            'disabilities': 1
        })

        if user is None:
            self.current_user = None
            self.send_error(403, message='Your token is invalid!')
            return

        current_time = mktime(datetime.now().utctimetuple())
        if current_time > user['expiresIn']:
            self.current_user = None
            self.send_error(403, message='Your token has expired!')
            return
        # decode the data
        self.current_user = {
            'email': user['email'],
            'encrypted_display_name': bytes.fromhex(user['displayName']),
            'salt': bytes.fromhex(user['salt']),
            'encrypted_address': bytes.fromhex(user['address']),
            'encrypted_date_of_birth': bytes.fromhex(user['date_of_birth']),
            'encrypted_phone_number': bytes.fromhex(user['phone_number']),
            'encrypted_disabilities': bytes.fromhex(user['disabilities'])
        }
