from flask_login import UserMixin
from uuid import uuid4
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import shelve
from flask import current_app as app

class User(UserMixin):

    def __init__(self, email_address, username, password):
        self.__id = str(uuid4())  # uuid is used to generate random user ids
        self.__email_address = email_address
        self.__username = username
        self.__password = password
        self.__first_name = None
        self.__last_name = None
        self.__description = ""
        self.__profile_picture = None
        self.__failed_attempt = 0
        self.__payment_info = []

    def set_payment_info(self,payment_info):
        self.__payment_info.append(payment_info)

    def get_payment_info(self):
        return self.__payment_info

    def set_id(self, id):
        self.__id = id

    def get_id(self):
        return self.__id

    def set_email_address(self, email_address):
        self.__email_address = email_address

    def get_email_address(self):
        return self.__email_address

    def set_password(self, password):
        self.__password = password

    def get_password(self):
        return self.__password

    def set_username(self, username):
        self.__username = username

    def get_username(self):
        return self.__username

    def set_first_name(self, first_name):
        self.__first_name = first_name

    def get_first_name(self):
        return self.__first_name

    def set_last_name(self, last_name):
        self.__last_name = last_name

    def get_last_name(self):
        return self.__last_name

    def set_description(self, description):
        self.__description = description

    def get_description(self):
        return self.__description

    def set_profile_picture(self, profile_picture):
        self.__profile_picture = profile_picture

    def get_profile_picture(self):
        return self.__profile_picture

    def set_failed_attempt(self, failed_attempt):
        self.__failed_attempt = failed_attempt

    def get_failed_attempt(self):
        return self.__failed_attempt

    def get_reset_token(self, expires_sec=3600):
        serial = Serializer(app.config['SECRET_KEY'], expires_sec)
        return serial.dumps({'user_id': self.get_id()}).decode('utf-8')
    
    @staticmethod
    def verify_reset_token(token):
        db = shelve.open('users.db', 'r')
        users_dict = db['Users']
        serial = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = serial.loads(token)['user_id']
        except:
            return None
        return users_dict.get(user_id)
