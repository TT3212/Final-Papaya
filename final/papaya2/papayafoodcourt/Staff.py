from User import User

class Staff(User):
    def __init__(self, email_address, username, password):
        super().__init__(email_address, username, password)
        self.__account_type = "Staff"
    
    def get_account_type(self):
        return self.__account_type

    def set_account_type(self, account_type):
        self.__account_type = account_type
