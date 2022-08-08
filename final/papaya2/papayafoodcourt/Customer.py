from User import User

class Customer(User):
    def __init__(self, email_address, username, password):
        super().__init__(email_address, username, password)
        self.__account_type = "Customer"
        self.__membership = None
        
    def set_membership(self, membership):
        self.__membership = membership
    
    def get_membership(self):
        return self.__membership
    
    def set_account_type(self, account_type):
        self.__account_type = account_type

    def get_account_type(self):
        return self.__account_type
    
