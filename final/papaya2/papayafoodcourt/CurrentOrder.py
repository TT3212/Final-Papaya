from shortuuid import ShortUUID
from datetime import datetime

class CurrentOrder():
    def __init__(self, cart_items, customer_name):
        self.__order_id = ShortUUID().random(length=6)
        self.__order_date_time = datetime.now()
        self.__cart_items = cart_items
        self.__customer_name = customer_name
        self.__delivery_stage = "Cooking"
        self.__delivery_time = 45
    
    def get_order_id(self):
        return self.__order_id
    
    def get_order_date_time(self):
        return self.__order_date_time
    
    def set_customer_name(self, name):
        self.__customer_name = name

    def get_customer_name(self):
        return self.__customer_name
        
    def set_cart_items(self, items):
        self.__cart_items = items
    
    def get_cart_items(self):
        return self.__cart_items

    def set_delivery_stage(self, stage):
        self.__delivery_stage = stage

    def get_delivery_stage(self):
        return self.__delivery_stage
    
    def add_delivery_time(self, minutes):
        self.__delivery_time += minutes

    def get_delivery_time(self):
        return self.__delivery_time