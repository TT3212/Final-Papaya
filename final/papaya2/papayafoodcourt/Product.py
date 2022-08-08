import random
class Product:


    def __init__(self, name, price, store, image, description):
        self.__food_id = random.randint(1, 9)
        self.__name = name
        self.__price = price
        self.__store = store
        self.__image = image
        self.__description = description

    def get_food_id(self):
        return self.__food_id

    def set_food_id(self):
        number = random.randint(111111, 999999)
        self.__food_id = self.__food_id + number + self.__food_id

    def set_name(self, name):
        self.__name = name

    def get_name(self):
        return self.__name

    def set_price(self, price):
        self.__price = price

    def get_price(self):
        return self.__price

    def set_store(self, store):
        self.__store = store

    def get_store(self):
        return self.__store

    def set_image(self, image):
        self.__image = image

    def get_image(self):
        return self.__image

    def set_description(self, description):
        self.__description = description

    def get_description(self):
        return self.__description

    def set_old_name(self, old_name):
        self.__old_name = old_name

    def get_old_name(self):
        return self.__old_name
