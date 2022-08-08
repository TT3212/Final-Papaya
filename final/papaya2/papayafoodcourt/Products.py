import shelve

class Products:
    def __init__(self, product_id, name, price, description, image):
        self.__product_id = product_id
        self.__product_name = name
        self.__price = price
        self.description = description
        self.__image = image

    def get_product_id(self):
        return self.__product_id

    def get_name(self):
        return self.__product_name

    def get_price(self):
        return self.__price

    def get_description(self):
        return self.description

    def get_image(self):
        return self.__image

    def set_product_id(self, product_id):
        self.__product_id = product_id

    def set_image(self, image):
        self.__image = image

    def set_name(self, name):
        self.__product_name = name

    def set_price(self, price):
        self.__price = price

    def set_description(self, description):
        self.description = description
