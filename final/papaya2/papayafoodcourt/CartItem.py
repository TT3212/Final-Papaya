from Products import Products


class CartItem(Products):
    def __init__(self, product_id, name, price, description, image, quantity, additional_request):
        super().__init__(product_id, name, price, description, image)
        self.__quantity = quantity
        self.__total_price = 0
        self.__current_url = ""
        self.__additional_request = additional_request

    def get_url(self):
        return self.__current_url

    def set_url(self, url):
        self.__current_url = url

    def get_quantity(self):
        return self.__quantity

    def set_quantity(self, quantity):
        self.__quantity = quantity

    def get_total_price(self):
        return "{:.2f}".format(float(self.__total_price))

    def set_total_price(self, total_price):
        self.__total_price =  "{:.2f}".format(float(total_price))
        
    def get_additional_request(self):
        return self.__additional_request

    def set_additional_request(self, additional_request):
        self.__additional_request = additional_request


