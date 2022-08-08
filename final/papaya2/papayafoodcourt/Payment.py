class Payment:
    def __init__(self):
        self.__delivery_mode = ""
        self.__delivery_fee = 0
        self.__payment_firstname = ""
        self.__payment_lastname = ""
        self.__payment_streetaddress = ""
        self.__payment_buildingblock = ""
        self.__payment_city = ""
        self.__payment_postalcode = ""
        self.__payment_phone_number = ""
        self.__payment_bill_info = ""
        self.__gst = 0
        self.__card_number = ""
        self.__card_name = ""
        self.__card_expiry_date = " "
        self.__card_CVV = ""

    def get_card_number(self):
        return self.__card_number

    def get_card_name(self):
        return self.__card_name

    def get_card_expiry_date(self):
        return self.__card_expiry_date

    def get_card_CVV(self):
        return self.__card_CVV

    def set_card_number(self, card_number):
        self.__card_number = card_number

    def set_card_name(self, card_name):
        self.__card_name = card_name

    def set_card_expiry_date(self, card_expiry_date):
        self.__card_expiry_date = card_expiry_date

    def set_card_CVV(self, CVV):
        self.__card_CVV = CVV

    def get_gst(self):
        return self.__gst

    def set_gst(self, subtotal):
        self.__gst = "{:.2f}".format(float(subtotal) * 0.07)

    def get_first_name(self):
        return self.__payment_firstname

    def set_first_name(self, first_name):
        self.__payment_firstname = first_name

    def get_last_name(self):
        return self.__payment_lastname

    def set_last_name(self, last_name):
        self.__payment_lastname = last_name

    def get_street_address(self):
        return self.__payment_streetaddress

    def set_street_address(self, street_address):
        self.__payment_streetaddress = street_address

    def get_building_block(self):
        return self.__payment_buildingblock

    def set_building_block(self, buidling_block):
        self.__payment_buildingblock = buidling_block

    def get_city(self):
        return self.__payment_city

    def set_city(self, city):
        self.__payment_city = city

    def get_postal_code(self):
        return self.__payment_postalcode

    def set_postal_code(self, postal_code):
        self.__payment_postalcode = postal_code

    def get_phone_number(self):
        return self.__payment_phone_number

    def set_phone_number(self, phone_number):
        self.__payment_phone_number = phone_number

    def get_bill_info(self):
        return self.__payment_bill

    def set_bill_info(self, bill_info):
        self.__payment_bill_info = bill_info

    def get_delivery_fee(self):
        return self.__delivery_fee

    def set_delivery_fee(self, delivery_fee):
        self.__delivery_fee = delivery_fee

    def get_delivery_mode(self):
        return self.__delivery_mode

    def set_delivery_mode(self, delivery_mode):
        self.__delivery_mode = delivery_mode
