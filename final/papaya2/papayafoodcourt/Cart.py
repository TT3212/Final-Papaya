from datetime import datetime

class Cart():
    def __init__(self):
        self.Cart = []
        self.__total_price = 0
        self.payment_info = []
        self.__subtotal_purchase = 0
        self.__gst = 0
        self.__final_total = 0
        self.__date = None

    def get_dateTime(self):
        return self.__date

    def set_dateTime(self):
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
        self.__date = dt_string

    def get_final_total(self):
        return self.__final_total

    def set_final_total(self, gst, subtotal, delivery_fee):
        final_total_amount = float(gst) + float(subtotal) + float(delivery_fee)
        self.__final_total = "{:.2f}".format(final_total_amount)


    def get_gst(self):
        return self.__gst

    def set_gst(self, gst):
        self.__gst = gst
        self.__gst  = float(self.__gst) * 0.07

    def get_subtotal_purchase(self):
        return self.__subtotal_purchase

    def reset_subtotal_purchase(self):
        self.__subtotal_purchase = 0

    def set_subtotal_purchase(self, total):
        cal_subtotal =  float(self.__subtotal_purchase) + float(total)
        self.__subtotal_purchase = cal_subtotal

    def get_payment_info(self):
        return self.__payment_info

    def set_payment_info(self, payment_info):
        self.__payment_info.append(payment_info)

    def get_total_price(self):
        return self.__total_price

    def set_total_price(self, item_quantity, item_price):
        self.__total_price =  float(item_quantity) * float(item_price)
