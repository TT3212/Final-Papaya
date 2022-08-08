class reviewUser:
    countReviewId = 0

    def __init__(self, customer_name, review_store, review_type, star_review, remarks):
        reviewUser.countReviewId += 1
        self.__review_id = reviewUser.countReviewId
        self.__customer_name = customer_name
        self.__review_store = review_store
        self.__review_type = review_type
        self.__star_review = star_review
        self.__remarks = remarks

    def get_review_id(self):
        return self.__review_id

    def get_customer_name(self):
        return self.__customer_name

    def get_review_store(self):
        return self.__review_store

    def get_review_type(self):
        return self.__review_type

    def get_star_review(self):
        return self.__star_review

    def get_remarks(self):
        return self.__remarks

    def set_review_id(self, review_id):
        self.__review_id = review_id

    def set_customer_name(self, customer_name):
        self.__customer_name = customer_name

    def set_review_store(self, review_store):
        self.__review_store = review_store

    def set_review_type(self, review_type):
        self.__review_type = review_type

    def set_star_review(self, star_review):
        self.__star_review = star_review

    def set_remarks(self, remarks):
        self.__remarks = remarks
