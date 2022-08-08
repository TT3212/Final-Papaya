from uuid import uuid4


class Store:
    def __init__(self, name, image, description):
        self.__id = str(uuid4())
        self.__name = name
        self.__image = image
        self.__description = description

    def set_id(self, id):
        self.__id = id

    def get_id(self):
        return self.__id

    def set_name(self, name):
        self.__name = name

    def get_name(self):
        return self.__name

    def set_image(self, image):
        self.__image = image

    def get_image(self):
        return self.__image

    def set_description(self, description):
        self.__description = description

    def get_description(self):
        return self.__description
