class MissingRole(Exception):

    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class MissingActiveRole(Exception):

    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class MissingResource(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)
