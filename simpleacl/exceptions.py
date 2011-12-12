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

class MissingPrivilege(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)
