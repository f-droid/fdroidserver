class FDroidException(Exception):
    def __init__(self, value=None, detail=None):
        self.value = value
        self.detail = detail

    def shortened_detail(self):
        if len(self.detail) < 16000:
            return self.detail
        return '[...]\n' + self.detail[-16000:]

    def __str__(self):
        if self.value is None:
            ret = __name__
        else:
            ret = str(self.value)
        if self.detail:
            ret += (
                "\n==== detail begin ====\n%s\n==== detail end ===="
                % ''.join(self.detail).strip()
            )
        return ret


class MetaDataException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


class VCSException(FDroidException):
    pass


class NoSubmodulesException(VCSException):
    pass


class BuildException(FDroidException):
    pass


class VerificationException(FDroidException):
    pass
