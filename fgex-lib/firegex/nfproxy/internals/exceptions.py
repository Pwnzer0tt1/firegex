
class NotReadyToRun(Exception):
    "raise this exception if the stream state is not ready to parse this object, the call will be skipped"
