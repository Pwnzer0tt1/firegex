
class NotReadyToRun(Exception):
    "raise this exception if the stream state is not ready to parse this object, the call will be skipped"

class DropPacket(Exception):
    "raise this exception if you want to drop the packet"

class StreamFullDrop(Exception):
    "raise this exception if you want to drop the packet due to full stream"

class RejectConnection(Exception):
    "raise this exception if you want to reject the connection"

class StreamFullReject(Exception):
    "raise this exception if you want to reject the connection due to full stream"

