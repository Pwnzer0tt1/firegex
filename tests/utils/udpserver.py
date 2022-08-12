from multiprocessing import Process
import socket

class UdpServer:
    def __init__(self,port,ipv6, proxy_port = None):
        def _startServer(port):
            sock = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('::1' if ipv6 else '127.0.0.1', port))
            while True:
                bytesAddressPair = sock.recvfrom(432)
                message = bytesAddressPair[0]
                address = bytesAddressPair[1]
                sock.sendto(message, address)
                
        self.ipv6 = ipv6
        self.port = port
        self.proxy_port = proxy_port
        self.server = Process(target=_startServer,args=[port])

    def start(self):
        self.server.start()
    
    def stop(self):
        self.server.terminate()

    def sendCheckData(self,data):
        s = socket.socket(socket.AF_INET6 if self.ipv6 else socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(data, ('::1' if self.ipv6 else '127.0.0.1', self.proxy_port if self.proxy_port else self.port))
        try:
            received_data = s.recvfrom(432)
        except Exception:
            return False
        return received_data[0] == data