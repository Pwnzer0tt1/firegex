from multiprocessing import Process
import socket

class TcpServer:
    def __init__(self,port,ipv6,proxy_port=None):
        def _startServer(port):
            sock = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('::1' if ipv6 else '127.0.0.1', port))
            sock.listen(8)
            while True:  
                connection,address = sock.accept()  
                buf = connection.recv(4096)  
                connection.send(buf)    		
                connection.close()
        self.proxy_port = proxy_port
        self.ipv6 = ipv6
        self.port = port
        self.server = Process(target=_startServer,args=[port])

    def start(self):
        self.server.start()
    
    def stop(self):
        self.server.terminate()

    def sendCheckData(self,data):
        s = socket.socket(socket.AF_INET6 if self.ipv6 else socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('::1' if self.ipv6 else '127.0.0.1', self.proxy_port if self.proxy_port else self.port))
        s.sendall(data)
        received_data = s.recv(4096)
        s.close()
        return received_data == data