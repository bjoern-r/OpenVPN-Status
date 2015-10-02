import socket
import telnetlib
import re

class connexion:
    """class connexion that create a socket, and connects to management openvpn server"""
    def __init__(self, hostname, port, password, request, version):
        self.hostname=hostname
        self.port=port
        self.password=password
        self.request=request
        self.version=version
        self.timeout = 2

    def interact(self):
        """function that interacte with the server and try to get out some data (using telnetlib)"""
        data = None
        try:
            tn = telnetlib.Telnet(self.hostname,self.port)
            line = tn.read_until("PASSWORD:", self.timeout)
            if line != []:
                tn.write(self.password + "\n")
                line = tn.read_until("correct\r\n",self.timeout)
                if line != []:
                    tn.read_very_eager()
                    tn.write(self.request + "\n")
                    tn.write("exit\n")
                    data = tn.read_all()
                tn.close()
                return data
        except Exception, e:
            raise(e)

    def interact2(self):
        """function that interacte with the server and try to get out some data"""
        try:
            if self.version==6:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            elif self.version==4: 
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.connect((self.hostname,self.port))

            data = sock.recv(1024)
            sock.send(self.password)
            sock.send('\r\n')
            data = sock.recv(4096)
            line=re.findall('SUCCESS:',data)
            if line != []:
                sock.send(self.request)
                sock.send('\r\n')
                data = sock.recv(40960)
                sock.send('exit')
                sock.send('\r\n')
                sock.close()
                return data
            else:
            print "cant read success"
                pass

        except Exception, e:
            raise(e)
