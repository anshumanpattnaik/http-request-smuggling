# MIT License

# Copyright (c) 2020 Anshuman Pattnaik

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import socket, ssl
import time

class SocketConnection():
    def connect(self, host, port, timeout):
        try:
            if port == 443:
                self.ssl_enable = True
                self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                self.s = socket.create_connection((host, port))
                self.ssl = self.context.wrap_socket(self.s, server_hostname=host)
                self.ssl.settimeout(timeout)
                self.is_connected = True
            else:
                self.ssl_enable = False
                self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.s.settimeout(timeout)
                self.s.connect((host, port))
                self.is_connected = True
            return self.s
        except:
            return None

    def send_payload(self, payload):
        if(self.ssl_enable):
            self.ssl.send(str(payload).encode())
        else:
            self.s.send(str(payload).encode())
        
    def receive_data(self, bufferSize=1024):
        try:
            if(self.ssl_enable):
                self.ssl.settimeout(None)
                self.data = self.ssl.recv(bufferSize)
            else:
                self.s.settimeout(None)
                self.data = self.s.recv(bufferSize)
        except Exception:
            self.data = None
        return self.data

    def detect_hrs_vulnerability(self,startTime,timeout):
        if time.time() - startTime >= timeout:
            return True
        return False
    
    def close_connection(self):
        if(self.ssl_enable):
            self.ssl.close()
            del self.ssl
        self.s.close()
        del self.s