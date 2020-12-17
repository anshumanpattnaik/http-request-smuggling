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
class Constants():
    def __init__(self):
        self.get = 'GET'
        self.post = 'POST'
        self.host = 'host'
        self.port = 'port'
        self.url = 'url'
        self.transfer_encoding = 'transfer_encoding'
        self.te_key = 'te_key'
        self.te_value = 'te_value'
        self.modified_chunked = 'modified_chunked'
        self.default_chunked = 'chunked'
        self.default_type = '(CL.TE/TE.CL)'
        self.clte = 'CL.TE'
        self.tecl = 'TE.CL'
        self.permute = 'permute'
        self.type = 'type'
        self.payload = 'payload'
        self.statuscode = 'statuscode'
        self.content_length_key = 'content_length_key'
        self.content_length = 'content_length'
        self.header_type = 'header_type'
        self.chunked_type = 'chunked_type'
        self.payload_chunk = 'payload_chunk'
        self.detection = 'detection'
        self.crlf = '\r\n'
        self.delayed_response_msg = '[Delayed Response] → Possible HTTP Request Smuggling'
        self.detecting = 'detecting...'
        self.ok = 'OK'
        self.magenta = 'magenta'
        self.yellow = 'yellow'
        self.white = 'white'
        self.red = 'red'
        self.cyan = 'cyan'
        self.blue = 'blue'
        self.green = 'green'
        self.reports = 'reports'
        self.output = '$Output'
        self.extenstion = '.txt'
        self.invalid_method_type = 'Invalid method type, please enter correct http method (eg GET or POST)'
        self.target_website_unrechable = 'Target website unreachable : 504 Gateway Timeout Error'
        self.keyboard_interrupt = 'KeyboardInterrupt'
        self.done = 'DONE'
        self.dis_connected = 'DISCONNECTED'