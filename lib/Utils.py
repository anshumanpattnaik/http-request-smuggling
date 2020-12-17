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
import time
import json
import os
from termcolor import cprint, colored
from pyfiglet import figlet_format
from urllib.parse import urlparse
import colorama
colorama.init()

class Utils():
    def __init__(self):
        self.title = "Smuggling"
        self.author = "Anshuman Pattnaik / @anspattnaik"
        self.github = "https://github.com/anshumanpattnaik/http-rquest-smuggling"
        self.blog = "https://hackbotone.com/blog/http-request-smuggling"
        self.version = "0.1"

    def getStartTime(self):
        return time.time()

    def print_header(self):
        cprint(figlet_format(self.title, font='ogre'), 'green', attrs=['bold'])
        
        header_key_color = 'yellow'
        header_value_color = 'red'

        print("{:<1}{:<23}{:<17}{}".format('', colored('Author', header_key_color, attrs=['bold']), colored(':', header_key_color, attrs=['bold']), colored(self.author, header_value_color, attrs=['bold'])))
        print("{:<1}{:<23}{:<17}{}".format('', colored('Github', header_key_color, attrs=['bold']) , colored(':', header_key_color, attrs=['bold']), colored(self.github, header_value_color, attrs=['bold'])))
        print("{:<1}{:<23}{:<17}{}".format('', colored('Blog', header_key_color, attrs=['bold']), colored(':', header_key_color, attrs=['bold']), colored(self.blog, header_value_color, attrs=['bold'])))
        print("{:<1}{:<23}{:<17}{}".format('', colored('Version', header_key_color, attrs=['bold']), colored(':', header_key_color, attrs=['bold']), colored(self.version, header_value_color, attrs=['bold'])))
        print("\n")

    def writePayload(self, fileName, payload):
        if not os.path.exists(os.path.dirname(fileName)):
            try:
                os.makedirs(os.path.dirname(fileName))
            except OSError as e:
                print(e)

        with open(fileName, "w") as f:
            f.write(payload)

    def url_parser(self, url):
        parser = {}
        try:
            u_parser = urlparse(url)

            host = u_parser.hostname
            
            if u_parser.scheme == 'https':
                port = 443
            if u_parser.scheme == 'http':
                port = 80

            parser["host"] = host
            parser["port"] = port
            
            path = u_parser.path
            if len(path) > 0:
                parser["path"] = path
            else:
                parser["path"] = '/'

            return json.dumps(parser)
        except:
            return "Invalid target url, please specify the valid url by following this example - http[s]://example.com"

    def read_target_list(self, file_name):
        with open(file_name) as urls_list:
            return [u.rstrip('\n') for u in urls_list]