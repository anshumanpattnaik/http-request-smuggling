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
import argparse
import json
import queue
import time
import sys
import threading
from termcolor import cprint, colored
from pyfiglet import figlet_format
from lib.Utils import Utils
from lib.Constants import Constants
from lib.SocketConnection import SocketConnection
import colorama
colorama.init()

utils = Utils()
constants = Constants()

# Argument parser
parser = argparse.ArgumentParser(description='HTTP Request Smuggling vulnerability detection tool')
parser.add_argument("-u","--url",help="set the target url")
parser.add_argument("-t","--timeout",help="set socket timeout, default - 10")
parser.add_argument("-m","--method",help="set HTTP Methods, i.e (GET or POST), default - POST")
parser.add_argument("-r","--retry",help="set the retry count to re-execute the payload, default - 2")
args = parser.parse_args()

def hrs_detection(host, port, path, method, permute_type, content_length_key, te_key, te_value, smuggle_type, content_length, payload, timeout, results_queue):
    headers = ''
    headers += '{} {} HTTP/1.1{}'.format(method,path,constants.crlf)
    headers += 'Host: {}{}'.format(host, constants.crlf)
    headers += '{} {}{}'.format(content_length_key, content_length, constants.crlf)
    headers += '{}{}{}'.format(te_key, te_value, constants.crlf)
    smuggle_body = headers + payload

    permute_type = "["+permute_type+"]"
    elapsed_time = "-"
    
    # Print Styling 
    _style_space_config = "{:<30}{:<25}{:<25}{:<25}{:<25}"
    _style_permute_type = colored(permute_type, constants.cyan, attrs=['bold'])
    _style_smuggle_type = colored(smuggle_type, constants.magenta, attrs=['bold'])
    _style_status_code = colored("-", constants.blue, attrs=['bold'])
    _style_elapsed_time = "{}".format(colored(elapsed_time, constants.yellow, attrs=['bold']))
    _style_status = colored(constants.detecting, constants.green, attrs=['bold'])
    
    print(_style_space_config.format(_style_permute_type, _style_smuggle_type, _style_status_code, _style_elapsed_time, _style_status), end="\r", flush=True)

    try:
        connection = SocketConnection()
        connection.connect(host, port, timeout)
        connection.send_payload(smuggle_body)
        
        start_time = time.time()
        response = connection.receive_data().decode("utf-8")
        end_time = time.time()

        if len(response.split()) > 0:
            status_code = response.split()[1]
        else:
            status_code = 'NO RESPONSE'
        _style_status_code = colored(status_code, constants.blue, attrs=['bold'])

        connection.closeConnection()

        elapsed_time = str(round((end_time - start_time) % 60, 2))+"s"
        _style_elapsed_time = "{}".format(colored(elapsed_time, constants.yellow, attrs=['bold']))

        is_hrs_found = connection.detect_hrs_vulnerability(start_time, timeout)
        if is_hrs_found:
            _style_status = colored(constants.delayed_response_msg, constants.red, attrs=['bold'])
            reports = constants.reports+'/{}/{}-{}{}'.format(host,permute_type,smuggle_type,constants.extenstion)
            Utils().writePayload(reports, smuggle_body)
        else:
            _style_status = colored(constants.ok, constants.green, attrs=['bold'])
    except Exception as _:
        elapsed_time = time.time()+"s"
        _style_elapsed_time = "{}".format(colored(elapsed_time, constants.yellow, attrs=['bold']))
        _style_status = colored(constants.dis_connected, constants.red, attrs=['bold'])

    print(_style_space_config.format(_style_permute_type, _style_smuggle_type, _style_status_code, _style_elapsed_time, _style_status))
    time.sleep(1)

if __name__ == "__main__":
    utils.print_header()

    url = args.url
    if url:
        result = utils.url_parser(url)
        try:
            json_res = json.loads(result)
            host = json_res['host']
            port = json_res['port']
            path = json_res['path']
        
            timeout = args.timeout if args.timeout else 10
            method = args.method if args.method else "POST"
            retry = int(args.retry) if args.retry else 2

            payloads = open('payloads.json')
            data = json.load(payloads)

            total_hrs_request = len(data[constants.permute]) * len(data[constants.detection]) * retry

            results_queue = queue.Queue()
            payload_list = list()

            for permute in data[constants.permute]:
                for d in data[constants.detection]:
                    for _ in range(retry):
                        transfer_encoding_obj = permute[constants.transfer_encoding]
                        hrs_detection(host,
                                      port,
                                      path,
                                      method,
                                      permute[constants.type],
                                      permute[constants.content_length_key],
                                      transfer_encoding_obj[constants.te_key],
                                      transfer_encoding_obj[constants.te_value],
                                      d[constants.type],
                                      d[constants.content_length],
                                      d[constants.payload],
                                      timeout,
                                      results_queue)
        except ValueError as _:
            print(result)
    else:
        print('Set the target url by following (-u) argument')