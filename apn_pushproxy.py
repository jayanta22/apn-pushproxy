#!/usr/bin/env python2.7
import os
import logging
import sys
import errno
import socket
import random
import time
import ssl
import struct
import simplejson as json
from flask import Flask, request


LOG_FILE = os.path.expanduser("~/pushproxy.log")

# Host name and certificate for the production APN servers
APN_PRODUCTION_HOST = ('gateway.push.apple.com', 2195)
APN_PRODUCTION_CERT = 'prod_certificate.pem'
 
# Host name and certificate for sandboxed APN servers
APN_SANDBOX_HOST = ('gateway.sandbox.push.apple.com', 2195)
APN_SANDBOX_CERT = 'dev_certificate.pem'


APN_ERRORS = {
    1: "Processing error",
    2: "Missing device token",
    3: "Missing topic",
    4: "Missing payload",
    5: "Invalid token size",
    6: "Invalid topic size",
    7: "Invalid payload size",
    8: "Invalid token",
    255: "Unknown error",
}


def open_ssl_socket(host, cert):
    '''  
    Create open and return a SSL socket, connected with the
    given host and signed with the given SSL certificate. 
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_s = ssl.wrap_socket(s, certfile = cert)
    ssl_s.connect(host)
    return ssl_s


def send_apn(data_socket, notification):
    # Be sure to send the full notification content.
    # Due to GIL no synchronization is needed.
    while notification:
        num_bytes = data_socket.write(notification)
        notification = notification[num_bytes:]

def safe_send_apn(notification, use_sandbox=False, retries=3):
    
    while retries:
        # Pick the socket to send data to
        data_socket = sandbox_socket if use_sandbox else production_socket

        try:        
            send_apn(data_socket, notification)
            bin_response = data_socket.read()
            logging.info("APN response: %r", bin_response)

            if len(bin_response) == 0:
                break

            response = struct.unpack("!BBL", bin_response)
            command, status, _ = response
            if status == 0: break
            
            if status in APN_ERRORS:
                return APN_ERRORS[status]
            else:
                return "Unexpected APN status repsonse (%s)" % status

        except socket.timeout:
            return "Timeout"

        except socket.error, e:
            code,msg = e
            if code == errno.EPIPE:
                production_socket.close()
                sandbox_socket.close()
                init_apn_sockets()
            else:
                return "Error"

        retries -= 1


def init_apn_sockets():
    ''' 
    Opens SSL sockets for APN notifications. Two sockets are returned,
    one for production usage, one for sandobxed usage
    '''
    global production_socket, sandbox_socket

    try:
        production_socket = open_ssl_socket(APN_PRODUCTION_HOST,APN_PRODUCTION_CERT)
        sandbox_socket = open_ssl_socket(APN_SANDBOX_HOST, APN_SANDBOX_CERT)
    except ssl.SSLError, e:
        logging.exception( "Cant open ssl sockets")
        logging.exception("Shutting down...")
        sys.exit(1)


######################### REQUEST HANDLERS ############################

# Generate the SSL sockets
production_socket, sandbox_socket = None, None
init_apn_sockets()


# Create the application object
app = Flask(__name__)


@app.route("/test")
def help():
    ''' Validates that the server is up and running '''

    return "Push Proxy for APN\n"
    

@app.route("/", methods = ['POST'])
def main():
    ''' Sends APN push notifications for Apphance Guide '''
    
    use_sandbox = request.form.get("sandboxed", False)
    device_tokens = request.form.get('device_tokens')
    payload = request.form.get('payload')
    expiration = request.form.get('expiration', 86400)

    logging.debug(payload)
    provider_identifier = random.randint(0, 2**16)
    expiry = time.time() + int(expiration)
    expiry = int(expiry)

    # Validate the input data
    if not device_tokens: 
        return "Device Tokens are missing!"

    if not payload:       
        return "Payload is missing!"

    device_tokens = device_tokens.split(',')
    if len(device_tokens) < 1:
        return "Invalid device token format"

    # Format the header of the APN notification
    payload = payload.encode('ascii', errors='ignore')
    apn_data = '!BLLH32sH%ds' % len(payload)
    
    apn_notification = r''
    for token in device_tokens:
        # Strip the token and pack the notification data into a
        # binary format.
        token = token.strip().decode('hex')
        apn_notification += struct.pack(apn_data, 0, provider_identifier, expiry, 32, token, len(payload), payload)
    
    safe_send_apn(apn_notification, use_sandbox = use_sandbox)

    return "OK"


if __name__ == "__main__":
    app.debug = True
    
    fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler = logging.FileHandler(LOG_FILE)
    handler.setFormatter(fmt)
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)

    logging.debug("Starting the server...")
    app.run()



    