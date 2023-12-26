#!/usr/bin/env python3
#
# The purpose of this class is to drive unit tests against a server that
# handles requests for system statistics.  Unit tests will cover a number
# of areas, described as the following suites of tests:
#
#   1.  Correctness for good requests
#   2.  Correctness for expectable bad requests
#   3.  Malicious request handling
#
#

import atexit, base64, errno, getopt, json, multiprocessing, os
import random, requests, signal, socket, struct, string, subprocess
import sys, time, traceback, unittest, re

from datetime import datetime
from fractions import Fraction as F
from multiprocessing.dummy import Pool as ThreadPool
from socket import error as SocketError

from http.client import OK, NOT_FOUND, FORBIDDEN, BAD_REQUEST, METHOD_NOT_ALLOWED, NOT_IMPLEMENTED, HTTPConnection
random.seed(42)

script_dir = "/".join(os.path.realpath(__file__).split("/")[:-1])
if script_dir == "":
    script_dir = "."
script_dir = os.path.realpath(script_dir)

def encode(s):
    return s.encode('utf-8')

def get_socket_connection(hostname, port):
    """
    Connect to a server at hostname on the supplied port, and return the socket
    connection to the server.
    """
    for res in socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
        family, sockettype, protocol, canonname, socketaddress = res
        try:
            sock = socket.socket(family, sockettype, protocol)
            sock.settimeout(10)
            # avoid TCP listen overflows when making back-to-back requests 
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 1))

        except socket.error as msg:
            sock = None
            continue

        try:
            sock.connect(socketaddress)
        except socket.error as msg:
            sock.close()
            sock = None
            continue

        break

    if sock is None:
        raise ValueError('The script was unable to open a socket to the server')
    else:
        return sock

def run_connection_check_empty_login(http_conn, hostname):
    """
    Run a check of the connection for validity, using a well-formed
    request for /api/login and checking it after receiving it.
    """

    # GET request for the object /api/login
    http_conn.request("GET", "/api/login", headers={"Host": hostname})

    # Get the server's response
    server_response = http_conn.getresponse()

    # Check the response status code
    assert server_response.status == OK, "Server failed to respond. " \
            "This test will fail until persistent connections are implemented (i.e. HTTP/1.1 support). " \
            "We recommend you implement this before moving forward."

    # Check the data included in the server's response
    assert check_empty_login_respnse(server_response.read().decode('utf-8')), \
        "empty login check failed"

def run_404_check(http_conn, obj, hostname):
    """
    Checks that the server properly generates a 404 status message when
    requesting a non-existent URL object.
    """

    # GET request for obj
    http_conn.request("GET", obj, headers={"Host": hostname})

    # Get the server's response
    server_response = http_conn.getresponse()

    # Check the response status code
    assert server_response.status == NOT_FOUND, \
        "Server failed to respond with a 404 status for obj=" + obj + ", gave response: " + str(server_response.status)
    server_response.read()


def run_method_check(http_conn, method, hostname):
    """
    Check that the unsupported method supplied has either a NOT IMPLEMENTED
    or METHOD NOT ALLOWED response from the server.
    """

    http_conn.request(method, "/api/login", headers={"Host": hostname})
    server_response = http_conn.getresponse()
    assert (server_response.status == METHOD_NOT_ALLOWED or
            server_response.status == NOT_IMPLEMENTED), \
        "Server failed to respond with the METHOD NOT ALLOWED or \
        NOT IMPLEMENTED status for method: " + method + " response was: " \
        + str(server_response.status)
    server_response.read()


def print_response(response):
    """Print the response line by line as returned by the server.  the response
    variable is simply the server_response.read(), and this function prints out
    each line of the output.  Most helpful for printing an actual web page. """

    lines = response.split("\n")
    for line in lines:
        print(line.strip())

def check_empty_login_respnse(response):
    return response.strip() == "{}"

ld_preload = f'{script_dir}/getaddrinfo.so.1.0.1'
if not os.path.exists(ld_preload):
    print (f"Couldn't find ${ld_preload}, please run (cd {script_dir}; ./build.sh)")
    sys.exit(1)

def usage():
    print("""
    Usage: python3 server_unit_test_pserv.py -s server [-h, -t testname, -o outfile]
        -h              Show help
        -s server       File path to the server executable
        -t testname     Run a test by itself, its name given as testname
        -l              List available tests
        -6 host         Hostname of IPv6 localhost (default: localhost6)
        -v              Send output from the server to stdout
        -o outputfile   Send output from the server to an output file
          """)


def handle_exception(type, exc, tb):
    """Install a default exception handler.
    If there is an exception thrown at any time in the script,
    report that the test failed, close the server and exit.
    """
    print("\n>>> FAIL: ", type, "'", exc, "'\n")
    print(type.__doc__ + "\n")
    traceback.print_tb(tb)


def decode_base64(data):
    """Decode base64, padding being optional.

    :param data: Base64 data as a string
    :returns: The decoded byte string.

    Adapted from https://stackoverflow.com/a/9807138
    """
    data = data.encode()
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += b'='* (4 - missing_padding)

    return base64.b64decode(data)


# Install the default exception handler
sys.excepthook = handle_exception


##############################################################################
## Class: Doc_Print_Test_Case
## Extending the unittest.TestCase class for a better print of the __doc__
## type of each test method.
##
#
# TBD: investigate if this method was only used in Python 2.4 and isn't
# already part of TestCase in unittest in Python 2.6
#
##############################################################################

class Doc_Print_Test_Case(unittest.TestCase):
    def __init__(self, methodName='runTest'):
        """
        Overriding the super-class __init__ because it uses an internal
        attribute for the test method doc that is not inherited.
        """
        unittest.TestCase.__init__(self, methodName)

    def shortDescription(self):
        """
        Returns the __doc__ of the test method, instead of unittest.TestCase's
        standard action of returning the first line of the test method.  This
        will allow for more verbose testing with each method.
        """
        return self._testMethodDoc

##############################################################################
## Class: Single_Conn_Protocol_Case
## test cases that ensure HTTP/1.0 connections close automatically,
## and HTTP/1.1 connections have persistent connections.
##############################################################################

class Single_Conn_Protocol_Case(Doc_Print_Test_Case):
    """
    Test case for a single connection, checking various points of protocol
    usage that ensures the servers to be HTTP 1.0 and 1.1 compliant.
    Each case should be handled without the server crashing.
    """

    def __init__(self, testname, hostname, port):
        """
        Prepare the test case for creating connections.
        """
        super(Single_Conn_Protocol_Case, self).__init__(testname)
        self.hostname = hostname
        self.port = port

    def tearDown(self):
        """  Test Name: None -- tearDown function\n\
        Number Connections: N/A \n\
        Procedure: None.  An error here \n\
                   means the server crashed after servicing the request from \n\
                   the previous test.
        """
        if server.poll() is not None:
            # self.fail("The server has crashed.  Please investigate.")
            print("The server has crashed.  Please investigate.")

    def test_http_1_0_compliance(self):
        """  Test Name: test_http_1_0_compliance\n\
        Number Connections: 1 \n\
        Procedure: Writes "GET /api/login HTTP/1.0\\r\\n" to the server, then \n\
                   checks nothing has been returned, and finishes with the \n\
                   extra "\\r\\n" and checking the data sent back from the \n\
                   server.
        """
        # Make HTTP connection for the server
        sock = get_socket_connection(self.hostname, self.port)

        sock.send(encode("GET /api/login HTTP/1.0\r\n"))
        sock.send(encode("Host: " + self.hostname + "\r\n"))
        sock.settimeout(1)
        time.sleep(.1)
        try:
            if sock.recv(4096, socket.MSG_PEEK).decode('utf8') != '':
                self.fail("The http response was returned too early, before" + \
                          " the extra \r\n line.")

        except socket.timeout:
            pass

        sock.send(encode("\r\n"))
        # If there is a HTTP response, it should be a valid /login
        # response.
        data = ""

        time.sleep(0.1)
        try:
            while sock.recv(4096, socket.MSG_PEEK).decode('utf8') != '':
                msg_buffer = sock.recv(4096).decode('utf8')
                data = data + msg_buffer

        # Connections close after responses for HTTP/1.0 , therefore a timeout
        # should not occur.
        except socket.timeout:
            self.fail("The server did not respond and close the connection in sufficient time.")

        data = data.split("\r\n\r\n")
        assert len(data) == 2, \
            "The response could not be parsed, check your use of \\r\\n"

        assert check_empty_login_respnse(data[1]), \
            "The /login object was not properly returned."

        sock.close()

    def test_http_1_1_compliance(self):
        """  Test Name: test_http_1_1_compliance\n\
        Number Connections: 1 \n\
        Procedure: Ensure a persistent connection by sending seven consecutive\n\
                   requests to the server on one connection.
        """
        # Make HTTP connection for the server
        self.http_connection = HTTPConnection(self.hostname, self.port)
        self.http_connection.auto_open = 0

        # Connect to the server
        self.http_connection.connect()

        for x in range(0, 7):
            # GET request for the object /login
            self.http_connection.request("GET", "/api/login")

            # Get the server's response
            server_response = self.http_connection.getresponse()

            # Check that the server did not close the connection
            # this will be True if the server responds with a HTTP/1.1
            # independent of whether the connection has been closed or not.
            self.assertEqual(server_response._check_close(), False, \
                             "Server closed the connection")

            # Check the response status code
            self.assertEqual(server_response.status, OK, "Server failed to respond")

            # Check the data included in the server's response
            self.assertTrue(check_empty_login_respnse(server_response.read().decode('utf8')), \
                            "empty login response check failed")

        self.http_connection.close()


##############################################################################
## Class: Single_Conn_Malicious_Case
## Test cases that are attempting to break down the server
##############################################################################

class Single_Conn_Malicious_Case(Doc_Print_Test_Case):
    """
    Test case for a single connection, using particularly malicious requests
    that are designed to seek out leaks and points that lack robustness.
    Each case should be handled without the server crashing.
    """

    def __init__(self, testname, hostname, port):
        """
        Prepare the test case for creating connections.
        """
        super(Single_Conn_Malicious_Case, self).__init__(testname)
        self.hostname = hostname
        self.port = port
        self.private_file = 'private/secure.html'
        self.username = 'user0'
        self.password = 'thepassword'

        # Prepare the a_string for query checks
        self.a_string = "aaaaaaaaaaaaaaaa"
        for x in range(0, 6):
            self.a_string = self.a_string + self.a_string


    def setUp(self):
        """  Test Name: None -- setUp function\n\
        Number Connections: N/A \n\
        Procedure: Create requests session.
        """
        # Create a requests session
        self.session = requests.Session()

    def tearDown(self):
        """  Test Name: None -- tearDown function\n\
        Number Connections: N/A \n\
        Procedure: An error here \
                   means the server crashed after servicing the request from \
                   the previous test.
        """

        if server.poll() is not None:
            # self.fail("The server has crashed.  Please investigate.")
            print("The server has crashed.  Please investigate.")
        # Close the requests session
        self.session.close()

    def test_method_check_long(self):
        """  Test Name: test_method_check_4\n\
        Number Connections: 1 \n\
        Procedure: Test a request using a long method:\n\
            aa....aaa /api/login HTTP/1.1
        """
        http_connection = HTTPConnection(hostname, port)
        run_method_check(http_connection, self.a_string*2, self.hostname)
        http_connection.close()

    def test_method_check_4(self):
        """  Test Name: test_method_check_4\n\
        Number Connections: 1 \n\
        Procedure: Test a request using a different method than GET:\n\
            ASD /api/login HTTP/1.1
        """
        http_connection = HTTPConnection(hostname, port)
        run_method_check(http_connection, "ASD", self.hostname)
        http_connection.close()

    def test_login_post_invalid_body(self):
        """ Test Name: test_login_post_invalid_body\n
        Number Connections: One \n\
        Procedure: Simple POST request:\n\
            POST /api/login HTTP/1.1

        Run a check for login by providing an ill-formed body i.e. not JSON
        for /api/login. Not checking for response text.
        """
        http_connection = HTTPConnection(hostname, port)
        # Ill-formed body for the request
        data = '"username": "%s", "password": "%s"' % (self.username, self.password)

        # POST request for login
        http_connection.request("POST", "/api/login", data)

        # Get the server response
        server_response = http_connection.getresponse()

        # Check the response code (403 or 400)
        self.assertTrue(server_response.status == FORBIDDEN or
                        server_response.status == BAD_REQUEST)
        http_connection.close()

    def test_multi_connection_disconnect(self):
        """  Test Name: test_multi_connection_disconnect\n\
        Number Connections: 5 \n\
        Procedure: tries to do a login GET request but fails and closes connection at some point during
        the request response sequence.
        """
        request_string = f'GET /api/login HTTP/1.1\r\nHost: {self.hostname}\r\n\r\n'.encode()
        nconnections = len(request_string)
        connection_list = [ (get_socket_connection(self.hostname, self.port), i) for i in range(nconnections) ]
        random.shuffle(connection_list)

        # write one character to each until they are at the failure point
        for idx in range(len(request_string)):
            for sock, stop_idx in connection_list:
                if idx < stop_idx:
                    sock.send(request_string[idx:idx+1])

        for sock, _ in connection_list:
            sock.close()

        # since we are using raw sockets here, we can't and don't test the result.
        # it suffices if the server doesn't crash

    def test_file_descriptor_leak(self):
        """  Test Name: test_file_descriptor_leak\n\
        Number Connections: 4000, but only one is connected at a time \n\
        Procedure: 4000 connections are processed as follows: \n\
            1.  Make the connection\n\
            2.  Test a /api/login request\n\
            3.  Close the connection\n\
        IMPORTANT NOTE: May also thread/fork-bomb your server!
        """
        start = time.time()
        for x in range(4000):
            http_connection = HTTPConnection(hostname, port)
            # avoid TCP listen overflows
            http_connection.connect()
            http_connection.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 1))

            # GET request for the object /login
            http_connection.request("GET", "/api/login")

            # Get the server's response
            server_response = http_connection.getresponse()

            # Check the response status code
            assert server_response.status == OK, "Server failed to respond"

            # Check the data included in the server's response
            assert check_empty_login_respnse(server_response.read().decode('utf8')), \
                "api/login check failed"
            http_connection.close()
            if time.time() - start > 60:
                raise AssertionError("Timeout - took more than 60 seconds")

    def test_file_descriptor_early_disco_leak_1(self):
        """  Test Name: test_file_descriptor_early_disco_leak_1\n\
        Number Connections: 4000, but only one is connected at a time \n\
        Procedure: 4000 connections are processed as follows: \n\
            1.  Make the connection\n\
            2.  Send to the server: GET /api/login HTTP/1.1\\r\\n\n\
                  NOTE: Only ONE \\r\\n is sent!\n\
            3.  Close the connection\n\
        IMPORTANT NOTE: May also thread/fork-bomb your server!
        """
        # Test note: the failure will be induced if get_socket_connection
        # is unable to create a new connection, and an assertion error is thrown
        start = time.time()
        for x in range(4000):
            socket = get_socket_connection(self.hostname, self.port)

            # Write to the server
            socket.send(encode("GET /api/login HTTP/1.1\r\n"))
            socket.send(encode("Host: " + self.hostname + "\r\n"))
            # Close the socket
            socket.close()
            if time.time() - start > 60:
                raise AssertionError("Timeout - took more than 60 seconds")

    def test_file_descriptor_early_disco_leak_2(self):
        """  Test Name: test_file_descriptor_early_disco_leak_2\n\
        Number Connections: 2000, but only one is connected at a time \n\
        Procedure: 2000 connections are processed as follows: \n\
            1.  Make the connection\n\
            2.  Send to the server: GET /api/login HTTP/1.1\n\
                  NOTE: NO \\r\\n's are sent!\n\
            3.  Close the connection\n\
        IMPORTANT NOTE: May also thread/fork-bomb your server!
        """

        # Test note: the failure will be induced if get_socket_connection
        # is unable to create a new connection, and an assertion error is thrown
        start = time.time()
        for x in range(4000):
            socket = get_socket_connection(self.hostname, self.port)

            # Write to the server
            socket.send(encode("GET /api/login HTTP/1.1"))

            # Close the socket
            socket.close()
            if time.time() - start > 60:
                raise AssertionError("Timeout - took more than 60 seconds")

    def test_80_kb_URI(self):
        """  Test Name: test_80_kb_URI\n\
        Number Connections: 1\n\
        Procedure: Send a GET request for a URI object that is 80kb long.\n\
                   Then check that another connection and request can still\n\
                   be made.  Also, ensure that an appropriate response is\n\
                   sent to the 80kb request.\n\
        """

        sock = get_socket_connection(self.hostname, self.port)

        sock.send(encode("GET "))

        data = ''
        try:
            for x in range(1, 10240):
                sock.send(encode("/api/login"))

            sock.send(encode(" HTTP/1.1\r\n"))
            sock.send(encode("Host: " + self.hostname + "\r\n\r\n"))

            # If there is a HTTP response, it should NOT be a valid /api/login
            # response.  All other responses are fine, including closing the
            # connection, so long as the server continues serving other connections
            sock.settimeout(1)
            data = ""

            time.sleep(0.1)
            while sock.recv(4096, socket.MSG_PEEK).decode('utf8') != '':
                msg_buffer = sock.recv(4096).decode('utf8')
                data = data + msg_buffer

                # Socket timeouts are not expected for HTTP/1.0 , therefore an open
                # connection is bad.
        except socket.timeout:
            pass
        except SocketError as e:
            if e.errno != errno.ECONNRESET:
                raise

        data = data.split("\r\n\r\n")

        try:
            if len(data) >= 2 and check_empty_login_respnse(data[1]):
                self.fail("A valid /api/login object was returned for an invalid request.")

        # If an error is generated, it comes from trying to an interpret a JSON
        # object that doesn't exist.
        except (AssertionError, ValueError):
            pass

        sock.close()

        # Make HTTP connection for the server
        self.http_connection = HTTPConnection(self.hostname, self.port)

        # Connect to the server
        self.http_connection.auto_open = 0
        self.http_connection.connect()

        # GET request for the object /api/login
        self.http_connection.request("GET", "/api/login")

        # Get the server's response
        server_response = self.http_connection.getresponse()

        # Check the response status code
        self.assertEqual(server_response.status, OK, "Server failed to respond")

        # Check the data included in the server's response
        self.assertTrue(check_empty_login_respnse(server_response.read().decode('utf8')), \
                        "api/login check failed")

        self.http_connection.close()

    def test_byte_wise_request(self):
        """  Test Name: test_byte_wise_request\n\
        Number Connections: 1\n\
        Procedure: Send a request for GET /api/login HTTP/1.1 byte by byte.\n\
        """

        # Make the low-level connection
        sock = get_socket_connection(self.hostname, self.port)

        for x in "GET /api/login HTTP/1.0\r\nHost: " + self.hostname + "\r\n":
            sock.send(encode(x))
            time.sleep(0.1)

        sock.settimeout(1)
        msg_buffer = ''
        try:
            if sock.recv(4096, socket.MSG_PEEK).decode('utf8') != '':
                self.fail("Data was returned before the extra \r\n")

        # We want nothing back until after we've sent the last \r\n
        except socket.timeout:
            pass

        if msg_buffer != '':
            self.fail("The server responded before the full request was sent.")

        sock.send(encode("\r"))
        sock.send(encode("\n"))

        time.sleep(0.1)
        # Collect the response
        try:
            while sock.recv(4096, socket.MSG_PEEK).decode('utf8') != '':
                data = sock.recv(4096).decode('utf8')
                msg_buffer = msg_buffer + data

                # Check the response
                data = data.split("\r\n\r\n")
        except socket.timeout:
            self.fail("The socket timed out on responding to the message.")
            return

        if len(data) == 2 and check_empty_login_respnse(data[1]):
            pass
        elif len(data) != 2:
            self.fail("The server did not return the proper api/login data")
        else:
            self.fail("A proper login object was not returned.")

        sock.close()
    
    def test_auth_browser_cookies(self):
        """ Test Name: test_auth_browser_cookies
        Number Connections: N/A
        Procedure: Sends cookies that are actually taken from one a web browser
        when connecting to courses.cs.vt.edu. They're valid cookies, but they
        should not be recognized by the server as valid authentication.
        Similar idea for test_auth_wrong_cookie. A failure here means the server
        might have crashed or it served a private file despite without checking
        for valid authentication.
        """
        # set up a few different cookies to try (no, these don't actually work
        # - don't try any session hijacking with these cookies ;), we made
        # sure they are invalid)
        cookies = [
            ["IDMSESSID", "9DD957C450BBCFE9D75022A05DC71D0E701FE23AF0DEE777090831C9FFD087FF0EE5704771BA11D02B3FA5CC13F20B4F8A6758A02768E160AE1E100A8D4BECCE"],
            ["auth_token", "[\"hokiebird\"\054 \"Hokie Bird\"].Yhy5-g.HXxh5WxmTawBv_LHPaTLnXNkYiI|5b9df2848955b572910a6ff3d2c98d27febbe6a8949c18cde52c8c11c91ed5437f40accae8f8b77a41e335e83556a3670d5f5178d8ddd4f8eb83e1a82974ce4a"],
            ["session", ".eJwlzsFKw0AQgOFXKXuuZXczm93psV4qFBEs2GAkzM7OJEVNIaG2IL67hV7_e_L9mk4nmQezVvqaZWm6YzFrQ947cJoLRslQAaDW3hlSql2JZKUUT5m9S1LFCEKRMaqVKFqSg0hellofmStWUATRANYGmzmRdRA4E6KU2musEFXZ5aBY2hiyoGRukPMs013z3hq-zMO571uzXLTm8TSOp2xxei8fq2ZowkO_2h6uQ3i7fu_plvnpdtsX2u_Gw_Nnc3zyf_8CpUfl.Yjo3NQ.m-n22sd9bMNXyvtXpIS6dZ85Cv4"]
        ]

        # now, come up with various combinations of cookies to try
        cookie_combos = []
        for c1 in cookies:
            combo = []
            combo.append(c1)
            cookie_combos.append([c1])
            for c2 in cookies:
                if c1 != c2:
                    combo.append(c2)
            cookie_combos.append(combo)

        # loop through each of the cookies
        for combo in cookie_combos:
            # clear the session cookies and set cookies
            self.session.cookies.clear()
            for cookie in combo:
                self.session.cookies.set(cookie[0], cookie[1])

            # try making a GET /api/login request
            response = None
            try:
                response = self.session.get('http://%s:%s/api/login' % (self.hostname, self.port), timeout=2)
            except requests.exception.RequestException:
                raise AssertionError("The server did not respond within 2s")

            # make sure the correct response code was sent
            if response.status_code != requests.codes.ok:
                raise AssertionError("The server responded with %d instead of 200 OK for a GET /api/login request" %
                                     response.status_code)

            # make sure the JSON data returned is empty
            if response.text.strip() != "{}":
                raise AssertionError("The server returned something other than an empty JSON object ({}) for a "
                                     "GET /api/login request with invalid cookies. Received: '%s'" % response.text)

            # now, try making a request for a private file
            response = None
            try:
                response = self.session.get('http://%s:%s/private/secure.html' % (self.hostname, self.port), timeout=2)
            except requests.exception.RequestException:
                raise AssertionError("The server did not respond within 2s")

            # make sure we didn't receive a 200 OK
            if response.status_code == requests.codes.ok:
                raise AssertionError("The server served a private file despite not being authenticated.")


##############################################################################
## Class: Single_Conn_Bad_Case
## Test cases that aim for various errors in well-formed queries.
##############################################################################

class Single_Conn_Bad_Case(Doc_Print_Test_Case):
    """
    Test case for a single connection, using bad requests that are
    well formed.  The tests are aptly named for describing their effects.
    Each case should be handled gracefully and without the server crashing.
    """

    def __init__(self, testname, hostname, port):
        """
        Prepare the test case for creating connections.
        """
        super(Single_Conn_Bad_Case, self).__init__(testname)
        self.hostname = hostname
        self.port = port
 
        N = 10
        self.username = 'user0'
        self.invalid_username = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for _ in range(N))
        self.password = 'thepassword'
        self.invalid_password = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for _ in range(N))
        self.private_file = 'private/secure.html'

    def setUp(self):
        """  Test Name: None -- setUp function\n\
        Number Connections: N/A \n\
        Procedure: Opens the HTTP connection to the server.  An error here \
                   means the script was unable to create a connection to the \
                   server.
        """
        # make a 'session' object (used by some of the tests that were moved
        # here)
        self.session = requests.Session()

        # Make HTTP connection for the server
        self.http_connection = HTTPConnection(self.hostname, self.port)

        # Connect to the server
        self.http_connection.auto_open = 0
        self.http_connection.connect()

    def tearDown(self):
        """  Test Name: None -- tearDown function\n\
        Number Connections: N/A \n\
        Procedure: Closes the HTTP connection to the server.  An error here \
                   means the server crashed after servicing the request from \
                   the previous test.
        """
        # Close the HTTP connection
        self.http_connection.close()
        if server.poll() is not None:
            # self.fail("The server has crashed.  Please investigate.")
            print("The server has crashed.  Please investigate.")

    def test_404_not_found_1(self):
        """  Test Name: test_404_not_found_1\n\
        Number Connections: 1 \n\
        Procedure: Test a simple GET request for an illegal object URL:\n\
            GET /junk HTTP/1.1
        """
        run_404_check(self.http_connection, "/api/junk", self.hostname)

    def test_404_not_found_2(self):
        """  Test Name: test_404_not_found_2\n\
        Number Connections: 1 \n\
        Procedure: Test a simple GET request for an illegal object URL:\n\
            GET /api/login/api/login HTTP/1.1
        """
        run_404_check(self.http_connection, "/api/login/api/login", self.hostname)

    def test_404_not_found_3(self):
        """  Test Name: test_404_not_found_3\n\
        Number Connections: 1 \n\
        Procedure: Test a simple GET request for an illegal object URL:\n\
            GET /api/logon HTTP/1.1
        """
        run_404_check(self.http_connection, "/api/logon", self.hostname)

    def test_404_not_found_4(self):
        """  Test Name: test_404_not_found_4\n\
        Number Connections: 1 \n\
        Procedure: Test a simple GET request for an illegal object URL:\n\
            GET /api/api/login HTTP/1.1
        """
        run_404_check(self.http_connection, "/api/api/login", self.hostname)

    def test_404_not_found_5(self):
        """  Test Name: test_404_not_found_5\n\
        Number Connections: 1 \n\
        Procedure: Test a simple GET request for an illegal object URL:\n\
            GET /api/loginjunk HTTP/1.1
        """
        run_404_check(self.http_connection, "/api/api", self.hostname)

    def test_404_not_found_6(self):
        """  Test Name: test_404_not_found_6\n\
        Number Connections: 1 \n\
        Procedure: Test a simple GET request for an illegal object URL:\n\
            GET /api/loginjunk HTTP/1.1
        """
        run_404_check(self.http_connection, "/api/loginjunk", self.hostname)

    def test_404_not_found_7(self):
        """  Test Name: test_404_not_found_7\n\
        Number Connections: 1 \n\
        Procedure: Test a simple GET request for an illegal object URL:\n\
            GET /login/api HTTP/1.1
        """
        run_404_check(self.http_connection, "/login/api", self.hostname)
    
    def test_login_post_invalid_username(self):
        """ Test Name: test_login_post_invalid_username\n
        Number Connections: One \n\
        Procedure: Simple POST request:\n\
            POST /api/login HTTP/1.1

        Run a check for login by providing an incorrect username using a
        well-formed request for /api/login. Not checking for response text.
        """
        # JSON body for the request
        data = {"username": self.invalid_username, "password": self.password}
        body = json.dumps(data)

        # POST request for login
        self.http_connection.request("POST", "/api/login", body)

        # Get the server response
        server_response = self.http_connection.getresponse()

        # Check the response code
        self.assertEqual(server_response.status, FORBIDDEN)

    def test_login_post_invalid_password(self):
        """ Test Name: test_login_post_invalid_password\n
        Number Connections: One \n\
        Procedure: Simple POST request:\n\
            POST /api/login HTTP/1.1

        Run a check for login by providing an incorrect password using a
        well-formed request for /api/login. Not checking for response text.
        """
        # JSON body for the request
        data = {"username": self.username, "password": self.invalid_password}
        body = json.dumps(data)

        # POST request for login
        self.http_connection.request("POST", "/api/login", body)

        # Get the server response
        server_response = self.http_connection.getresponse()

        # Check the response code
        self.assertEqual(server_response.status, FORBIDDEN)
 
    def test_login_valid_body_extra_parameters(self):
        """  Test Name: test_login_valid_body_extra_parameters\n
        Number Connections: One \n\
        Procedure: Simple POST request:\n\
            POST /api/login HTTP/1.1

        Run a check for login by providing a well-formed body with extra
        parameters in the JSON body for /api/login. Not checking for
        response text.
        """
        # JSON body for the request
        data = {"username": self.username, "password": self.password, "key": "value"}
        body = json.dumps(data)

        # POST request for login
        self.http_connection.request("POST", "/api/login", body)

        # Get the server response
        server_response = self.http_connection.getresponse()

        # Check the response code
        self.assertEqual(server_response.status, OK)

    def test_auth_flipped_token(self):
        """ Test Name: test_auth_flipped_token
        Number Connections: N/A
        Procedure: Checks if JSON parsing appropriately covers the case
                   when the correct key/value pair is present, but the
                   order in which it appears is flipped.
                   For example, typically one might expect:
                     '{"username": "<username>", "password": "<password>"}'
                   This tests for parsing of:
                     '{"password": "<password>", "username": "<username>"}'
        """
        # Login using the default credentials, with the password appearing
        # first in the JWT, followed by the username
        try:
            response = self.session.post('http://%s:%s/api/login' % (self.hostname, self.port),
                                         json={'password': self.password, 'username': self.username},
                                         timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that the user is authenticated
        self.assertEqual(response.status_code, requests.codes.ok, "Authentication failed.")

        # Define the private URL to get
        url = 'http://%s:%s/%s' % (self.hostname, self.port, self.private_file)

        # Use the session cookie to get the private file
        try:
            response = self.session.get(url, timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that access is granted
        self.assertEqual(response.status_code, requests.codes.ok,
                         "Server did not respond with private file despite being authenticated.")

    def test_auth_wrong_cookie(self):
        """ Test Name: test_auth_wrong_cookie
        Number Connections: N/A
        Procedure: Sends multiple requests with different cookies:
                     0. (First, a POST to /api/login to retrieve a valid cookie)
                     1. A cookie with the wrong name and correct JWT value
                     2. A cookie with the wrong name and wrong JWT value
                     3. Two cookies, both with wrong names and values
                     4. One wrong cookie, and one correct cookie.
                   Requests 1-3 should NOT be allowed to access a private file.
                   Request 4 SHOULD be allowed to access a private file.
                   (Note: a "wrong" name/value means a name/value that doesn't
                   equal the cookie returned by a successful POST to /api/login.)
        """
        # Login using the default credentials
        try:
            response = self.session.post('http://%s:%s/api/login' % (self.hostname, self.port),
                                         json={'username': self.username, 'password': self.password},
                                         timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that the user is authenticated
        self.assertEqual(response.status_code, requests.codes.ok, "Authentication failed.")

        # Define the private URL to get
        url = 'http://%s:%s/%s' % (self.hostname, self.port, self.private_file)

        # find the cookie returned by the server (its name and value)
        cookie_dict = self.session.cookies.get_dict()        # convert cookies to dict
        self.assertEqual(len(cookie_dict), 1, "Server did not return an authentication token.")
        cookie_key = list(cookie_dict.keys())[0]             # grab cookie's name
        cookie_val = self.session.cookies.get(cookie_key)    # grab cookie value
        # create a few "bad cookie" key-value pairs
        bad_cookie1_key = "a_bad_cookie1"
        bad_cookie1_val = "chocolate_chip"
        bad_cookie2_key = "a_bad_cookie2"
        bad_cookie2_val = "oatmeal_raisin"

        # ---------- test 1: same cookie value, different name ---------- #
        # append a string to the cookie name, making it the wrong cookie.
        # Then, clear the session cookies and add the wrong cookie
        self.session.cookies.clear()                         # wipe cookies
        self.session.cookies.set(bad_cookie1_key, cookie_val) # add wrong-named cookie
        
        # Use the INVALID cookie to try to get the private file
        try:
            response = self.session.get(url, timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that access is forbidden
        self.assertEqual(response.status_code, requests.codes.forbidden,
                         "Server responded with private file despite not being authenticated.")
        
        # ----------- test 2: different cookie value AND name ----------- #
        # append a string to the cookie value. Then, update the bad cookie's value
        self.session.cookies.set(bad_cookie1_key, bad_cookie1_val)
        
        # Use the INVALID cookie to try to get the private file
        try:
            response = self.session.get(url, timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that access is forbidden
        self.assertEqual(response.status_code, requests.codes.forbidden,
                         "Server responded with private file despite not being authenticated.")
        
        # ------------- test 3: multiple incorrect cookies -------------- #
        # set another cookie, so we end up sending TWO invalid cookies
        self.session.cookies.set(bad_cookie2_key, bad_cookie2_val)
        
        # Use the INVALID cookies to try to get the private file
        try:
            response = self.session.get(url, timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that access is forbidden
        self.assertEqual(response.status_code, requests.codes.forbidden,
                         "Server responded with private file despite not being authenticated.")
        
        # --------- test 4: one bad cookie, one correct cookie ---------- #
        # clear the session cookies and add a bad cookie followed by a good cookie
        self.session.cookies.clear()
        self.session.cookies.set(bad_cookie1_key, bad_cookie1_val)
        self.session.cookies.set(cookie_key, cookie_val)
        
        # this time, even though we do have a wrong cookie, we also have the
        # correct cookie. So, the student's code *should* see this correct
        # cookie and allow us to get access to the private file
        try:
            response = self.session.get(url, timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that access is forbidden
        self.assertEqual(response.status_code, requests.codes.ok,
                         "Server failed to respond with private file despite being authenticated.")


class Multi_Conn_Sequential_Case(Doc_Print_Test_Case):
    """
    Test case for multiple connections, using good requests that are properly
    formed.  Further, the requests are processed sequentially.
    The tests are aptly named for describing their effects.
    """

    def __init__(self, testname, hostname, port):
        """
        Prepare the test case for creating connections.
        """
        super(Multi_Conn_Sequential_Case, self).__init__(testname)
        self.hostname = hostname
        self.port = port

    def setUp(self):
        """  Test Name: None -- setUp function\n\
        Number Connections: N/A \n\
        Procedure: Opens the HTTP connection to the server.  An error here \
                   means the script was unable to create a connection to the \
                   server.
        """
        self.http_connections = []

    def tearDown(self):
        """  Test Name: None -- tearDown function\n\
        Number Connections: N/A \n\
        Procedure: Closes the HTTP connection to the server.  An error here \
                   means the server crashed after servicing the request from \
                   the previous test.
        """
        for http_conn in self.http_connections:
            http_conn.close()
        if server.poll() is not None:
            # self.fail("The server has crashed.  Please investigate.")
            print("The server has crashed.  Please investigate.")

    def test_two_connections(self):
        """  Test Name: test_two_connections\n\
        Number Connections: 2 \n\
        Procedure: Run 2 connections simultaneously for simple GET requests:\n\
                        GET /api/login HTTP/1.1
                   NOTE: this test requires HTTP/1.1 persistent connection support.
        """

        # Append two connections to the list
        for x in range(2):
            self.http_connections.append(HTTPConnection(self.hostname,
                                                        self.port))
        # Connect each connection
        for http_conn in self.http_connections:
            http_conn.connect()

        # Run a request for /api/login and check it
        # we run these in opposite order so that serial server implementations
        # fail.
        for http_conn in reversed(self.http_connections):
            run_connection_check_empty_login(http_conn, self.hostname)

        # Run a request for /api/login and check it
        for http_conn in self.http_connections:
            run_connection_check_empty_login(http_conn, self.hostname)



    def test_four_connections(self):
        """  Test Name: test_four_connections\n\
        Number Connections: 4 \n\
        Procedure: Run 4 connections simultaneously for simple GET requests:\n\
                        GET /api/login HTTP/1.1
                   NOTE: this test requires HTTP/1.1 persistent connection support.
        """

        # Append four connections to the list
        for x in range(4):
            self.http_connections.append(HTTPConnection(self.hostname,
                                                        self.port))
        # Connect each connection
        for http_conn in self.http_connections:
            http_conn.connect()

        # Run a request for /api/login and check it
        for http_conn in reversed(self.http_connections):
            run_connection_check_empty_login(http_conn, self.hostname)

        # Run a request for /api/login and check it
        for http_conn in self.http_connections:
            run_connection_check_empty_login(http_conn, self.hostname)

    def test_eight_connections(self):
        """  Test Name: test_eight_connections\n\
        Number Connections: 8 \n\
        Procedure: Run 8 connections simultaneously for simple GET requests:\n\
                        GET /api/login HTTP/1.1
                   NOTE: this test requires HTTP/1.1 persistent connection support.
        """

        # Append eight connections to the list
        for x in range(8):
            self.http_connections.append(HTTPConnection(self.hostname,
                                                        self.port))
        # Connect each connection
        for http_conn in self.http_connections:
            http_conn.connect()

        # Run a request for /api/login and check it
        for http_conn in reversed(self.http_connections):
            run_connection_check_empty_login(http_conn, self.hostname)

        # Re-connect in the case of HTTP/1.0 protocol implementation
        for http_conn in self.http_connections:
            http_conn.connect()

        # Run a request for /api/login and check it
        for http_conn in self.http_connections:
            run_connection_check_empty_login(http_conn, self.hostname)



class Single_Conn_Good_Case(Doc_Print_Test_Case):
    """
    Test case for a single connection, using good requests that are properly
    formed.  The tests are aptly named for describing their effects.
    """

    def __init__(self, testname, hostname, port):
        """
        Prepare the test case for creating connections.
        """
        super(Single_Conn_Good_Case, self).__init__(testname)

        self.hostname = hostname
        self.port = port

    def setUp(self):
        """  Test Name: None -- setUp function\n\
        Number Connections: N/A \n\
        Procedure: Opens the HTTP connection to the server.  An error here \
                   means the script was unable to create a connection to the \
                   server.
        """
        # Make HTTP connection for the server
        self.http_connection = HTTPConnection(self.hostname, self.port)

        # Connect to the server
        self.http_connection.connect()

    def tearDown(self):
        """  Test Name: None -- tearDown function\n\
        Number Connections: N/A \n\
        Procedure: Closes the HTTP connection to the server.  An error here \
                   means the server crashed after servicing the request from \
                   the previous test.
        """
        # Close the HTTP connection
        self.http_connection.close()
        if server.poll() is not None:
            # self.fail("The server has crashed.  Please investigate.")
            print("The server has crashed.  Please investigate.")

    def test_login_get(self):
        """  Test Name: test_login_get\n\
        Number Connections: One \n\
        Procedure: Simple GET request:\n\
            GET /api/login HTTP/1.1
        """

        # GET request for the object /api/login
        self.http_connection.request("GET", "/api/login")

        # Get the server's response
        server_response = self.http_connection.getresponse()

        # Check the response status code
        self.assertEqual(server_response.status, OK, "Server failed to respond")

        # Check the data included in the server's response
        self.assertTrue(check_empty_login_respnse(server_response.read().decode('utf8')), \
                        "login check failed")


class Access_Control(Doc_Print_Test_Case):
    """
    Test cases for access control, using good requests that are properly
    formed. The tests are aptly named for describing their effects.
    """

    def __init__(self, testname, hostname, port):
        """
        Prepare the test case for creating connections.
        """
        super(Access_Control, self).__init__(testname)

        self.hostname = hostname
        self.port = port
        self.public_file_1 = 'index.html'
        self.public_file_2 = 'js/jquery.min.js'
        self.public_file_3 = 'css/jquery-ui.min.css'
        self.private_file = 'private/secure.html'
        self.username = 'user0'
        self.password = 'thepassword'
        self.invalid_password = 'wrongpassword'

    def setUp(self):
        """  Test Name: None -- setUp function\n\
        Number Connections: N/A \n\
        Procedure: Opens the HTTP connection to the server.  An error here \
                   means the script was unable to create a connection to the \
                   server.
        """
        # Create a requests session
        self.session = requests.Session()

    def tearDown(self):
        """  Test Name: None -- tearDown function\n\
        Number Connections: N/A \n\
        Procedure: Closes the HTTP connection to the server.  An error here \
                   means the server crashed after servicing the request from \
                   the previous test.
        """
        # Close the HTTP connection
        self.session.close()

    # =============================== Helpers ================================ #
    # Does a lower-case search for headers within a response's headers. If
    # found, the first ocurrence is returned (the header's value is returned).
    def find_header(self, response, name):
        for header in response.headers:
            if header.lower() == name.lower():
                return response.headers[header]
        return None


    # ================================ Tests ================================= #
    def test_access_control_private_valid_token(self):
        """ Test Name: test_access_control_private_valid_token
        Number Connections: N/A
        Procedure: Checks if private files can be accessed given the right
                   username and password. An error here means that the either
                   the server did not authenticate the user correctly or that
                   despite being authenticated the user is not served with
                   the contents of the private path.
        """
        # Login using the default credentials
        try:
            response = self.session.post('http://%s:%s/api/login' % (self.hostname, self.port),
                                         json={'username': self.username, 'password': self.password},
                                         timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that the user is authenticated
        self.assertEqual(response.status_code, requests.codes.ok, "Authentication failed.")

        # Define the private URL to get
        url = 'http://%s:%s/%s' % (self.hostname, self.port, self.private_file)

        # Use the session cookie to get the private file
        response = self.session.get(url, timeout=2)

        # Ensure that access is granted
        self.assertEqual(response.status_code, requests.codes.ok,
                         "Server failed to respond with private file despite being authenticated.")
    
    def test_access_control_public_valid_token(self):
        """ Test Name: test_access_control_public_valid_token
        Number Connections: N/A
        Procedure: Checks if public files can be accessed given the right
                   username and password. Public paths DO NOT require a
                   username and password. A failure here means that
                   authentication failed or that public paths are not being
                   served.
        """
        # Login using the default credentials
        try:
            response = self.session.post('http://%s:%s/api/login' % (self.hostname, self.port),
                                         json={'username': self.username, 'password': self.password},
                                         timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that the user is authenticated
        self.assertEqual(response.status_code, requests.codes.ok, "Authentication failed.")

        # Define the public URL to get - test HTML file
        url = 'http://%s:%s/%s' % (self.hostname, self.port, self.public_file_1)

        # Use the session cookie to get the private file
        try:
            response = self.session.get(url, timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that access is granted
        self.assertEqual(response.status_code, requests.codes.ok,
                         "Server failed to respond with public file despite being authenticated.")

        # Ensure that file was correctly returned
        self.assertEqual(response.content, open(f'{base_dir}/{self.public_file_1}', 'rb').read())

        # Define the public URL to get - test JS file
        url = 'http://%s:%s/%s' % (self.hostname, self.port, self.public_file_2)

        # Use the session cookie to get the private file
        try:
            response = self.session.get(url, timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that access is granted
        self.assertEqual(response.status_code, requests.codes.ok,
                         "Server failed to respond with public file despite being authenticated.")

        # Ensure that file was correctly returned
        self.assertEqual(response.content, open(f'{base_dir}/{self.public_file_2}', 'rb').read())

        # Define the public URL to get - test CSS file
        url = 'http://%s:%s/%s' % (self.hostname, self.port, self.public_file_3)

        # Use the session cookie to get the private file
        try:
            response = self.session.get(url, timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that access is granted
        self.assertEqual(response.status_code, requests.codes.ok,
                         "Server failed to respond with public file despite being authenticated.")

        # Ensure that file was correctly returned
        self.assertEqual(response.content, open(f'{base_dir}/{self.public_file_3}', 'rb').read())
                
    def test_access_control_public_no_token(self):
        """ Test Name: test_access_control_public_no_token
        Number Connections: N/A
        Procedure: Checks if public files can be accessed without a username
                   and password. A failure here means that public paths are
                   not being served.
        """
        # Define the public URL to get - test HTML file
        url = 'http://%s:%s/%s' % (self.hostname, self.port, self.public_file_1)

        # Use the session cookie to get the private file
        try:
            response = self.session.get(url, timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that access is granted
        self.assertEqual(response.status_code, requests.codes.ok,
                         "Server failed to respond with a public file.")

        # Define the public URL to get - test JS file
        url = 'http://%s:%s/%s' % (self.hostname, self.port, self.public_file_1)

        # Use the session cookie to get the private file
        try:
            response = self.session.get(url, timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that access is granted
        self.assertEqual(response.status_code, requests.codes.ok,
                         "Server failed to respond with a public file.")

        # Define the public URL to get - test CSS file
        url = 'http://%s:%s/%s' % (self.hostname, self.port, self.public_file_1)

        # Use the session cookie to get the private file
        try:
            response = self.session.get(url, timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that access is granted
        self.assertEqual(response.status_code, requests.codes.ok,
                         "Server failed to respond with a public file.")
                        
    def test_access_control_private_invalid_token(self):
        """ Test Name: test_access_control_private_invalid_token
        Number Connections: N/A
        Procedure: Checks if private files can be accessed given invalid
                   authentication details. A failure here means that
                   authentication succeeded or that private paths are being
                   served without authentication.
        """
        # Login using the default credentials
        try:
            response = self.session.post('http://%s:%s/api/login' % (self.hostname, self.port),
                                         json={'username': self.username, 'password': self.invalid_password},
                                         timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that the user is authenticated
        self.assertEqual(response.status_code, requests.codes.forbidden, "Authentication failed.")

        # Define the private URL to get
        url = 'http://%s:%s/%s' % (self.hostname, self.port, self.private_file)

        # Use the session cookie to get the private file
        try:
            response = self.session.get(url, timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that access is forbidden
        self.assertEqual(response.status_code, requests.codes.forbidden,
                         "Server responded with private file despite not being authenticated.")
                         
    def test_access_control_private_valid_semantic_token(self):
        """ Test Name: test_access_control_private_valid_semantic_token
        Number Connections: N/A
        Procedure: Checks if JSON parsing appropriately guards against
                   missing key/value pairs in the request body (e.g. a 
                   request without "username" or "password".)
                   The JSON might be semantically valid, but not
                   hold the requisite key/value pairs that are needed.
        """
        # Login using the default credentials
        try:
            response = self.session.post('http://%s:%s/api/login' % (self.hostname, self.port),
                                         json={'foo': 'bar'},
                                         timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that the user is not authenticated
        # accepted responses include 400 and 403
        if response.status_code not in [requests.codes.bad_request, requests.codes.forbidden]:
            raise AssertionError("Server did not respond with 403 or 400 to missing authentication info")

        # Define the private URL to get
        url = 'http://%s:%s/%s' % (self.hostname, self.port, self.private_file)

        # Use the session cookie to get the private file
        try:
            response = self.session.get(url, timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that access is forbidden
        self.assertEqual(response.status_code, requests.codes.forbidden,
                         "Server responded with private file despite not being authenticated.")    
    
    def test_access_control_private_no_token(self):
        """ Test Name: test_access_control_private_no_token
        Number Connections: N/A
        Procedure: Checks if private files can be accessed without
                   authentication details. A failure here means that
                   private paths are being served without authentication.
        """
        # Define the private URL to get
        url = 'http://%s:%s/%s' % (self.hostname, self.port, self.private_file)

        # Use the session cookie to get the private file
        try:
            response = self.session.get(url, timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that access is forbidden
        self.assertEqual(response.status_code, requests.codes.forbidden,
                         "Server responded with a private file despite no token.")

    def test_access_control_private_malformed_token(self):
        """ Test Name: test_access_control_private_no_token
        Number Connections: N/A
        Procedure: Checks if private files can be accessed with malformed
                   authentication tokens. A failure here means that the
                   authentication token is not being checked when serving
                   private files.
        """
        # Login using the default credentials
        try:
            response = self.session.post('http://%s:%s/api/login' % (self.hostname, self.port),
                                         json={'username': self.username, 'password': self.password},
                                         timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that the user is authenticated
        self.assertEqual(response.status_code, requests.codes.ok, "Authentication failed.")

        # Get cookie name
        for cookie in self.session.cookies:
            try:
                encoded_data = cookie.value.split('.')[1]

                # Try to decode the payload
                decoded_payload = decode_base64(encoded_data)

                # Get decoded_payload as JSON
                data = json.loads(decoded_payload)

                break

            except (IndexError, ValueError):
                continue

        # Delete the current authentication token
        del self.session.cookies[cookie.name]

        # Set a false authentication token in the cookie
        self.session.cookies.set(cookie.name, 'false_token')

        # Define the private URL to get
        url = 'http://%s:%s/%s' % (self.hostname, self.port, self.private_file)

        # Use the session cookie to get the private file
        try:
            response = self.session.get(url, timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # Ensure that access is forbidden
        self.assertEqual(response.status_code, requests.codes.forbidden,
                         "Server responded with private file despite given an invalid auth token.")

    def test_access_control_private_path(self):
        """ Test Name: test_access_control_private_path
        Number Connections: N/A
        Procedure: Checks if private files can be accessed through redirection.
                   A failure here means that the private paths are not
                   adequately protected and paths such as /public/../private/secret
                   can be accessed.
        """
        # Define the private URL to get prefixed with a public path
        url = 'http://%s:%s/public/../%s' % (self.hostname, self.port, self.private_file)

        # Use the session cookie to get the private file
        try:
            # prevent path segment normalization
            req = requests.Request('GET', url)
            prepared_req = req.prepare()
            # set the URL manually in case newer requests/urllib3 normalizes URL
            # in prepare() function
            prepared_req.url = url
            response = self.session.send(prepared_req, timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        if (response.status_code == requests.codes.forbidden):
            raise AssertionError('Server responded with 403 FORBIDDEN instead of 404 NOT FOUND')

        # Ensure that response code is 404
        self.assertEqual(response.status_code, requests.codes.not_found,
                         "Server did not respond with 404 when it should have, possible IDOR?")

    def test_login_content_type(self):
        """ Test Name: test_login_content_type
        Number Connections: N/A
        Procedure: Checks to ensure the Content-Type header is being sent in
                   responses to GETs and POSTs to /api/login (both with AND
                   without Cookie headers). A failure here means either:
                    - 'Content-Type' is not a part of some or all of your /api/login responses, OR
                    - The value of your 'Content-Type' header is not what it should be.
        """
        # inner helper function that takes a response and checks for the correct
        # content-type header
        def check_content_type(response):
            # search for the content-type header and ensure we see "application/json"
            content_type = self.find_header(response, "Content-Type")
            content_expect = "application/json"
            if content_type == None:
                raise AssertionError("Server didn't respond with the Content-Type header when sent a request to /api/login")
            if content_type.lower() != content_expect:
                raise AssertionError("Server didn't respond with the correct Content-Type value when sent a request to /api/login. "
                                     "Expected: '%s', received: '%s'" % (content_expect, content_type))

        # first, we'll build the /api/login url
        login_url = "http://%s:%s/api/login" % (self.hostname, self.port)

        # TEST 1: send a simple GET /api/login with NO COOKIE
        try:
            response = self.session.get(login_url, timeout=2)
            check_content_type(response)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # TEST 2: try sending a POST /api/login with the correct credentials
        try:
            response = self.session.post(login_url,
                                         json={'username': self.username, 'password': self.password},
                                         timeout=2)
            check_content_type(response)
            # Ensure that the user is authenticated
            self.assertEqual(response.status_code, requests.codes.ok, "Authentication failed.")
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # TEST 3: send one more GET /api/login with the cookie we just received
        try:
            response = self.session.get(login_url, timeout=2)
            check_content_type(response)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")
        

class Fallback(Doc_Print_Test_Case):
    """
    Test cases for HTML 5 fallback, using good requests that expect a
    fallback to occur when a file isn't found or / is requested.
    """

    def __init__(self, testname, hostname, port):
        """
        Prepare the test case for creating connections.
        """
        super(Fallback, self).__init__(testname)

        self.hostname = hostname
        self.port = port
        self.files_nofallback = ['js/jquery.min.js', 'css/jquery-ui.min.css']

    def setUp(self):
        """  Test Name: None -- setUp function\n\
        Number Connections: N/A \n\
        Procedure: Opens the HTTP connection to the server.  An error here \
                   means the script was unable to create a connection to the \
                   server.
        """
        # Create a requests session
        self.session = requests.Session()

    def tearDown(self):
        """  Test Name: None -- tearDown function\n\
        Number Connections: N/A \n\
        Procedure: Closes the HTTP connection to the server.  An error here \
                   means the server crashed after servicing the request from \
                   the previous test.
        """
        # Close the HTTP connection
        self.session.close()

    def test_html5_fallback_valid_file(self):
        """ Test Name: test_access_control_private_path
        Number Connections: N/A
        Procedure: Checks if the server, with HTML5 fallback enabled, still sends
                   the correct contents of files that DO exist to the client.
                   A failure here means the server's HTML5 fallback is sending back
                   the contents of /index.html even though a request was made for
                   a valid file that exists and is accessible.
        """
        
        # ----------------------- Retrieve /index.html ----------------------- #
        # first, make a GET request for /index.html
        index_content = ""
        index_url = "http://%s:%s/index.html" % (self.hostname, self.port)
        try:
            req = requests.Request('GET', index_url)
            prepared_req = req.prepare()
            prepared_req.url = index_url
            response = self.session.send(prepared_req, timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")
        
        # check the response code - we expect 200 OK
        if (response.status_code != requests.codes.ok):
            raise AssertionError('Server responded with %d instead of 200 OK when requested with /%s' % 
                                 (response.status_code, 'index.html'))
        index_content = response.text

       # ---------------------------- Actual Test ---------------------------- #
        # do the following for each of the no-fallback-expected files
        for f in self.files_nofallback: 
            # build a url to the file
            url = "http://%s:%s/%s" % (self.hostname, self.port, f)

            # make a GET request for the file
            try:
                req = requests.Request('GET', url)
                prepared_req = req.prepare()
                prepared_req.url = url
                response = self.session.send(prepared_req, timeout=2)
            except requests.exceptions.RequestException:
                raise AssertionError("The server did not respond within 2s")
            
            # check the response code - we expect 200 OK
            if (response.status_code != requests.codes.ok):
                raise AssertionError('Server responded with %d instead of 200 OK when requested with /%s' %
                                     (response.status_code, f))

            # check the contents of the file - this SHOULDN'T be index.html
            if index_content in response.text:
                raise AssertionError('Server returned /index.html when requested with a different, valid file')
    
    def test_html5_fallback_invalid_file(self):
        """ Test Name: test_html5_fallback_invalid_file
        Number Connections: N/A
        Procedure: Checks if the server supports the HTML5 fallback as per the
                   policy for Svelte App.
                   This policy says that / should return /index.html
                   /x should return /x.html if it exists, and all other requests
                   should return the special file /200.html

                   A failure here means that HTML5 fallback support does not work
                   (meaning, a request for /some_file_that_doesnt_exist does not get
                   rerouted to /200.html)
        """
       
        # ----------------------- Retrieve /index.html ----------------------- #
        # first, make a GET request for /index.html
        index_content = {}
        names = ['index.html', 'public.html', '200.html']
        for fname in names:
            index_url = "http://%s:%s/%s" % (self.hostname, self.port, fname)
            try:
                req = requests.Request('GET', index_url)
                prepared_req = req.prepare()
                prepared_req.url = index_url
                response = self.session.send(prepared_req, timeout=2)
            except requests.exceptions.RequestException:
                raise AssertionError("The server did not respond within 2s")

            # check the response code - we expect 200 OK
            if (response.status_code != requests.codes.ok):
                raise AssertionError('Server responded with %d instead of 200 OK when requesting /%s' %
                                     (response.status_code, fname))
            index_content[fname] = response.text
         
        # --------------------------- Actual Test ---------------------------- #
        # do the following for each of the fallback-expected files
        for path, expected in [('', 'index.html'),
                               ('this_file_better_not_exist_or_the_test_will_fail', '200.html'),
                               ('public', 'public.html')]:
            # build a url to the file
            url = "http://%s:%s/%s" % (self.hostname, self.port, path)

            # make a GET request for the file
            try:
                req = requests.Request('GET', url)
                prepared_req = req.prepare()
                prepared_req.url = url
                response = self.session.send(prepared_req, timeout=2)
            except requests.exceptions.RequestException:
                raise AssertionError("The server did not respond within 2s")
            
            # check the response code - we expect 200 OK
            if (response.status_code != requests.codes.ok):
                raise AssertionError('Server responded with %d instead of 200 OK when requesting /%s' %
                                     (response.status_code, path))

            # check the contents of the file - this SHOULD be index.html
            if index_content[expected] != response.text:
                raise AssertionError(f'Server failed to return the content of /{expected} when requesting \'%s\'' % path)

class Authentication(Doc_Print_Test_Case):
    """
    Test cases for authentication expiry, using good requests that are properly
    formed. The tests are aptly named for describing their effects.
    """

    def __init__(self, testname, hostname, port):
        """
        Prepare the test case for creating connections.
        """
        super(Authentication, self).__init__(testname)

        self.hostname = hostname
        self.port = port
        self.public_file = 'index.html'
        self.private_file = 'private/secure.html'
        self.username = 'user0'
        self.password = 'thepassword'
        self.incorrect_password = 'wrongword'
        self.sleep_time = 8 if run_slow else 4
        self.current_year = datetime.now().year

    def setUp(self):
        """  Test Name: None -- setUp function\n\
        Number Connections: N/A \n\
        Procedure: Opens the HTTP connection to the server.  An error here \
                   means the script was unable to create a connection to the \
                   server.
        """
        # Create a requests session
        self.sessions = []

    def tearDown(self):
        """  Test Name: None -- tearDown function\n\
        Number Connections: N/A \n\
        Procedure: Closes the HTTP connection to the server.  An error here \
                   means the server crashed after servicing the request from \
                   the previous test.
        """
        del self.sessions

    def test_expires_authentication_token(self):
        """ Test Name: test_expires_authentication_token
        Number Connections: 30
        Procedure: Checks if the authentication token expires in the timeframe
                   given. An error here means that expiry authentication token
                   duration is not correctly configured.
        """
        # Create multiple sessions
        for i in range(30):
            self.sessions.append(requests.Session())

        # Randomize failure events
        should_fail = lambda: bool(random.getrandbits(1))

        def test_expiry_authentication(i):
            # Login using the default credentials
            try:
                response = self.sessions[i].post('http://%s:%s/api/login' % (self.hostname, self.port),
                                             json={'username': self.username, 'password': self.password},
                                             timeout=2)
            except requests.exceptions.RequestException:
                raise AssertionError("The server did not respond within 2s POST")

            # Ensure that the user is authenticated
            self.assertEqual(response.status_code, requests.codes.ok, "Authentication failed.")

            # Define the private URL to get
            url = 'http://%s:%s/%s' % (self.hostname, self.port, self.private_file)

            if should_fail():
                # Use the session cookie to get the private file
                try:
                    response = self.sessions[i].get(url, timeout=2)
                except requests.exceptions.RequestException:
                    raise AssertionError("The server did not respond within 2s GET %s" % self.private_file)

                # Ensure that access is granted
                self.assertEqual(response.status_code, requests.codes.ok,
                                 "Server did not respond with the private file despite valid authentication.")
            else:
                # Sleep for a short duration till token expires
                time.sleep(self.sleep_time)

                # Use the session cookie to get the private file
                try:
                    response = self.sessions[i].get(url, timeout=2)
                except requests.exceptions.RequestException:
                    raise AssertionError("The server did not respond within 2s")

                # Ensure that response is not OK
                assert response.ok == False, "The response to the query was 200 OK when it should have been 403 FORBIDDEN"

                # Ensure that access is forbidden
                self.assertEqual(response.status_code, requests.codes.forbidden,
                                 "Server responded with %s (expected value = %s) when the token expires."
                                    % (response.status_code, requests.codes.forbidden))

            self.sessions[i].close()

        pool = ThreadPool(30)
        pool.map(test_expiry_authentication, range(30))
        pool.terminate()
 
    def test_jwt_claims_json(self):
        """ Test Name: test_jwt_claims_json
        Number Connections: N/A
        Procedure: Checks if the JWT JSON has the right claims set.
                   An error here means that some of the claims required are
                   not being set correctly.
        """
        # Create multiple sessions
        for i in range(30):
            self.sessions.append(requests.Session())

        for i in range(30):
            # ----------------------- Login JSON Check ----------------------- #
            # Login using the default credentials
            try:
                response = self.sessions[i].post('http://%s:%s/api/login' % (self.hostname, self.port),
                                             json={'username': self.username, 'password': self.password},
                                             timeout=2)
            except requests.exceptions.RequestException:
                raise AssertionError("The server did not respond within 2s")

            # Ensure that the user is authenticated
            self.assertEqual(response.status_code, requests.codes.ok, "Authentication failed.")

            try:
                # Convert the response to JSON
                data = response.json()

                # ensure all expected fields are present
                assert 'iat' in data, "Could not find the claim 'iat' in the JSON object."
                assert 'exp' in data, "Could not find the claim 'exp' in the JSON object."
                assert 'sub' in data, "Could not find the claim 'sub' in the JSON object."

                # verify that the two timestamps are valid dates
                assert datetime.fromtimestamp(data['iat']).year == self.current_year, "'iat' returned is not a valid date"
                assert datetime.fromtimestamp(data['exp']).year == self.current_year, "'exp' returned is not a valid date"

                # Verify that the subject claim to is set to the right username
                assert data['sub'] == self.username, "The subject claim 'sub' should be set to %s" % self.username

            except ValueError:
                raise AssertionError('The login API did not return a valid JSON object')

            # --------------------- Login GET JSON Check --------------------- #
            # send a GET request to retrieve the same claims as above
            try:
                response = self.sessions[i].get('http://%s:%s/api/login' % (self.hostname, self.port),
                                                timeout=2)
            except requests.exceptions.RequestException:
                raise AssertionError("The server did not respond within 2s")

            try:
                # Convert the response to JSON
                data = response.json()

                # ensure all expected fields are present
                assert 'iat' in data, "Could not find the claim 'iat' in the JSON object."
                assert 'exp' in data, "Could not find the claim 'exp' in the JSON object."
                assert 'sub' in data, "Could not find the claim 'sub' in the JSON object."
                
                # Verify that the two timestamps are valid dates from self.current_year
                assert datetime.fromtimestamp(data['iat']).year == self.current_year, "'iat' returned is not a valid date"
                assert datetime.fromtimestamp(data['exp']).year == self.current_year, "'exp' returned is not a valid date"

                # Verify that the subject claim to is set to the right username
                assert data['sub'] == self.username, "The subject claim 'sub' should be set to %s" % self.username

            except ValueError:
                raise AssertionError('The login GET API did not return a valid JSON object')

            
            # Sleep for a short duration before testing again
            time.sleep(random.random() / 10.0)

            # Close the session
            self.sessions[i].close()

    def test_jwt_claims_cookie(self):
        """ Test Name: test_jwt_claims_cookie
        Number Connections: N/A
        Procedure: Checks if the JWT cookie has the right claims set.
                   An error here means that some of the claims required are
                   not being set correctly.
        """
        # Create multiple sessions
        for i in range(30):
            self.sessions.append(requests.Session())

        for i in range(30):
            # Login using the default credentials
            try:
                response = self.sessions[i].post('http://%s:%s/api/login' % (self.hostname, self.port),
                                             json={'username': self.username, 'password': self.password},
                                             timeout=2)

            except requests.exceptions.RequestException:
                raise AssertionError("The server did not respond within 2s")

            # Ensure that the user is authenticated
            self.assertEqual(response.status_code, requests.codes.ok, "Authentication failed.")

            # Get the cookie value from the response
            found_cookie = False

            for cookie in self.sessions[i].cookies:
                try:
                    self.assertEquals(cookie.path, "/", "Cookie path should be /")
                    self.assertTrue("HttpOnly" in cookie._rest, "Cookie is not http only.")
                    maxage = cookie.expires - time.mktime(datetime.now().timetuple())
                    if abs(maxage - int(auth_token_expiry)) > 1:
                        raise AssertionError(f"Cookie's Max-Age is {maxage} should be {auth_token_expiry}")

                    encoded_data = cookie.value.split('.')[1]

                    # Try to decode the payload
                    decoded_payload = decode_base64(encoded_data)

                    # Get decoded_payload as JSON
                    data = json.loads(decoded_payload)

                    found_cookie = True

                except (IndexError, ValueError):
                    continue

            # If cookie is None, it means no cookie has been set
            if not found_cookie:
                raise AssertionError('No valid cookie found.')

            # Verify that the JWT contains 'iat'
            assert 'iat' in data, "Could not find the claim 'iat' in the JSON object."

            # Verify that the JWT contains 'iat'
            assert 'exp' in data, "Could not find the claim 'exp' in the JSON object."

            # Verify that the JWT contains 'sub'
            assert 'sub' in data, "Could not find the claim 'sub' in the JSON object."

            # Verify that the 'iat' claim to is a valid date from self.current_year
            assert datetime.fromtimestamp(data['iat']).year == self.current_year, "'iat' returned is not a valid date"

            # Verify that the 'exp' claim to is a valid date from self.current_year
            assert datetime.fromtimestamp(data['exp']).year == self.current_year, "'exp' returned is not a valid date"

            # Verify that the subject claim to is set to the right username
            assert data['sub'] == self.username, "The subject claim 'sub' should be set to %s" % self.username

            # Sleep for a short duration before testing again
            time.sleep(random.random() / 10.0)

            # Close the session
            self.sessions[i].close()

class VideoStreaming(Doc_Print_Test_Case):
    """
    Test cases for the /api/video endpoint and using Range requests to stream
    videos and other files.
    """

    def __init__(self, testname, hostname, port):
        """
        Prepare the test case for creating connections.
        """
        super(VideoStreaming, self).__init__(testname)

        self.hostname = hostname
        self.port = port
        self.nonvideos = ['index.html', 'js/jquery.min.js', 'css/jquery-ui.min.css']

    def setUp(self):
        """  Test Name: None -- setUp function\n\
        Number Connections: N/A \n\
        Procedure: Opens the HTTP connection to the server.  An error here \
                   means the script was unable to create a connection to the \
                   server.
        """
        # open the base directory and search through it for video files. We'll
        # use these to compare against /api/video responses
        self.vids = []
        for root, dirs, files in os.walk(base_dir):
            for fname in files:
                # only consider .mp4 files
                if fname.endswith(".mp4"):
                    self.vids.append(os.path.join(root, fname))

        # Create a requests session
        self.session = requests.Session()

    def tearDown(self):
        """  Test Name: None -- tearDown function\n\
        Number Connections: N/A \n\
        Procedure: Closes the HTTP connection to the server.  An error here \
                   means the server crashed after servicing the request from \
                   the previous test.
        """
        # Close the HTTP connection
        self.session.close()
    
    # Does a lower-case search for headers within a response's headers. If
    # found, the first ocurrence is returned (the header's value is returned).
    def find_header(self, response, name):
        for header in response.headers:
            if header.lower() == name.lower():
                return response.headers[header]
        return None

    # Takes in a file path (fpath) and the response object returned from the web
    # server, and a start and end byte index, and compares the bytes requested.
    # Returns True if they match, and False otherwise.
    def compare_file_bytes(self, fpath, response, start, length):
        # open the file for reading and seek to the starting point
        fp = open(fpath, "rb")
        fp.seek(start, 0)

        # read small chunks at a time
        chksz = 128
        bread = 0
        for chunk in response.iter_content(chunk_size=128):
            chunk_len = len(chunk)
            ebytes = fp.read(chunk_len)     # "expected bytes"

            # if we didn't read enough bytes from the file, something must be
            # up with the response's data
            if len(ebytes) < chunk_len:
                return False
            
            # add to the counter
            bread += chunk_len
            
            # if the two byte arrays aren't equal, return False
            if ebytes != chunk:
                return False
        
        # if we didn't read enough bytes from the response, something is wrong
        if bread < length:
            return False

        # close the file
        fp.close()
        return True

    def test_api_video(self):
        """ Test Name: test_api_video
        Number Connections: N/A
        Procedure: Tests the /api/video endpoint and ensures the server responds
        with the correct information. A failure here means either /api/video is
        unsupported entirely or there's an issue with the JSON data the server
        send in a response to GET /api/video.
        """

        # build the URL for /api/video and make the GET request
        url = "http://%s:%s/api/video" % (self.hostname, self.port)
        response = None
        # make a GET request for the file
        try:
            req = requests.Request('GET', url)
            prepared_req = req.prepare()
            prepared_req.url = url
            response = self.session.send(prepared_req, timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")

        # make sure the correct status code was received
        if response.status_code != requests.codes.ok:
            raise AssertionError("Server responded with %d instead of 200 OK when requested with /api/video" %
                                 response.status_code)

        # make sure the correct Content-Type is specified
        content_type = self.find_header(response, "Content-Type")
        content_expect = "application/json"
        if content_type == None:
            raise AssertionError("Server didn't respond with the Content-Type header when requested with /api/video")
        if content_type.lower() != content_expect:
            raise AssertionError("Server didn't respond with the correct Content-Type value when requested with /api/video. "
                                 "Expected: %s, received: %s" % (content_expect, content_type))

        # attempt to decode the JSON data from /api/video
        jdata = None
        try:
            jdata = response.json()
        except Exception as e:
            raise AssertionError("Failed to decode the JSON data your server sent as a response to /api/video. "
                                 "Error: %s" % str(e))
        
        # now we'll examine the JSON data and make sure it's formatted right
        # [{"name": "v1.mp4", "size": 1512799}, {"name": "v2.mp4", "size": 9126406}]
        if type(jdata) != list:
            raise AssertionError("JSON data returned from /api/video must be in a list format (ex: [{\"a\": 1}, {\"b\": 2}])")
        for entry in jdata:
            # each entry should have two fields: "name" and "size"
            if "name" not in entry or "size" not in entry:
                raise AssertionError("Each JSON entry returned from /api/video must have a \"name\" and a \"size\"")
        
        # next, iterate over the videos *we* observed in the test root
        # directory and ensure each one is present in the JSON data
        base_dir_full = os.path.realpath(base_dir)
        for expected in self.vids:
            # stat the video file to retrieve its size in bytes
            expected_size = os.path.getsize(expected)
            # use the base directory to derive the correct string that should
            # be placed in the JSON data
            expected_str = expected.replace(base_dir_full, "")
            if expected_str.startswith("/"):
                expected_str = expected_str[1:]
            
            # search for the entry within the array, and thrown an error of we
            # couldn't find it
            entry = None
            for e in jdata:
                entry = e if e["name"] == expected_str else entry
            if entry == None:
                raise AssertionError("Failed to find \"%s\" in server's response to GET /api/video. Received:\n%s" %
                                     (expected_str, json.dumps(jdata)))
            
            # ensure the reported size is what we expect
            if entry["size"] != expected_size:
                raise AssertionError("Incorrect size reported for \"%s\" in response to GET /api/video. Expected %d, received %d" %
                                     (expected_str, expected_size, entry["size"]))

    def test_accept_ranges_header(self):
        """ Test Name: test_accept_ranges_header
        Number Connections: N/A
        Procedure: Makes a variety of requests to the web server and searches
        for at least one occurrence of the Accept-Ranges header being sent back
        in the server's response headers. A failure here means the server doesn't
        appear to be sending the Accept-Ranges header in its responses.
        """
        # build a collection of URLs to try
        url_prefix = "http://%s:%s" % (self.hostname, self.port)
        resources = ["/index.html", "/public/index.html", "/v1.mp4"]

        # do the following for each URL
        occurrences = 0
        for resource in resources:
            url = url_prefix + resource
            response = None
            # make a GET request for the particular resource
            try:
                req = requests.Request('GET', url)
                prepared_req = req.prepare()
                prepared_req.url = url
                response = self.session.send(prepared_req, timeout=2)
            except requests.exceptions.RequestException:
                raise AssertionError("The server did not respond within 2s")
            
            # make sure the correct status code was received
            if response.status_code != requests.codes.ok:
                raise AssertionError("Server responded with %d instead of 200 OK when requested with %s" %
                                     (response.status_code, resource))
            
            # search the header dictionary (lowercase comparison) for Accept-Ranges
            accept_ranges_expect = "bytes"
            accept_ranges = self.find_header(response, "Accept-Ranges")
            if accept_ranges != None:
                occurrences += 1
                # make sure the correct value is given ("bytes")
                if "bytes" not in accept_ranges:
                    raise AssertionError("Server responded with an unexpected Accept-Ranges values. "
                                         "Expected: %s, received: %s" % (accept_ranges_expect, response.headers["Accept-Ranges"]))

        # if no occurrences were found, throw an error
        if occurrences == 0:
            raise AssertionError("Failed to find the Accept-Ranges header in the server's responses. "
                                 "Your server must send 'Accept-Ranges: bytes' in its HTTP responses when serving static files.")

    def test_video_get(self):
        """ Test Name: test_video_get
        Number Connections: N/A
        Procedure: Makes a simple GET request for a video and checks headers,
        content length, bytes, etc. A failure here means GET requests for
        videos (WITHOUT Range requests) aren't performing properly.
        """
        # build a url to one of the videos in the test directory, then make a
        # simple GET request
        vid = os.path.basename(self.vids[0])
        url = "http://%s:%s/%s" % (self.hostname, self.port, vid)
        response = None
        try:
            req = requests.Request('GET', url)
            prepared_req = req.prepare()
            prepared_req.url = url
            response = self.session.send(prepared_req, timeout=2)
        except requests.exceptions.RequestException:
            raise AssertionError("The server did not respond within 2s")
        
        # make sure the correct status code was received
        if response.status_code != requests.codes.ok:
            raise AssertionError("Server responded with %d instead of 200 OK when requested with a valid video" %
                                    response.status_code)

        # check for the content-type header
        content_type = self.find_header(response, "Content-Type")
        content_expect = "video/mp4"
        if content_type == None:
            raise AssertionError("Server didn't respond with the Content-Type header when requested with a valid video")
        if content_type.lower() != content_expect:
            raise AssertionError("Server didn't respond with the correct Content-Type value when requested with a valid video. "
                                 "Expected: %s, received: %s" % (content_expect, content_type))

        # check for the content-length header
        content_length = self.find_header(response, "Content-Length")
        content_length_expect = os.path.getsize(self.vids[0])
        if content_length == None:
            raise AssertionError("Server didn't respond with the Content-Length header when requested with a valid video")
        if content_length != str(content_length_expect):
            raise AssertionError("Server didn't respond with the correct Content-Length value when requested with a valid video. "
                                 "Expected: %s, received: %s" % (content_length_expect, content_length))


        # now, we'll compare the actual video file with what was sent
        if not self.compare_file_bytes(self.vids[0], response, 0, content_length_expect):
            raise AssertionError("Server didn't send the correct bytes. Should have been the entire video file.")

    def test_video_range_request(self):
        """ Test Name: test_video_range_request
        Number Connections: N/A
        Procedure: Makes a GET request for a video and sends various Range
        header values to test the server's ability to serve range requests.
        A failure here means some (or all) cases of the server's Range request
        handling isn't working properly.
        """
        # build a URL to the video we'll be GET'ing
        vid = os.path.basename(self.vids[0])
        vidsize = os.path.getsize(self.vids[0])
        url = "http://%s:%s/%s" % (self.hostname, self.port, vid)
        # set up a few range request values to test with the video
        ranges = [[0, 1], [0, 100], [300, 500], [1000, -1]]#, [-1, 1000]]

        # iterate across each range array to test each one
        for rg in ranges:
            # build the Range header string
            rg_left = "" if rg[0] == -1 else "%d" % rg[0]
            rg_right = "" if rg[1] == -1 else "%d" % rg[1]
            rgheader = "bytes=%s-%s" % (rg_left, rg_right)

            # send a request with the Range header
            response = None
            try:
                req = requests.Request('GET', url)
                req.headers = {"Range": rgheader}
                prepared_req = req.prepare()
                prepared_req.url = url
                response = self.session.send(prepared_req, timeout=2)
            except requests.exceptions.RequestException:
                raise AssertionError("The server did not respond within 2s\nRange request sent: '%s'" % rgheader)
            
            # make sure the correct status code was received
            if response.status_code != requests.codes.partial_content:
                raise AssertionError("Server responded with %d instead of 206 PARTIAL CONTENT when range-requested with a valid video"
                                     "\nRange request sent: '%s'" % (response.status_code, rgheader))
            
            # check for the content-type header
            content_type = self.find_header(response, "Content-Type")
            content_expect = "video/mp4"
            if content_type == None:
                raise AssertionError("Server didn't respond with the Content-Type header when requested with a valid video"
                                     "\nRange request sent: '%s'" % rgheader)
            if content_type.lower() != content_expect:
                raise AssertionError("Server didn't respond with the correct Content-Type value when requested with a valid video. "
                                     "Expected: %s, received: %s\nRange request sent: '%s'" % (content_expect, content_type, rgheader))
    
            # check for the content-length header and make sure it's the correct
            # value based on the current range value we're trying
            content_length = self.find_header(response, "Content-Length")
            content_length_expect = rg[1] - rg[0] + 1
            if rg[0] == -1:
                content_length_expect = rg[1]
            elif rg[1] == -1:
                content_length_expect = vidsize - rg[0]
            if content_length == None:
                raise AssertionError("Server didn't respond with the Content-Length header when requested with a valid video"
                                     "\nRange request sent: '%s'" % rgheader)
            if content_length != str(content_length_expect):
                raise AssertionError("Server didn't respond with the correct Content-Length value when requested with a valid video. "
                                     "Expected: %s, received: %s\nRange request sent: '%s'" % (content_length_expect, content_length, rgheader))

            # check for the Content-Range header and make sure it's the correct
            # value
            content_range = self.find_header(response, "Content-Range")
            byte_start = rg[0] if rg[0] != -1 else vidsize - rg[1]
            content_range_expect = "bytes %d-%d/%d" % (byte_start, byte_start + content_length_expect - 1, vidsize)
            if content_range == None:
                raise AssertionError("Server didn't respond with the Content-Range header when requested with a valid video"
                                     "\nRange request sent: '%s'" % rgheader)
            if content_range.lower() != content_range_expect:
                raise AssertionError("Server didn't respond with the correct Content-Range value when requested with a valid video. "
                                     "Expected: '%s', received: '%s'\nRange request sent: '%s'" % (content_range_expect, content_range, rgheader))

            # finally, we'll compare the actual bytes that were received. They
            # must match the exact bytes found in the original file
            if not self.compare_file_bytes(self.vids[0], response, byte_start, content_length_expect):
                raise AssertionError("Server didn't send the correct bytes. Should have been bytes %d-%d"
                                     "\nRange request sent: '%s'" % (byte_start, byte_start + content_length_expect - 1, rgheader))


###############################################################################
# Globally define the Server object so it can be checked by all test cases
###############################################################################
server = None
output_file_name = None

from signal import SIGTERM
def killserver(server):
    pid = server.pid
    try:
        pgid = os.getpgid(pid)
        os.killpg(pgid, SIGTERM)
    except OSError:
        # process might already be dead, os.getpgid throw in this case
        pass

###############################################################################
# Define an atexit shutdown method that kills the server as needed
###############################################################################
def make_clean_up_testing(server):
    def clean_up_testing():
        try:
            killserver(server)   # SIGTERM
        except:
            pass

    return clean_up_testing

# --------------------------- Test Categories ---------------------------- #
# before anything else, we'll set up a specification for testing categories
# and which unit test classes to into each. We do this *here* and not below
# so the 'list_tests' code below can accurately print things out. Not the
# best code organization, but we work with what we've got.
# First we'll set up one function for every test category, used to build a
# unit test suite object.

# Suite builder function for minimum requirements.
def make_suite_minreq(hostname, port):
    min_req_suite = unittest.TestSuite()
    # Add all of the tests from the class Single_Conn_Good_Case
    for test_function in dir(Single_Conn_Good_Case):
        if test_function.startswith("test_"):
            min_req_suite.addTest(Single_Conn_Good_Case(test_function, hostname, port))
    # In particular, add the two-connection test from Multi_Conn_Sequential_Case,
    # and the 1.0 protocol check (early return check) from Single_Conn_Protocol_Case
    min_req_suite.addTest(Multi_Conn_Sequential_Case("test_two_connections", hostname, port))
    min_req_suite.addTest(Single_Conn_Protocol_Case("test_http_1_0_compliance", hostname, port))
    return min_req_suite

# Suite builder function for authentication.
def make_suite_auth(hostname, port):
    auth_tests_suite = unittest.TestSuite()
    # Add all of the tests from the class Access_Control
    for test_function in dir(Access_Control):
        if test_function.startswith("test_"):
            auth_tests_suite.addTest(Access_Control(test_function, hostname, port))
    # Add all of the tests from the class Authentication
    for test_function in dir(Authentication):
        if test_function.startswith("test_"):
            auth_tests_suite.addTest(Authentication(test_function, hostname, port))
    return auth_tests_suite

# Suite builder function for HTML5 fallback.
def make_suite_fallback(hostname, port):
    # Test Suite to test HTML5 fallback functionality. Add all tests from
    # the Fallback class.
    html5_fallback_suite = unittest.TestSuite()
    for test_function in dir(Fallback):
        if test_function.startswith("test_"):
            html5_fallback_suite.addTest(Fallback(test_function, hostname, port))
    return html5_fallback_suite

# Suite builder function for video streaming.
def make_suite_video(hostname, port):
    # Test Suite for video streaming functionality. Add all tests from the
    # VideoStreaming class.
    video_suite = unittest.TestSuite()
    for test_function in dir(VideoStreaming):
        if test_function.startswith("test_"):
            video_suite.addTest(VideoStreaming(test_function, hostname, port))
    return video_suite

# Suite builder function for IPv6 support.
def make_suite_ipv6(hostname, port):
    ipv6_test_suite = unittest.TestSuite()
    # Add all of the tests from the class Single_Conn_Good_Case
    for test_function in dir(Single_Conn_Good_Case):
        if test_function.startswith("test_"):
            ipv6_test_suite.addTest(Single_Conn_Good_Case(test_function, hostname, port))
    return ipv6_test_suite

# Suite builder function for extra tests.
def make_suite_extra(hostname, port):
    # Test Suite for extra points, mostly testing error cases
    extra_tests_suite = unittest.TestSuite()
    # Add all of the tests from the class Multi_Conn_Sequential_Case
    for test_function in dir(Multi_Conn_Sequential_Case):
        if test_function.startswith("test_"):
            extra_tests_suite.addTest(Multi_Conn_Sequential_Case(test_function, hostname, port))
    # Add all of the tests from the class Single_Conn_Bad_Case
    for test_function in dir(Single_Conn_Bad_Case):
        if test_function.startswith("test_"):
            extra_tests_suite.addTest(Single_Conn_Bad_Case(test_function, hostname, port))
    # In particular, add the 1.1 protocol persistent connection check from Single_Conn_Protocol_Case
    extra_tests_suite.addTest(Single_Conn_Protocol_Case("test_http_1_1_compliance", hostname, port))
    return extra_tests_suite

# Suite builder function for malicious tests.
def make_suite_malicious(hostname, port):
    # Malicious Test Suite
    malicious_tests_suite = unittest.TestSuite()
    # Add all of the tests from the class Single_Conn_Malicious_Case
    for test_function in dir(Single_Conn_Malicious_Case):
        if test_function.startswith("test_"):
            malicious_tests_suite.addTest(Single_Conn_Malicious_Case(test_function, hostname, port))
    return malicious_tests_suite

# main JSON for test categories
test_categories = {
    "minreq": {
        "name": "Minimum Requirements",
        "points": 25,
        "maker": make_suite_minreq
    },
    "auth": {
        "name": "Authentication Functionality",
        "points": 20,
        "maker": make_suite_auth
    },
    "fallback": {
        "name": "HTML5 Fallback Functionality",
        "points": 5,
        "maker": make_suite_fallback
    },
    "video": {
        "name": "Video Streaming Functionality",
        "points": 10,
        "maker": make_suite_video
    },
    "ipv6": {
        "name": "IPv6 Support",
        "points": 5,
        "maker": make_suite_ipv6
    },
    "extra": {
        "name": "Extra Corner Cases",
        "points": 15,
        "maker": make_suite_extra
    },
    "malicious": {
        "name": "Robustness/Malicious",
        "points": 15,
        "maker": make_suite_malicious
    }
}
# ------------------------------------------------------------------------ #


# Grade distribution constants
#grade_points_available = 95
# 6 tests
minreq_total = test_categories["minreq"]["points"]
# 27 tests
extra_total = test_categories["extra"]["points"]
# 5 tests
malicious_total = test_categories["malicious"]["points"]
# 4 tests
ipv6_total = test_categories["ipv6"]["points"]
# ? tests
auth_total = test_categories["auth"]["points"]
# ? tests (html5 fallback)
fallback_total = test_categories["fallback"]["points"]
# ? tests (video features)
video_total = test_categories["video"]["points"]


def print_points(minreq, extra, malicious, ipv6, auth, fallback, video):
    """All arguments are fractions (out of 1)"""
    # compute individual scores
    minreq_final = int(minreq * minreq_total)
    auth_final = int(auth * auth_total)
    fallback_final = int(fallback * fallback_total)
    video_final = int(video * video_total)
    ipv6_final = int(ipv6 * ipv6_total)
    extra_final = int(extra * extra_total)
    malicious_final = int(malicious * malicious_total)
    # compute total scores
    total = minreq_total + auth_total + fallback_total + video_total + ipv6_total + \
            extra_total + malicious_total
    total_final = minreq_final + auth_final + fallback_final + video_final + \
                  ipv6_final + extra_final + malicious_final
    
    # print all scores, including the total
    print("%-30s\t%2d/%2d" % (test_categories["minreq"]["name"], minreq_final, minreq_total))
    print("%-30s\t%2d/%2d" % (test_categories["auth"]["name"], auth_final, auth_total))
    print("%-30s\t%2d/%2d" % (test_categories["fallback"]["name"], fallback_final, fallback_total))
    print("%-30s\t%2d/%2d" % (test_categories["video"]["name"], video_final, video_total))
    print("%-30s\t%2d/%2d" % (test_categories["ipv6"]["name"], ipv6_final, ipv6_total))
    print("%-30s\t%2d/%2d" % (test_categories["extra"]["name"], extra_final, extra_total))
    print("%-30s\t%2d/%2d" % (test_categories["malicious"]["name"], malicious_final, malicious_total))
    print("-----")
    print("%-30s\t%d/%d" % ("TOTAL", total_final, total))


###############################################################################
# Main
###############################################################################
# Not sure if this is necessary
if __name__ == '__main__':

    try:
        opts, args = getopt.getopt(sys.argv[1:], "ndhs:t:vo:l6:w", \
                                   ["help"])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(str(err))  # will print something like "option -a not recognized"
        usage()
        sys.exit(2)

    server_path = None
    run_slow = False
    verbose = False
    individual_test = None
    runIPv6 = True
    list_tests = False
    ipv6_host = "localhost6"

    ipv6_score = 0
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-s"):
            server_path = a
        elif o in ("-t"):
            individual_test = a
        elif o in ("-l"):
            list_tests = True
        elif o in ("-w"):
            run_slow = True
        elif o in ("-v"):
            verbose = True
        elif o in ("-o"):
            output_file_name = a
        elif o in ("-6"):
            ipv6_host = a
        else:
            assert False, "unhandled option"

    alltests = [Single_Conn_Good_Case, Multi_Conn_Sequential_Case, Single_Conn_Bad_Case,
                Single_Conn_Malicious_Case, Single_Conn_Protocol_Case, Access_Control,
                Authentication, Fallback, VideoStreaming]


    def findtest(tname):
        for clazz in alltests:
            if tname in dir(clazz):
                return clazz
        return None
     
    # if the student requested to list all tests, do so here and exit
    if list_tests:
        for key in test_categories:
            category = test_categories[key]
            # build the test suite
            suite = category["maker"]("NO_HOSTNAME_NEEDED", "NO_PORT_NEEDED")
            print("Category: %s" % category["name"])
            # print all tests within
            for test in suite:
                # get the test ID and split it up by "."
                tid = test.id()
                tid_pieces = tid.split(".")
                print("\t%s" % tid_pieces[2])
        # exit - we're done
        sys.exit(0)

    if server_path is None:
        usage()
        sys.exit()

    # Check access to the server path
    if not os.access(server_path, os.R_OK):
        print("File ", server_path, " is not readable")
        sys.exit(1)

    # Setting the default timeout to allow connections to time out
    socket.setdefaulttimeout(4)

    # Determine the hostname for running the server locally
    hostname = socket.gethostname()

    # Determine the port number to use, based off of the current PID.
    port = (os.getpid() % 10000) + 20000

    # Set the base directory for the server, relative to
    # where this script is located
    base_dir = f'{script_dir}/test_root_data'

    # Authentication token expiry
    auth_token_expiry = '2'
    
    def start_server(preargs = [], postargs = []):
        args = preargs + [server_path, "-p", str(port), "-R", base_dir] + postargs
        output_file = None

        # Open the output file if possible
        if output_file_name is not None:
            output_file = open(output_file_name, "a")

        def make_new_pgrp():
            os.setpgid(0, 0)

        if output_file is not None:
            # Open the server on this machine
            server = subprocess.Popen(args, preexec_fn = make_new_pgrp,
                                      stdout=output_file, stderr=subprocess.STDOUT)
        elif verbose == True:
            # open the server with stdout unspecified (by default it will go to
            # the terminal).
            server = subprocess.Popen(args, preexec_fn = make_new_pgrp)
        else:
            # if the above fail, put stdout and stderr into /dev/null
            server = subprocess.Popen(args, preexec_fn = make_new_pgrp,
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL)

        # Register the atexit function to shutdown the server on Python exit
        atexit.register(make_clean_up_testing(server))

        return server

    server = start_server()

    # Ensure that the server is running and accepting connections.
    counter = 0
    while True:
        try:
            # by using the IP address returned here, we force the use of IPv4
            localhostname = socket.gethostbyname(socket.gethostname())
            http_conn = HTTPConnection(localhostname, port)
            http_conn.connect()
            http_conn.close()
            break
        except:
            if counter >= 10:
                print("""
The server is not responding to IPv4 connection requests, and may not be
functioning properly.  Ensure that you sent the proper location for your
server, and that your server starts running in a reasonable amount of time
(this waited 5 seconds for your server to start running).

In the case that your server works fine and there's an error in our
script, please use the 'ps' command to see if the server is still running,
and let us know if there is an issue with our script creating a runaway
process.
                """)
                sys.exit(1)

            counter += 1
            time.sleep(.5)

    print("Your server has started successfully.  Now to begin testing.")
    # If an individual test was requested, find that test and only add it.  If no
    # tests are found of that name, error and exit.
    if individual_test is not None:
        single_test_suite = unittest.TestSuite()
        testclass = findtest(individual_test)

        # make sure the class was found
        if testclass == None:
            print("Couldn't find a test with the name '%s'" % individual_test)
            sys.exit(1)

        if testclass == Authentication:
            killserver(server)
            server.wait()
            server = start_server(postargs=['-e', auth_token_expiry])
            time.sleep(3 if run_slow else 1)
        if testclass == Fallback:
            killserver(server)
            server.wait()
            server = start_server(postargs=['-a'])
            time.sleep(3 if run_slow else 1)

        single_test_class = testclass(individual_test, hostname, port)
        if testclass:
            single_test_suite.addTest(single_test_class)
        else:
            print("The test \"" + individual_test + "\" was not found in the test classes. Use -l.")
            sys.exit(1)

        # print information about the test to the user
        print("Running a single test: %s. Brief description:\n%s" %
              (single_test_class.id().split(".")[2], single_test_class.shortDescription()))

        # Run the single test test suite and store the results
        test_results = unittest.TextTestRunner().run(single_test_suite)

        if test_results.wasSuccessful():
            print("Test: " + individual_test + " passed!")
        else:
            print("Test: " + individual_test + " failed.")

    else:
        
        # build all test suites
        min_req_suite = make_suite_minreq(hostname, port)
        auth_tests_suite = make_suite_auth(hostname, port)
        html5_fallback_suite = make_suite_fallback(hostname, port)
        video_suite = make_suite_video(hostname, port)
        extra_tests_suite = make_suite_extra(hostname, port)
        malicious_tests_suite = make_suite_malicious(hostname, port)
         
        # start running the tests 
        print('Beginning the Minimum Requirement Tests')
        time.sleep(3 if run_slow else 1)
        # Run the minimum requirements test suite and store the results
        test_results = unittest.TextTestRunner().run(min_req_suite)

        nt = min_req_suite.countTestCases()
        minreq_score = max(0, F(nt - len(test_results.errors) - len(test_results.failures), nt))

        # Check if the server passed the minimum requirements
        if test_results.wasSuccessful():
            print("\nYou have passed the Minimum Requirements for this project!\n")
        else:
            print("\nYou have NOT passed the Minimum Requirements for this project.\n" +
                  "Please examine the above errors, the remaining tests\n" +
                  "will not be run until after the above tests pass.\n")

            print_points(minreq_score, 0, 0, 0, 0, 0, 0)
            sys.exit()

        print('Beginning Authentication Tests')
        # Kill the server and start it again with expiry flag set to auth_token_expiry seconds
        killserver(server)
        server.wait()
        server = start_server(postargs=['-e', auth_token_expiry])

        time.sleep(3 if run_slow else 1)
        # Run the extra tests
        test_results = unittest.TextTestRunner().run(auth_tests_suite)

        auth_score = max(0,
                         F(auth_tests_suite.countTestCases() - len(test_results.errors) - len(test_results.failures),
                           auth_tests_suite.countTestCases()))

        print('Beginning HTML5 Fallback Tests')
        # kill the server and start it again with '-a' (to enable HTML5 fallback)
        killserver(server)
        server.wait()
        server = start_server(postargs=['-a'])  # add HTML5 fallback argument
        time.sleep(3 if run_slow else 1)        # wait for start-up

        # run the html5 fallback test suite and compute a score
        test_results = unittest.TextTestRunner().run(html5_fallback_suite)
        fallback_score = max(0,
                             F(html5_fallback_suite.countTestCases() - len(test_results.errors) - len(test_results.failures),
                               html5_fallback_suite.countTestCases()))

        print('Beginning Video Streaming Tests')
        # kill the server and restart it
        killserver(server)
        server.wait()
        server = start_server()
        time.sleep(3 if run_slow else 1)

        # run the video streaming tests and compute a score
        test_results = unittest.TextTestRunner().run(video_suite)
        video_score = max(0,
                          F(video_suite.countTestCases() - len(test_results.errors) - len(test_results.failures),
                            video_suite.countTestCases()))
  
        if runIPv6:
            #
            # Now run IPv6 in various combinations
            #
            # check that base server can accept IPv6 connections.
            ts1 = make_suite_ipv6(ipv6_host, port)
            testcases, points = 0, 0

            def run_and_count(msg, ts1):
                global testcases, points
                print (msg)
                test_results = unittest.TextTestRunner().run(ts1)
                testcases += ts1.countTestCases()
                points += ts1.countTestCases() - len(test_results.errors) - len(test_results.failures)

            run_and_count("Checking that server can accept IPv6 connections", ts1)

            def restart_server(preargs=args):
                killserver(server)
                server.wait()
                newserver = start_server(preargs=preargs)
                time.sleep(3 if run_slow else 1)
                return newserver

            server = restart_server(preargs=['env', 'REVERSEIPADDR=1', f'LD_PRELOAD={ld_preload}'])

            ts2 = make_suite_ipv6(ipv6_host, port)
            run_and_count("Checking that server can accept IPv6 connections if addresses are in reverse", ts2)

            # check that server can accept IPv6 connections if only IPv6 addresses are listed
            server = restart_server(preargs=['env', 'SKIPIPV4=1', f'LD_PRELOAD={ld_preload}'])

            ts3 = make_suite_ipv6(ipv6_host, port)
            run_and_count("Checking that server can accept IPv6 connections if no IPv4 addresses", ts3)

            # check that server can accept IPv4 connections if only IPv4 addresses are listed
            server = restart_server(preargs=['env', 'SKIPIPV6=1', f'LD_PRELOAD={ld_preload}'])

            ts4 = make_suite_ipv6(hostname, port)
            run_and_count("Checking that server can accept IPv4 connections if no IPv6 addresses", ts4)

            ipv6_score = max(0, F(points, testcases))
            if points == testcases:
                print("\nCongratulations! IPv6 support appears to work!\n")
            else:
                print(
                        "\nYou have NOT passed the IPv6 portion.  Check that your code is properly handles all possible configurations.  " +
                        "Please examine the errors listed above.\n")

        print('Beginning Extra Tests')
        server = restart_server()
        time.sleep(3 if run_slow else 1)
        # Run the extra tests
        test_results = unittest.TextTestRunner().run(extra_tests_suite)

        extra_score = max(0,
                          F(extra_tests_suite.countTestCases() - len(test_results.errors) - len(test_results.failures),
                            extra_tests_suite.countTestCases()))

        # Kill the server and start it normally without the expiry set to auth_token_expiry seconds
        killserver(server)
        server.wait()
        server = start_server()

        # Check if the server passed the extra tests
        if test_results.wasSuccessful():
            print("\nYou have passed the Extra Tests for this project!\n")
            
        # decide whether or not we should run the malicious tests
        do_run_malicious = minreq_score == 1.0 and \
                           auth_score == 1.0 and \
                           extra_score == 1.0
        if not do_run_malicious:
            print("\nYou have NOT passed one of the following test categories:\n"
                  "  - %s\n  - %s\n  - %s\n"
                  "Please examine the errors above. The Malicious tests will not\n"
                  "be run until the above tests pass.\n" %
                  (test_categories["minreq"]["name"],
                   test_categories["auth"]["name"],
                   test_categories["extra"]["name"]))

            print_points(minreq_score, extra_score, 0, ipv6_score, auth_score, fallback_score, video_score)
            sys.exit()


        print("Now running the MALICIOUS Tests.  WARNING:  These tests will not necessarily run fast!")
        time.sleep(1)
        # Run the malicious tests
        test_results = unittest.TextTestRunner().run(malicious_tests_suite)

        robustness_score = max(0, F(
            malicious_tests_suite.countTestCases() - len(test_results.errors) - len(test_results.failures),
            malicious_tests_suite.countTestCases()))

        # Check if the server passed the extra tests
        if test_results.wasSuccessful():
            print("\nCongratulations! You have passed the Malicious Tests!\n")
        else:
            print("\nYou have NOT passed one or more of the Malicious Tests.  " +
                  "Please examine the errors listed above.\n")

        print_points(minreq_score, extra_score, robustness_score, ipv6_score, auth_score, fallback_score, video_score)

