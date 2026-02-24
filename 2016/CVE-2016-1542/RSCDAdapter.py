# A requests adapter for handling RSCD connections to BMC BladeLogic agents.
# It's amazing how much code is required just to prepend an SSL connection with a couple of cleartext characters
# before letting requests use it.

import socket
import httplib
import ssl
import requests

from requests.adapters import HTTPAdapter
from requests.compat import urlparse

class RSCDConnection(httplib.HTTPConnection, object):

    def __init__(self, host, port, timeout=60):
        super(RSCDConnection, self).__init__(host, timeout=timeout)
        self.sock = None
        self.timeout = timeout
        self.host = host
        self.port = port

    def __del__(self):  # base class does not have d'tor
        if self.sock:
            self.sock.close()

    def connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self.host, self.port))
        sock.sendall("TLSRPC")
        self.sock = ssl.wrap_socket(sock)


class RSCDConnectionPool(requests.packages.urllib3.connectionpool.HTTPConnectionPool):

    def __init__(self, url, port, timeout=60):
        super(RSCDConnectionPool, self).__init__(url, port, timeout=timeout)
        self.host = urlparse(url).hostname
        self.timeout = timeout

    def _new_conn(self):
        return RSCDConnection(self.host, self.port, self.timeout)


class RSCDAdapter(HTTPAdapter):

    def __init__(self, port=4750, timeout=60, pool_connections=25):
        super(RSCDAdapter, self).__init__()
        self.timeout = timeout
        self.port = port
        self.pools = requests.packages.urllib3._collections.RecentlyUsedContainer(
            pool_connections, dispose_func=lambda p: p.close()
        )
        super(RSCDAdapter, self).__init__()

    def get_connection(self, url, proxies=None):
        proxies = proxies or {}
        proxy = proxies.get(urlparse(url.lower()).scheme)

        if proxy:
           raise ValueError('%s does not support specifying proxies' % self.__class__.__name__)

        with self.pools.lock:
           pool = self.pools.get(url)
           if pool:
               return pool

           pool = RSCDConnectionPool(url, self.port, self.timeout)
           self.pools[url] = pool

        return pool

    def request_url(self, request, proxies):
        return request.path_url

    def close(self):
        self.pools.clear()
