from requests.adapters import HTTPAdapter

from urllib3.util.ssl_ import create_urllib3_context


class SSLAdapter(HTTPAdapter):
    """
    Variation of solution found to make it possible to let
    requests use passphrases for client certificates.

    https://github.com/psf/requests/issues/1573

    and

    https://github.com/psf/requests/issues/2519
    """

    def __init__(self, certfile=None, keyfile=None, password=None, *args, **kwargs):
        self.ssl_context = None

        if certfile and keyfile:
            self.ssl_context = create_urllib3_context()
            self.ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile, password=password)

        return super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        if self.ssl_context is not None:
            kwargs['ssl_context'] = self.ssl_context
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        if self.ssl_context is not None:
            kwargs['ssl_context'] = self.ssl_context
        return super().proxy_manager_for(*args, **kwargs)
