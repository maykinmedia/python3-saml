from cryptography.x509 import load_pem_x509_certificate, Certificate


def load_pem_certificate(pem_data: str) -> Certificate:
    """
    Load an X509 certificate in PEM format.

    PEM is base64 encoded data, so it can be encoded as ASCII.
    """
    data = pem_data.encode("ascii")
    return load_pem_x509_certificate(data)
