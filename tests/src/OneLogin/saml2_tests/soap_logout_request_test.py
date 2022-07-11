import json
import unittest
from os.path import dirname, exists, join

import responses

from onelogin.saml2.errors import OneLogin_Saml2_ValidationError
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.soap_logout_request import Soap_Logout_Request


class Soap_Logout_Request_Test(unittest.TestCase):
    data_path = join(dirname(dirname(dirname(dirname(__file__)))), "data")
    settings_path = join(dirname(dirname(dirname(dirname(__file__)))), "settings")

    def loadSettingsJSON(self, name="settings1.json"):
        filename = join(self.settings_path, name)
        if exists(filename):
            stream = open(filename, "r")
            settings = json.load(stream)
            stream.close()
            return settings
        else:
            raise Exception("Settings json file does not exist")

    def file_contents(self, filename):
        f = open(filename, "r")
        content = f.read()
        f.close()
        return content

    def get_soap_logout_request(self, xml_file="soap_logout_request.xml"):
        settings_info = self.loadSettingsJSON()
        settings = OneLogin_Saml2_Settings(settings_info)
        request = self.file_contents(
            join(self.data_path, "soap_logout_requests", xml_file)
        )
        return Soap_Logout_Request(settings, request)

    def testConstructor(self):
        """
        Tests the Soap_Logout_Request Constructor.
        """
        soap_logout_request = self.get_soap_logout_request()

        self.assertIsInstance(soap_logout_request, Soap_Logout_Request)
        self.assertEqual(
            soap_logout_request.document.tag,
            "{urn:oasis:names:tc:SAML:2.0:protocol}LogoutRequest",
        )

    def testGetNameId(self):
        soap_logout_request = self.get_soap_logout_request()

        self.assertEqual(
            soap_logout_request.get_name_id(),
            "ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c",
        )

    @unittest.mock.patch("onelogin.saml2.utils.OneLogin_Saml2_Utils.validate_sign")
    @responses.activate
    def testValid(self, mock):
        mock.return_value = True

        soap_logout_request = self.get_soap_logout_request()

        soap_logout_request.validate()

    def testEmptyId(self):
        soap_logout_request = self.get_soap_logout_request(
            xml_file="soap_logout_request_empty_id.xml"
        )

        with self.assertRaises(OneLogin_Saml2_ValidationError) as context:
            soap_logout_request.validate()

        self.assertEqual(
            str(context.exception), "Missing ID attribute on SAML Logout Request"
        )

    def testInvalidSignature(self):
        soap_logout_request = self.get_soap_logout_request(
            xml_file="soap_logout_request_invalid_signature.xml"
        )

        with self.assertRaises(OneLogin_Saml2_ValidationError) as context:
            soap_logout_request.validate()

        self.assertEqual(
            str(context.exception), "Found an invalid Signed Element. Rejected"
        )

    @unittest.mock.patch("onelogin.saml2.utils.OneLogin_Saml2_Utils.validate_sign")
    @responses.activate
    def testInvalidIssuer(self, mock):
        mock.return_value = True

        soap_logout_request = self.get_soap_logout_request(
            xml_file="soap_logout_request_invalid_issuer.xml"
        )

        with self.assertRaises(OneLogin_Saml2_ValidationError) as context:
            soap_logout_request.validate()

        self.assertEqual(
            str(context.exception),
            "Invalid issuer in the Logout Request (expected http://idp.example.com/, got http://other-idp.example.com/)",
        )

    @unittest.mock.patch("onelogin.saml2.utils.OneLogin_Saml2_Utils.validate_sign")
    @responses.activate
    def testEmptyNameId(self, mock):
        mock.return_value = True

        soap_logout_request = self.get_soap_logout_request(
            xml_file="soap_logout_request_empty_nameId.xml"
        )

        with self.assertRaises(OneLogin_Saml2_ValidationError) as context:
            soap_logout_request.validate()

        self.assertEqual(str(context.exception), "The NameID value is empty")
