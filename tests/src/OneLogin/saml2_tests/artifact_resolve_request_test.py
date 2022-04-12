import json
import unittest
from hashlib import sha1
from os.path import dirname, exists, join
from unittest.mock import patch

import requests_mock

from onelogin.saml2.artifact_resolve import Artifact_Resolve_Request
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.settings import OneLogin_Saml2_Settings


class Saml2_Artifact_Resolve_Request_Test(unittest.TestCase):
    data_path = join(dirname(dirname(dirname(dirname(__file__)))), "data")
    settings_path = join(dirname(dirname(dirname(dirname(__file__)))), "settings")

    def loadSettingsJSON(self, name="settings1.json"):
        filename = join(self.settings_path, name)
        if exists(filename):
            stream = open(filename, "r")
            settings = json.load(stream)
            stream.close()
            return settings

    def file_contents(self, filename):
        f = open(filename, "r")
        content = f.read()
        f.close()
        return content

    @patch("onelogin.saml2.artifact_resolve.parse_saml2_artifact")
    @requests_mock.Mocker()
    def testConstructRequestContentTypeHeader(self, m_parse_artifact, m):
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON("settings14.json"))
        idp = settings.get_idp_data()
        sha1_entity_id = sha1(idp["entityId"].encode("utf-8")).digest()
        m_parse_artifact.return_value = ("0", sha1_entity_id, "")

        saml_art = "someRandomString!"
        artifact_resolve_request = Artifact_Resolve_Request(settings, saml_art)

        m.post("https://idp.com/saml/idp/resolve_artifact")
        artifact_resolve_request.send()

        request = m.request_history[-1]

        self.assertIn("content-type", request.headers)
        self.assertEqual(
            OneLogin_Saml2_Constants.TEXT_XML, request.headers["content-type"]
        )

    @patch("onelogin.saml2.artifact_resolve.parse_saml2_artifact")
    @requests_mock.Mocker()
    def testConstructRequestContentTypeDefaultHeader(self, m_parse_artifact, m):
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON("settings11.json"))
        idp = settings.get_idp_data()
        sha1_entity_id = sha1(idp["entityId"].encode("utf-8")).digest()
        m_parse_artifact.return_value = ("0", sha1_entity_id, "")

        saml_art = "someRandomString!"
        artifact_resolve_request = Artifact_Resolve_Request(settings, saml_art)

        m.post("https://idp.com/saml/idp/resolve_artifact")
        artifact_resolve_request.send()

        request = m.request_history[-1]

        self.assertIn("content-type", request.headers)
        self.assertEqual(
            OneLogin_Saml2_Constants.SOAP_XML, request.headers["content-type"]
        )
