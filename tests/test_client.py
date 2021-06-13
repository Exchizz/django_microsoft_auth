import json
import urllib.parse
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

from django.contrib.sites.models import Site
from django.test import RequestFactory, override_settings

from microsoft_auth.client import MicrosoftClient
from microsoft_auth.conf import LOGIN_TYPE_XBL

from . import TestCase

STATE = "test_state"
CLIENT_ID = "test_client_id"
REDIRECT_URI = "https://testserver/microsoft/auth-callback/"
ACCESS_TOKEN = "test_access_token"
XBOX_TOKEN = "test_xbox_token"
XBOX_PROFILE = "test_profile"


@override_settings(SITE_ID=1)
class ClientTests(TestCase):
    @classmethod
    def setUpClass(self):
        super().setUpClass()

    def setUp(self):
        super().setUp()

        self.factory = RequestFactory()

    def _get_auth_url(self, base_url, scopes=MicrosoftClient.SCOPE_MICROSOFT):
        args = {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": " ".join(scopes),
            "state": STATE,
            "response_mode": "form_post",
        }
        return (base_url + "?" + urllib.parse.urlencode(args), STATE)

    def _assert_auth_url(self, expected, actual):
        # parse urls
        e_url = urlparse(expected[0])
        e_qs = parse_qs(e_url.query)
        a_url = urlparse(actual[0])
        a_qs = parse_qs(a_url.query)

        # assert url
        self.assertEqual(e_url.scheme, a_url.scheme)
        self.assertEqual(e_url.path, a_url.path)
        self.assertEqual(e_url.netloc, a_url.netloc)
        self.assertEqual(len(e_qs.items()), len(a_qs.items()))
        for key, value in e_qs.items():
            self.assertEqual(value, a_qs[key])

        # assert state
        self.assertEqual(expected[1], actual[1])

    def test_scope(self):
        expected_scopes = " ".join(MicrosoftClient.SCOPE_MICROSOFT)

        auth_client = MicrosoftClient()
        self.assertEqual(expected_scopes, auth_client.scope)

    @override_settings(MICROSOFT_AUTH_LOGIN_TYPE=LOGIN_TYPE_XBL)
    def test_xbox_scopes(self):
        expected_scopes = " ".join(MicrosoftClient.SCOPE_XBL)

        auth_client = MicrosoftClient()
        self.assertEqual(expected_scopes, auth_client.scope)

    def test_state(self):
        auth_client = MicrosoftClient(state=STATE)
        self.assertEqual(STATE, auth_client.state)

    def test_redirect_uri(self):
        auth_client = MicrosoftClient()
        self.assertEqual(REDIRECT_URI, auth_client.redirect_uri)

    @override_settings(MICROSOFT_AUTH_CLIENT_ID=CLIENT_ID)
    def test_authorization_url(self):
        auth_client = MicrosoftClient(state=STATE)

        base_url = auth_client.openid_config["authorization_endpoint"]
        expected_auth_url = self._get_auth_url(base_url)

        self._assert_auth_url(
            expected_auth_url, auth_client.authorization_url()
        )

    @override_settings(
        MICROSOFT_AUTH_CLIENT_ID=CLIENT_ID,
        MICROSOFT_AUTH_LOGIN_TYPE=LOGIN_TYPE_XBL,
    )
    def test_authorization_url_with_xbl(self):
        base_url = MicrosoftClient._xbox_authorization_url
        expected_auth_url = self._get_auth_url(
            base_url, scopes=MicrosoftClient.SCOPE_XBL
        )

        auth_client = MicrosoftClient(state=STATE)
        self._assert_auth_url(
            expected_auth_url, auth_client.authorization_url()
        )

    @patch("microsoft_auth.client.requests")
    def test_fetch_xbox_token(self, mock_requests):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = XBOX_TOKEN
        mock_requests.post.return_value = mock_response

        auth_client = MicrosoftClient()
        auth_client.token = {"access_token": ACCESS_TOKEN}
        xbox_token = auth_client.fetch_xbox_token()

        self.assertEqual(XBOX_TOKEN, xbox_token)
        self.assertEqual(XBOX_TOKEN, auth_client.xbox_token)

    @patch("microsoft_auth.client.requests")
    def test_fetch_xbox_token_params(self, mock_requests):
        expected_headers = {
            "Content-type": "application/json",
            "Accept": "application/json",
        }
        expected_data = json.dumps(
            {
                "RelyingParty": "http://auth.xboxlive.com",
                "TokenType": "JWT",
                "Properties": {
                    "AuthMethod": "RPS",
                    "SiteName": "user.auth.xboxlive.com",
                    "RpsTicket": "d={}".format(ACCESS_TOKEN),
                },
            }
        )

        auth_client = MicrosoftClient()
        auth_client.token = {"access_token": ACCESS_TOKEN}
        auth_client.fetch_xbox_token()

        mock_requests.post.assert_called_with(
            MicrosoftClient._xbox_token_url,
            data=expected_data,
            headers=expected_headers,
        )

    @patch("microsoft_auth.client.requests")
    def test_fetch_xbox_token_bad_response(self, mock_requests):
        mock_response = Mock()
        mock_response.status_code = 400
        mock_requests.post.return_value = mock_response

        auth_client = MicrosoftClient()
        auth_client.token = {"access_token": ACCESS_TOKEN}
        xbox_token = auth_client.fetch_xbox_token()

        self.assertEqual({}, xbox_token)
        self.assertEqual({}, auth_client.xbox_token)

    @patch("microsoft_auth.client.requests")
    def test_get_xbox_profile(self, mock_requests):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "DisplayClaims": {"xui": [XBOX_PROFILE]}
        }
        mock_requests.post.return_value = mock_response

        auth_client = MicrosoftClient()
        auth_client.xbox_token = {"Token": XBOX_TOKEN}
        xbox_profile = auth_client.get_xbox_profile()

        self.assertEqual(XBOX_PROFILE, xbox_profile)

    @patch("microsoft_auth.client.requests")
    def test_get_xbox_profile_params(self, mock_requests):
        expected_headers = {
            "Content-type": "application/json",
            "Accept": "application/json",
        }
        expected_data = json.dumps(
            {
                "RelyingParty": "http://xboxlive.com",
                "TokenType": "JWT",
                "Properties": {
                    "UserTokens": [XBOX_TOKEN],
                    "SandboxId": "RETAIL",
                },
            }
        )

        auth_client = MicrosoftClient()
        auth_client.xbox_token = {"Token": XBOX_TOKEN}
        auth_client.get_xbox_profile()

        mock_requests.post.assert_called_with(
            MicrosoftClient._profile_url,
            data=expected_data,
            headers=expected_headers,
        )

    @patch("microsoft_auth.client.requests")
    def test_get_xbox_profile_bad_response(self, mock_requests):
        mock_response = Mock()
        mock_response.status_code = 400
        mock_requests.post.return_value = mock_response

        auth_client = MicrosoftClient()
        auth_client.xbox_token = {"Token": XBOX_TOKEN}
        xbox_profile = auth_client.get_xbox_profile()

        self.assertEqual({}, xbox_profile)

    def test_get_xbox_profile_no_token(self):
        auth_client = MicrosoftClient()
        xbox_profile = auth_client.get_xbox_profile()

        self.assertEqual({}, xbox_profile)

    def test_valid_scopes(self):
        scopes = MicrosoftClient.SCOPE_MICROSOFT

        auth_client = MicrosoftClient()
        self.assertTrue(auth_client.valid_scopes(scopes))

    def test_valid_scopes_invalid(self):
        scopes = ["fake"]

        auth_client = MicrosoftClient()
        self.assertFalse(auth_client.valid_scopes(scopes))

    @override_settings(MICROSOFT_AUTH_LOGIN_TYPE=LOGIN_TYPE_XBL)
    def test_valid_scopes_xbox(self):
        scopes = MicrosoftClient.SCOPE_XBL

        auth_client = MicrosoftClient()
        self.assertTrue(auth_client.valid_scopes(scopes))

    @override_settings(
        SITE_ID=None, ALLOWED_HOSTS=["example.com", "testserver"]
    )
    def test_alternative_site(self):
        self.assertEqual(Site.objects.get(pk=1).domain, "testserver")

        Site.objects.create(domain="example.com", name="example.com")

        request = self.factory.get("/", HTTP_HOST="example.com")

        self.assertEqual(
            Site.objects.get_current(request).domain, "example.com"
        )

        client = MicrosoftClient(request=request)

        self.assertIn("example.com", client.authorization_url()[0])

    @override_settings(MICROSOFT_AUTH_ASSERTION_CERTIFICATE="cert.pem")
    @override_settings(MICROSOFT_AUTH_ASSERTION_CERTIFICATE_THUMBPRINT="2D:45:11:16:FA:3B:A1:0C:9A:DD:7E:A4:F5:04:55:0E:B7:64:04:0C")
    @override_settings(MICROSOFT_AUTH_ASSERTION_KEY_CONTENT="""
-----BEGIN PRIVATE KEY-----
MIIJRQIBADANBgkqhkiG9w0BAQEFAASCCS8wggkrAgEAAoICAQDPcXCBw/itFUfH
AJoO1gKpZO0Y3ReWx37fOmrMb+tBLaL3q7WDD53n1yiMw2+lEXqRv+UXgnXzT+KJ
tHdtDjj7+G1pYQmNV64IgjqGBPvxSljfF5FRkkQLAA0cY98NiHZTlHa4pAbQ2bx8
YoOErB7sDzvBGgti03ubgx11rSBH8XVc7WYSY2XtQHnOWR8WyV0Rz2MxctlRfYBp
X6tnjbC0JGyLyzNHBvf20i+zoY/HKBVX8P0R17ojnsF74HXZJd/u5ezQZah+1qh0
D+9DROSPgKYq8SFtNNA91VecDE06cqtRYQWsIClL4jIKlq3y0s+2LnwQcIdNLERt
WbEWitQTl8YIjL6bLVa5LMq0/ggI1LyTeS2x+sNqS1IbgfKN92fFni0doLLt1B7Z
ssn71IVhgkIc3xBhK4uMyuUhoKiOOSfkPnNsaQdecQCMU7b50yXMl78DOkhQ3UAV
TmRZxa6H8thFEWgmnTwTb6akUTyRtvsDuCLHB8Fyk5ZuceW74DsLvMRts/E9Hylu
az684oaf+fJ5kuh5we8PH/txnTXStNDWVLzt1YztAq7CqEMoVrs+9sWbAmZzg5gv
gVACbtiku5wdNVxGQ0uiQalycyPQBZf2fHrK/TKbFGF0ZbjWOU/mBrqw0kprhYpO
x0eK+g7PB0pnYqdJG9Z+jPRazpZd0wIDAQABAoICAQCPHkWv0aPczkTCIEEpoS8e
7XnC4K6ooSSAIE6Uk1asli7MTxQgwwJ/dGsOiruZF/EHY2xMBv8XifLSbMbEX76i
4Kejv4YWlPqF9ksoMYIc291qtVjV/WKicDubba/zJ0XzrgcmpkvphX9MFa+FNjbz
SCNCu5RFb4DlLtWBXZta51TAcy0r3JXy1Lv0yHnxf6WNZxaZhBI47axNhuq7u/7A
miylWeEbzMwA5sxwUzPeBGKNVL9UsxBCCQKWU6sa0M2phcoXkTtpnvGDeYbqUzqZ
YvnBwLD+JiTRtEIIcFhLzdcygwylz16OcxVxRrnmQNl7aKDButEuRi9DflD2K3va
dqImpAdlimbQjwxaX3Um4RnmM29fSiJtwxvCu9UpnDRwTcEUutDTh/eMnxe/qF7e
KBIATtVjxN78tSWTappzjLpiBzD1u/rUhG607goGuJKhOf2BnV/FI4Ux3k1joc6J
CpxGdtDPQf1769zI10eTfgNMOsnEE6/2MEra95jd/qsh05ZpWz0pIYxQySpDHvYp
y9GiAWOCBp5gvSOinDbE0HIyNW7iFGppUZxelBIi3pVjs7ohEOfXpqx19xAluOWC
tcnbxHjRLxBpMot+Qz/OjDsoC0OFSiWiuyN8qj9zJBmFmzOGP1xWlk3YlZ7iJ8WI
1bihaldLLjGqMZK+nu47gQKCAQEA6lm28ScI6WF2Y9bL64AmYkWiXLfWkG+9xZAs
uzSZ67gXKDhs5GNurntKXf/Js6WvXYgxED9KNBG2nIEe3ZKcWXEfxHo3oepls9Z3
0Spbiys71Uo7eyR1OoIOErnYixQlYeNz4jJpPi0KQdsGit7aOcFMINX/gh80dq6i
SR6FRJsK8BfGQ0AJMxZxkl0bej4VGYwOAaUFB6mzlp19DIB4EEp799oCag+7aFVp
F8cb5F0TPsEkrQQ0Zx0uaxERfZrerI24u0IedAD1/Mn99kBos5hVDujXWZ8Eqo5m
JZ7KFfVnPEhpBwRhhCQcxEltXGmJ0kyeMAVfJc9XarLa63doQQKCAQEA4ptg4HIK
nVhaxmNyPihvdZ0lbinCBOWI5pyVHLNbhPIQS9XRvTDNSBRUPCcv78V5ERtqc+rr
2Dw7iea+vtFED2MR5hpyff41QzIfoCZN+GNpmr7cqvWHpus5eTEXvIesax3QZw6G
gl4PAjTgkTRoxmOP+vWpVJ0Ed+Kh5wXEgezaptFqrHYXVN9Mgx8JhBZIohbQ1Ev4
EfnmdUsunfAfsL41frt7ZJ/FqOyixm6i1Rj26nWu5STeek1a2jUEZt7N4bxToB47
5gsSb+kGTeUHmd8hTFlTFRutGgUET0lA7QwL6HQSnPCAFcpqiuE4DBZPqET3PXFM
ZR6nKG7q7/lhEwKCAQEA3ZeBTZucaJk4ygTkA0XEha3UbZmDcEXIipPeSBHf7Sy/
8M8R4A9JLAD2e9WO0qi7HlTWF8fQkVWid2/8UIT+A/Dcmfr6ucaa7ibAWu6Taw+x
Xuf3QGRj2LP7PKewYynkgyAAhoUmUJ1kEotZL1yzumLVakMPe+mnwQU1/K+4UfvM
puPEG/jj+gOh1kTl43vqlaKB5/oyvGExqBw4jua3IKhdeioRmFpR2cDRQ6OI8zEz
LmaRGGxeZJYKO0EDaeJT5ZOIdsB5bTUvZB1XX07d8dv7qcJvRpX/YoqNecsgyQyn
1i+d5/2ze7Bt5wiLOROuN0UtWrjplCXvQbvnFzlsQQKCAQEAmpDdLXrcHqMLl9Jx
NFCkZhcAVvoIqwpdrN8VHnSAclgiIXgBDgjhnM6w/i7ElcmeYLrQi6yrndzHx7Iq
XUGkKNKsfMWBXsssTV89DyHRgSFeAP06yymak5JSq4V+6UupoY6+fez8dqPtnNWw
b5rN9LQom0dBbsODLrrZMBlRBkYmhi7FkkkidPOy3qUm+n+wn07stkHzPV+1gD/9
1iDZnNbA6ma7LdGFI0n1ZWBFlRDoKtiGqSnSzp1A4SHUlM5YpCau68JznN/kfYz2
jd8wphX6QneTIgy0r9DINcSDkqzq2m2B3KZ212Yv8fbZIfV99ArGkZRcRYT5A61U
dsclHQKCAQEAuusPi+FmkLi9tCx3QgpMA2VvEF3opQtaULEEGxXwygWW+pV4ue+g
3B50yMi3AArQp5hAXw0YuqzGjfYaRoXU+rZdSm/cG3fT66PJgWLfbcOye1S+PEGh
5qm6NixZbDvXEFDsfKvjUEtuukdZLnwOORd687Qciz05FMMa6yzPE7rRoHGq7j/5
7yZ/BG6CtQSBAo1ZrEvytvfDHDCYB+kv66HzT276NLKYYuARKQoYqWxV7UglwYBB
0SdHzFq+TyZ+fek0y8tMzDK/TjqzZdUAe0GwHaQMFyKJteAfnX3MiV4+8zM0OnmQ
LS+nmh7sapSw35+hWYioH5SEE+2Ssy/mMA==
-----END PRIVATE KEY-----""")
    @override_settings(MICROSOFT_AUTH_ASSERTION_CERTIFICATE="""
-----BEGIN CERTIFICATE-----
MIIFCTCCAvGgAwIBAgIUXgz/JgxhMn7Zen/Bfe65PqpSAS0wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTIxMDYxMzE3NDExM1oXDTIyMDYx
MzE3NDExM1owFDESMBAGA1UEAwwJbG9jYWxob3N0MIICIjANBgkqhkiG9w0BAQEF
AAOCAg8AMIICCgKCAgEAz3FwgcP4rRVHxwCaDtYCqWTtGN0Xlsd+3zpqzG/rQS2i
96u1gw+d59cojMNvpRF6kb/lF4J180/iibR3bQ44+/htaWEJjVeuCII6hgT78UpY
3xeRUZJECwANHGPfDYh2U5R2uKQG0Nm8fGKDhKwe7A87wRoLYtN7m4Mdda0gR/F1
XO1mEmNl7UB5zlkfFsldEc9jMXLZUX2AaV+rZ42wtCRsi8szRwb39tIvs6GPxygV
V/D9Ede6I57Be+B12SXf7uXs0GWoftaodA/vQ0Tkj4CmKvEhbTTQPdVXnAxNOnKr
UWEFrCApS+IyCpat8tLPti58EHCHTSxEbVmxForUE5fGCIy+my1WuSzKtP4ICNS8
k3ktsfrDaktSG4HyjfdnxZ4tHaCy7dQe2bLJ+9SFYYJCHN8QYSuLjMrlIaCojjkn
5D5zbGkHXnEAjFO2+dMlzJe/AzpIUN1AFU5kWcWuh/LYRRFoJp08E2+mpFE8kbb7
A7gixwfBcpOWbnHlu+A7C7zEbbPxPR8pbms+vOKGn/nyeZLoecHvDx/7cZ010rTQ
1lS87dWM7QKuwqhDKFa7PvbFmwJmc4OYL4FQAm7YpLucHTVcRkNLokGpcnMj0AWX
9nx6yv0ymxRhdGW41jlP5ga6sNJKa4WKTsdHivoOzwdKZ2KnSRvWfoz0Ws6WXdMC
AwEAAaNTMFEwHQYDVR0OBBYEFHIDUCg49DvfZ0NOR29JvNxoHVs0MB8GA1UdIwQY
MBaAFHIDUCg49DvfZ0NOR29JvNxoHVs0MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggIBAHAMjMxkE9dQO0DigmvkjPfFIb/8v99CrJNK462gcgqlHy5r
DA1th4R2mAe5hCfAnebg4xMoo4UHY3GcZL1sHH2PK5wSf0sbPxg0vYK4XbUiI+Oc
h0hmQVNckTogpa4iSx6+htT9ji0WR039SWNyXGdgolybYbBiZtSTyKcA5BPZUfLw
Q6FmkpCSEYmNbCMD+CdEOzauezxEe+Ezub83YfXx5n86PE8AR0QvU1NI0bvUR1dp
49Z9CvRPbkyMjdI5q+AlNf4vzR1Ixo8VBs9bXxhoMeTC4OH8l52d6if6C1+U5h1N
oTmnznEY1qWygnHJn9nKWpfcdJInOyq5arJW5Y+VeS5cFj/QkSY9PQGUk9ei5mFo
PqW0D699VJIChdOFPvYSWHbHxQsdRIQzCOEIRpr+vBIRV36W8kyrJ6sHc81J+1gW
YDMrp1Vql0mDBQpXNk0pQKV5MvAjhk8WWniHLe8Pp7LiWp4pe3thyhmsYHRiFBt3
3MTZ7EYSrc9HQZDqG/bFGZ8h/drPj7/XjQmi06Vxg+dU156gNuOPmNM7YZMkhydZ
nYGfSxh94+omhHZ9uVuWfLE8WYAL9iJdXGIhBB/M5HnHGGvJUyw3SYLNZRlSkYfT
LKT0uiboXGMgMK63Ifa9QJpp8wTS6G6/YTJuYDEV9n4FWJKBUYB69Q0YJZBi
-----END CERTIFICATE-----
""")
    @override_settings(MICROSOFT_AUTH_CLIENT_ID="1234")
    @patch("requests_oauthlib.OAuth2Session.fetch_token")
    def test_fetch_token_client_assertion(self, mock_fetch_token):
        auth_client = MicrosoftClient()
        token_endpoint = "http://test.com"

        kwargs = {
        }
  
        # Certificate created using "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365"
        token = auth_client.fetch_token(**kwargs)

        assertion = auth_client.create_assertion()
        type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" 

        args = {'cert': auth_client.config.MICROSOFT_AUTH_ASSERTION_CERTIFICATE, 
            'include_client_id': True, 
            'client_id': auth_client.config.MICROSOFT_AUTH_CLIENT_ID, 
            'client_assertion_type': type, 
            'client_assertion': assertion, 
            } 

        mock_fetch_token.assert_called_with(auth_client.openid_config["token_endpoint"], **args, **kwargs)

    @patch("requests_oauthlib.OAuth2Session.fetch_token")
    @override_settings(MICROSOFT_AUTH_CLIENT_SECRET="1234")
    def test_fetch_token_client_secret(self, mock_fetch_token):
        auth_client = MicrosoftClient()

        args = {
            'client_secret' : auth_client.config.MICROSOFT_AUTH_CLIENT_SECRET
        }

        kwargs = {
        }

        token = auth_client.fetch_token(**kwargs)
        mock_fetch_token.assert_called_with(auth_client.openid_config["token_endpoint"], **args, **kwargs)

