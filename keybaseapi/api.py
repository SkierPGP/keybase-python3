"""The core Keybase.io API module.
What this does:
    - Allows you to get data from the keybase site.
    - Turns the data into actual readable data, not weird mangled JSON.

"""
from warnings import warn



import requests
from configmaster.ConfigKey import ConfigKey

from pgpy import PGPKey, PGPSignature, PGPMessage
from pgpy.errors import PGPError

import pgpdump
import pgpdump.packet


class _Keybase(object):
    """
    The base class for all Keybase API classes.
    """

    API_VERSION = "1.0"

    def _make_request(self, url: str, params: dict, method: str="GET") -> requests.Response:
        """
        Makes a request to the keybase API. Internal method.
        """
        if method == "GET":
            return requests.get("https://keybase.io/_/api/{}/{}".format(self.API_VERSION, url),
                         params=params)
        elif method == "POST":
            return requests.get("https://keybase.io/_/api/{}/{}".format(self.API_VERSION, url),
                         data=params)
        else:
            return None

    def _translate_into_configkey(self, data: requests.Response) -> ConfigKey:
        """
        Transforms data into a ConfigKey object.
        """
        if "application/json" in data.headers['Content-Type']:
            c = ConfigKey(); c.load_from_dict(data.json()); return c
        else:
            return None

    def _get(self, url: str, params: dict) -> ConfigKey:
        """
        Makes a GET request.
        """
        return self._translate_into_configkey(self._make_request(url, params, "GET"))

    def _post(self, url: str, params: dict) -> ConfigKey:
        """
        Makes a POST request.
        """
        return self._translate_into_configkey(self._make_request(url, params, "POST"))


class User(_Keybase):
    """
    A class for getting information about keybase Users.

    This supports things such as twitter://user or github://user.

    Note that if the search returns multiple results, the first one will be picked.
    """
    def __init__(self, username: str, trust_keybase: bool=False) -> None:
        self.username = username
        if "://" in username:
            self.method = username.split("://")[0]
            self.username = username.split("://")[-1]
        else:
            self.method = "usernames"

        self.fetched = False

        self.trust = trust_keybase
        if trust_keybase:
            warn("Trusting Keybase servers for this API request...")

        self.valid = False

        # Structure definitions.
        self.raw_public_key = None
        self.public_key = None

        self.fingerprint = ""
        self.keyalgo = 1
        self.keybits = 0

        self.proofs = ConfigKey()

        self.fullname = ""
        self.location = ""
        self.bio = ""


        # Fetch the data.
        self._get_info()

    def _get_info(self):
        # Fetch the information from keybase.
        discovery = self._get("user/lookup.json", {self.method: self.username})
        self.raw_keybase_data = discovery
        self._map_data()

    def _map_data(self):
        # Begin mapping data to our structure.
        if self.raw_keybase_data.status.code != 0:
            self.fetched = False
            return
        else:
            self.fetched = True
        # Load first person's profile data.
        person = self.raw_keybase_data.them[0]
        # Load basic data.
        if not person:
            return

        self.real_name = person.profile.full_name
        self.location = person.profile.location
        self.bio = person.profile.bio
        self.username = person.basics.username

        # Map public key
        self.raw_public_key = person.public_keys.primary.bundle
        self.public_key = PGPKey()
        # Workaround for a bug.
        try:
            self.public_key.parse(self.raw_public_key)
        except AttributeError:
            # Fuck it!
            pass

        # Loop over our proofs.
        for proof in person.proofs_summary.all:
            self.proofs[proof.proof_id] = ConfigKey()
            self.proofs[proof.proof_id].load_from_dict(proof)

        self.valid = True

    def _verify_msg(self, msg: str) -> bool:
        # First, begin by dumping the compressed data.
        data = pgpdump.AsciiData(msg)
        packets = list(data.packets())
        if len(packets) == 1:
            # Decompress the data.
            new_packets = list(pgpdump.BinaryData(packets[0].decompressed_data).packets())
            return self._verify_packets(new_packets)
        else:
            # Just verify the signatures.
            return self._verify_packets(packets)


    def verify_proofs(self) -> bool:
        if self.trust:
            warn("Blindly trusting Keybase servers that the proofs are valid...")
            return True
        # Otherwise...
        for proof in self.proofs.values():
            # Get our URL.
            if proof.proof_type == "github":
                pass


    def _verify_packets(self, new_packets: list) -> bool:
        raise NotImplementedError
