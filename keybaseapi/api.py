"""The core Keybase.io API module.
What this does:
    - Allows you to get data from the keybase site.
    - Turns the data into actual readable data, not weird mangled JSON.

"""
from warnings import warn
import pgp
import pgp.message

import requests
from configmaster.ConfigKey import ConfigKey


headers = {
    "User-Agent": "keybase-python3 API interfacer (by https://keybase.io/eyes)"
}


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
                         params=params, headers=headers)
        elif method == "POST":
            return requests.get("https://keybase.io/_/api/{}/{}".format(self.API_VERSION, url),
                         data=params, headers=headers)
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

    def verify_data(self, pgp_message: str) -> bool:
        """
        Verifies a PGP message against the public key on file.

        Params:
            - pgp_message: The message to verify. This should be a fully contained message, either compressed or uncompressed, including the data to use and the signature.

        Returns:
            - A boolean, stating if the message was verified or not.

        """
        raise NotImplementedError

    def encrypt_data(self, message: str) -> pgp.message.EncryptedMessageWrapper:
        """"
        Encrypt data for the public key on file.

        Params:
            - message: The message to encrypt. This can be anything, but ideally it is string data.
            For security purposes, this parameter will attempt to be deleted after usage.
            THIS DATA MAY RETAIN IN MEMORY AFTER RETURNING FROM THE FUNCTION. DO NOT USE THIS TO HANDLE SENSITIVE DATA WITHOUT THE APPROPRIATE PRECAUTIONS.

        Returns:
            - a pgp.message.EncryptedMessageWrapper object.

        """
        raise NotImplementedError

class VerificationError(Exception):
    pass


class User(_Keybase):
    """
    A class for getting information about keybase Users.

    This supports things such as twitter://user or github://user.

    Note that if the search returns multiple results, the first one will be picked.
    """

    def encrypt_data(self, message: str) -> pgp.message.EncryptedMessageWrapper:
        raise NotImplementedError("python-pgp does not currently support encrypting.")

    def verify_data(self, pgp_message: str) -> bool:
        # Just pass a call to _verify_msg
        return self._verify_msg(pgp_message)

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
        self.public_key = pgp.read_key(self.raw_public_key)

        self.fingerprint = person.public_keys.primary.key_fingerprint.upper()
        self.keyalgo = person.public_keys.primary.key_algo
        self.keybits = person.public_keys.primary.key_bits

        self.subkeys = set(key[-16:] for key in person.public_keys.sibkeys)

        # Loop over our proofs.
        for proof in person.proofs_summary.all:
            self.proofs[proof.proof_id] = ConfigKey()
            self.proofs[proof.proof_id].load_from_dict(proof)

        self.valid = True

    def _verify_msg(self, msg: str) -> bool:
        # Load in the message.
        try:
            loaded_msg = pgp.read_message(msg, armored=True)
        except ValueError as e:
            raise VerificationError("Message was invalid") from e

        # Verify the key.
        # First, find a signature that matches the Key ID.
        for sig in loaded_msg.get_message().signatures:
            if self.fingerprint[-16:] in sig.issuer_key_ids:
                # Verified!
                signature = sig
                key_to_use = self.public_key
                break
            else:
                # Check for subkeys.
                for subkey in self.public_key.subkeys:
                    if subkey.fingerprint[-16:] in sig.issuer_key_ids:
                        # Verified as well.
                        key_to_use = subkey
                        signature = sig
                        break
                # This is a quick hack, to break out of both loops.
                else:
                    continue
                break
        else:
            raise VerificationError("Could not find a valid self signature in proof")
        # Then, verify using the public key on store.
        return key_to_use.verify(signature, loaded_msg.get_message().message)

    def _find_pgp_data(self, data: str) -> str:
        return data[data.find("-----BEGIN PGP MESSAGE-----"):data.find("-----END PGP MESSAGE-----")+26]

    def verify_proofs(self) -> bool:
        if self.trust:
            warn("Blindly trusting Keybase servers that the proofs are valid...")
            for proof in self.proofs.values():
                if proof.state == 1:
                    continue
                else:
                    raise VerificationError("Proof {} could not be verified!".format(proof.proof_type + "/" + proof.nametag))
            return True
        # Otherwise...
        for proof in self.proofs.values():
            # Get our URL.
            if proof.proof_type == "github":
                # Decode link.
                gist_id = proof.proof_url.split("/")[-1]
                request_url = "https://gist.githubusercontent.com/{}/{}/raw".format(proof.nametag, gist_id)
                r = requests.get(request_url, headers=headers)
                if r.status_code != 200:
                    raise VerificationError("Proof URL could not be validated")
                else:
                    # Search for the PGP key header...
                    data = r.text
                    key = self._find_pgp_data(data)
                    if not self._verify_msg(key):
                        raise VerificationError("Proof {} could not be verified!".format(proof.proof_type + "/" + proof.nametag))
            elif proof.proof_type == "reddit":
                # Sigh.
                # Reddit's API is shittastic, and I don't have enough justification to use praw for just fetching these.
                r = requests.get(proof.proof_url + "/.json", headers=headers)
                js = r.json()
                # Get the parent user's data.
                to_search_mtree = js[0]["data"]["children"][0]["data"]
                # Verify the username.
                if to_search_mtree["author"].lower() != proof.nametag.lower():
                    raise VerificationError("Proof {} username does not match")
                data = self._find_pgp_data(to_search_mtree["selftext"])
                # Next, strip the spaces from the left.
                ndata = []
                for line in data.split('\n'):
                    ndata.append(line.lstrip(' '))
                ndata = '\n'.join(ndata)
                if not self._verify_msg(ndata):
                    raise VerificationError("Proof {} could not be verified!".format(proof.proof_type + "/" + proof.nametag))
            elif proof.proof_type == "dns":
                warn("Cannot verify proofs of type {} current due to lack of keybase API support, without HTML scraping.".format(proof.proof_type))
        return True
