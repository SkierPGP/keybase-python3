import pgp
import pytest
import keybaseapi

signed_data = """-----BEGIN PGP MESSAGE-----
Version: GnuPG v2

owEBkARv+5ANAwAIAbM7eGjErpPKAa0CX2IHYWJjLmdwZ1Xi2NmFAgwDzqe/bO+L
Q9IBEACAHP+vUXJGTISuTzaL2/nwKBt7ulSM9R9nb9sCEcEy9mJ8O7em1UFddnHb
2BmL5I/KaN/sX2um/yTn9/vaCtJVCS0lbZuon2gWO5HkBXKmvP2c44IoVwEYhwAN
CXIZrHtE4uImhZn8cKMXkpghniHGWHa+3VKR5lF2hmX/KtcQ4lHtqPlH99Xkg1Mz
ofRKVgvj34mtVkUkUCok1cKNsuF+JdERvmNiUQFZ7Ddr/a3sVi35jHK5I/UPifGK
VzrAsfadIMDBfKlUQh8fuVu5n4Bg2SEYZk7Pvqz1tF2QoTydEfo71S/MEBfBTNaq
GSyC8Pf1s+JbNkQLOJURTDFyDFstRtOHAZ/rOud4MOPIknTGe6rZ4xy7Ve/jbDeZ
JI/p9E6Vaipui771jhjS+NFjy/565n0Ik1VKbZB8msbToSmXv6YKtIF36X4Am762
EEqYqQwpsRG7y1rxNrgSsm8Rw00/cmozVfc/tASvanMmXolihReVbIzfj5q7guB4
81iZIG1kRz6ApDGxyc9hpfIVPNSpTAJYC46Uq8RUofTLh10W+Mvj6gWv8mHvt2t4
pmtZEF9Rvh96ao7N3KyDmmM+IIS4GuJnXNUQ6Tq9Lpcf0tL2FkbbY/NjKGQ0U9lL
GyJzo61LBeOSTuVskcNaZ7nBj9GENZTlBGzqXIENpny0VfvWhtJBAZqpakySd7ou
6EVRNWWx0fEX8YsNVoP/0j/yDgiWbnlRrBMPCIbURcXQuboTL5TR8NkFB8jbuS7B
XF6ANdzwdZ2JAhwEAAEIAAYFAlXi2NkACgkQszt4aMSuk8pfHg//a0UjkDn5fe1B
xs9G/sdxFSksDJrFbWK2zZ7FJossz8eVENkcW418deQIIw+aRy6KClPFQ6b7TOzr
t877KroWfvJ2+WpE+e8KKl4F1ekhJ+AErEw8/Swu1MmND8RhUd5OiDXW0riSsJcW
6sW2AzN2tMAkL/tWqI6aztFVDRtGjoiOqdt/J69bdamNLxQN0kAOZN0bwLd/ocBv
KLSQfY3OSE3j20+6AaetkpT7nWC3TuTuX3s4LbI7nnU5V9REde22GsrFvn+3uYA5
XExXhuw+E/C7jthQJ1XBvT3MsS6Vk4Y9b+jkZ/N2izO1yroxPaN39BlWc0Dq7Cd1
x4KuDgAzXbGgh9nfnOBFmpcILsk3Un0CpBVFhN/kiuL1CpPzijw24kmLJrLoRffG
yh6Eq6sFXck7VwsazudAIDS81LYXDa+B0YaPLdaZ6f8k4BPVcpppXYLltmmhpuEP
L7jwAVdldRcwulr8aJptdMo0SM44QdIxIRbN0Z9wvtM/npNQvWPjvP9K8mkFN4sq
L5cWi8xWBKmByVKjjvhAImtPEaEAsjR6ZXZ0qtQQy6T3F4zArKRw6OZssDdztzsG
OW3+GrLep5OI0Ocf141cof1EMqfG+r2+0qya3sWmrP2UrwE1HcwiMlUicFHQF3yj
NoQj01OVyIS5EKWn9kHDI8rRHIHFulk=
=u/gz
-----END PGP MESSAGE-----"""

def test_information_fetching():
    """Test fetching of basic Keybase information from the server."""
    user = keybaseapi.User("max")
    assert user.real_name == "Max Krohn"
    assert user.fingerprint == "8EFBE2E4DD56B35273634E8F6052B2AD31A6631C"
    assert isinstance(user.public_key, pgp.TransferablePublicKey)

def test_proof_fetching():
    """Test fetching of proofs from the server."""
    user = keybaseapi.User("max")
    assert len(user.proofs.items()) == 10

def test_verification():
    """Test verification of the proofs fetched."""
    user = keybaseapi.User("max")
    assert user.verify_proofs()

def test_blind_verification():
    """Test trusting of keybase servers."""
    user = keybaseapi.User("max", trust_keybase=True)
    assert user.verify_proofs()

def test_verification_detached():
    """Test verification of a detached signature."""
    user = keybaseapi.User("eyes")
    assert user.verify_data(signed_data)

def test_verification_of_invalid_user():
    user = keybaseapi.User("mdshbduhysabdwyfvbw38yfgbwe7fbwy8fbw8f7bwe79fb3")
    assert not user.verify_proofs()

def test_verification_of_non_username():
    """Test verification of a user discovered via github:// or reddit://"""
    user_g = keybaseapi.User("github://maxtaco")
    user_r = keybaseapi.User("reddit://maxtaco")
    user_k = keybaseapi.User("max")
    assert user_g.public_key.fingerprint == user_r.public_key.fingerprint
    assert user_r.public_key.fingerprint == user_k.public_key.fingerprint
    assert user_g.raw_public_key == user_k.raw_public_key
    assert user_r.raw_public_key == user_k.raw_public_key
    assert user_g.verify_proofs()
    assert user_r.verify_proofs()
    assert user_k.verify_proofs()

@pytest.mark.xfail(raises=keybaseapi.UserNotFoundError)
def test_verification_of_invalid_external_user():
    """Test verification of a user that doesn't exist via github:// or reddit://"""
    user_r = keybaseapi.User("reddit://sidlib7")
    user_g = keybaseapi.User("github://dejwsdhh")


@pytest.mark.xfail
def test_verification_broken():
    """Test a broken signature."""
    user = keybaseapi.User("eyes")
    ns = list(signed_data)
    ns[107] = "q"
    ns = ''.join(ns)
    assert not user.verify_data(ns)
