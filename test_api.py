import keybaseapi

def test_information_fetching():
    """Test fetching of basic Keybase information from the server."""
    user = keybaseapi.User("max")
    assert user.real_name == "Max Krohn"
    assert user.fingerprint == "8EFBE2E4DD56B35273634E8F6052B2AD31A6631C"

def test_proof_fetching():
    user = keybaseapi.User("max")
    assert len(user.proofs.items()) == 10

def test_verification():
    user = keybaseapi.User("max")
    assert user.verify_proofs()

def test_blind_verification():
    user = keybaseapi.User("max", trust_keybase=True)
    assert user.verify_proofs()
