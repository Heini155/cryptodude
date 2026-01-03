import json

import cryptodude_encrypt as cd


def test_nonce_length_small_message():
    # < 64 KiB => f=2 => nonce_len=13
    f = cd._sjcl_ccm_L_from_msg_len(10_000)
    assert f == 2
    assert (15 - f) == 13


def test_nonce_length_medium_message():
    # >= 2^(8*2)=65536 => f becomes 3 => nonce_len=12
    f = cd._sjcl_ccm_L_from_msg_len(70_000)
    assert f == 3
    assert (15 - f) == 12


def test_encrypt_outputs_valid_json_fields():
    params = cd.SjclParams(iter=200_000, ks=128, ts=128)
    obj = cd.encrypt_html_to_sjcl_json(b"<html>ok</html>", "pw", params=params)
    # Required SJCL fields
    for k in ("iv", "v", "iter", "ks", "ts", "mode", "adata", "cipher", "salt", "ct"):
        assert k in obj
    assert obj["mode"] == "ccm"
    assert obj["cipher"] == "aes"
    # JSON dumps roundtrip
    s = json.dumps(obj)
    obj2 = json.loads(s)
    assert obj2["ct"] == obj["ct"]
