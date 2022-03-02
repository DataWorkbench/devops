import urllib
import hmac
import json
import base64
import requests
from hashlib import sha256


def generate_signature(args, secret_access_key, path):

    quoted_ordered_args = "&".join(["=".join([urllib.quote(k), urllib.quote(str(args[k]))]) for k in sorted(args)])

    string_to_sign = "\n".join([
        "GET",
        path,
        quoted_ordered_args,
    ])

    print string_to_sign

    h = hmac.new(secret_access_key, digestmod=sha256)
    h.update(string_to_sign)
    sign = base64.b64encode(h.digest()).strip()
    signature = urllib.quote_plus(sign)

    string_args = quoted_ordered_args + "&" + "signature=" + signature

    return string_args


def send_request(action, params, access_key_id, api_server, zone=None, path="/iaas/"):
    a = {}

    a["action"] = action
    if zone:
        a["zone"] = zone

    a.update(params)

    string_args = generate_signature(a, access_key_id, path)

    u = api_server + path + "?" + string_args
    rsp = requests.get(u)
    if rsp.status_code == 200:
        return json.loads(rsp.content)

    return None
