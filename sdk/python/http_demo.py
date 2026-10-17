"""Localhost-only demonstration. Generates a fresh in-memory key every run."""
import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from lip4d import create_intent, sign_message_ed25519

HERE=Path(__file__).resolve()
REPO=HERE.parents[2]
GO=REPO/"guardian"/"go"
GUARDIAN="http://127.0.0.1:8765"
RESOURCE="http://127.0.0.1:8766"

def post(url,payload):
    data=json.dumps(payload,separators=(",",":")).encode()
    req=urllib.request.Request(url,data,{"Content-Type":"application/json"},method="POST")
    with urllib.request.urlopen(req,timeout=5) as response:
        return json.load(response)

def main():
    key=Ed25519PrivateKey.generate()
    pub=key.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)
    arg=base64.urlsafe_b64encode(pub).decode().rstrip("=")
    binary=os.environ.get("LIP4D_HTTPDEMO_BIN")
    command=[binary,"-agent-key",arg] if binary else ["go","run","./cmd/httpdemo","-agent-key",arg]
    proc=subprocess.Popen(command,cwd=GO,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    try:
        deadline=time.monotonic()+90
        while time.monotonic()<deadline:
            if proc.poll() is not None:
                raise RuntimeError("Go server exited before becoming available: "+proc.stderr.read().decode(errors="replace")[-3000:])
            try:
                intent=create_intent(issuer="spiffe://example.org/agent/a",audience="https://guardian.example.org",action="org.example.read",resource="https://api.example.org/record/1",purpose="Read authorised record",rationale="Local demo only",trust_domain="example.org")
                signed=sign_message_ed25519(intent,key,kid="local-demo-agent")
                challenge=post(GUARDIAN+"/begin",signed)
                break
            except urllib.error.HTTPError as exc:
                details=exc.read().decode("utf-8",errors="replace").strip()
                raise RuntimeError(f"Guardian HTTP {exc.code}: {details}") from exc
            except (urllib.error.URLError,TimeoutError,ConnectionError):
                time.sleep(.1)
        else: raise RuntimeError("Go server did not respond within 90 seconds; check port 8765 and the Go process log")
        # Attestation must bind to exactly the same intent and four dimensions.
        att={
            "lip_version":"0.3","message_type":"attestation",
            "message_id":"urn:uuid:cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            "in_reply_to":challenge["challenge_id"],"nonce":challenge["nonce"],
            "issuer":intent["issuer"],"audience":intent["audience"],
            "issued_at":intent["issued_at"],"expires_at":intent["expires_at"],
            "intent":intent["intent"],"dimensions":intent["dimensions"],
            "evidence":[{"type":"demo","format":"json","value":{"test_only":True}}]
        }
        grant=post(GUARDIAN+"/finish",{"challenge_id":challenge["challenge_id"],"attestation":sign_message_ed25519(att,key,kid="local-demo-agent")})
        resource_request={"grant":grant,"request":{"Subject":intent["issuer"],"Audience":"https://api.example.org","IntentDigest":__import__("lip4d").digest_intent(intent),"Action":intent["intent"]["action"],"Resource":intent["intent"]["resource"]}}
        print("First invocation:",post(RESOURCE+"/invoke",resource_request))
        try:
            post(RESOURCE+"/invoke",resource_request)
            raise RuntimeError("SECURITY FAILURE: replay accepted")
        except urllib.error.HTTPError as e:
            if e.code!=403:raise
            print("Replay denied: HTTP 403")
        print("Local demonstration succeeded; no normative LIP-4D grant is claimed.")
    finally:
        proc.terminate()
        try:proc.wait(timeout=3)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()

if __name__=="__main__":
    try:main()
    except Exception as exc:print("Demo error:",exc,file=sys.stderr);sys.exit(1)
