package guardian

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "testing"
 "time"
)

func TestNestedKeysCanonicalizedForPythonSignature(t *testing.T) {
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 bare:=map[string]any{
  "lip_version":"0.3","message_type":"intent","message_id":"urn:uuid:11111111-1111-4111-8111-111111111111",
  "issuer":"spiffe://example.org/agent/a","audience":"https://guardian.example.org",
  "issued_at":"2026-10-17T20:00:00Z","expires_at":"2026-10-17T20:02:00Z",
  "intent":map[string]any{"resource":"https://api.example.org/item/1","purpose":"demo","action":"read","parameters":map[string]any{"z":2,"a":1}},
  "dimensions":map[string]any{"topos":map[string]any{"trust_domain":"example.org"},"physis":map[string]any{"revision":1},"logos":map[string]any{"rationale":"demo"},"chronos":map[string]any{"sequence":1}},
 }
 header:=base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"demo","typ":"application/lip+json"}`))
 canonical,err:=json.Marshal(bare);if err!=nil{t.Fatal(err)}
 signature:=ed25519.Sign(priv,[]byte(header+"."+base64.RawURLEncoding.EncodeToString(canonical)))
 bare["proof"]=map[string]any{"type":"jws-detached","jws":header+".."+base64.RawURLEncoding.EncodeToString(signature)}
 // Deliberately send the nested keys in a different order from signing.
 raw:=[]byte(`{"proof":`+mustJSON(t,bare["proof"])+`,"issuer":"spiffe://example.org/agent/a","audience":"https://guardian.example.org","lip_version":"0.3","message_type":"intent","message_id":"urn:uuid:11111111-1111-4111-8111-111111111111","issued_at":"2026-10-17T20:00:00Z","expires_at":"2026-10-17T20:02:00Z","intent":{"purpose":"demo","parameters":{"z":2,"a":1},"resource":"https://api.example.org/item/1","action":"read"},"dimensions":{"topos":{"trust_domain":"example.org"},"physis":{"revision":1},"logos":{"rationale":"demo"},"chronos":{"sequence":1}}}`)
 cfg:=Config{TrustedIssuer:"spiffe://example.org/agent/a",Audience:"https://guardian.example.org",PublicKey:pub,AllowedActions:map[string]bool{"read":true},AllowedResourcePrefix:"https://api.example.org/",Now:func()time.Time{return time.Date(2026,10,17,20,1,0,0,time.UTC)}}
 d,err:=Evaluate(raw,cfg);if err!=nil||!d.Allowed{t.Fatalf("reordered signed nested fields rejected: %v %+v",err,d)}
}
func mustJSON(t *testing.T,v any) string {t.Helper();b,e:=json.Marshal(v);if e!=nil{t.Fatal(e)};return string(b)}
