// Package guardian provides a fail-closed experimental intent evaluator.
// It does NOT issue LIP-4D grants or implement production JCS/JWS conformance.
package guardian

import (
 "crypto/ed25519"
 "crypto/sha256"
 "crypto/subtle"
 "encoding/base64"
 "encoding/json"
 "errors"
 "fmt"
 "strings"
 "time"
)

var ErrDenied=errors.New("intent rejected")
type Config struct {
 TrustedIssuer string
 Audience string
 PublicKey ed25519.PublicKey
 AllowedActions map[string]bool
 AllowedResourcePrefix string
 Now func() time.Time
}
type Decision struct { Allowed bool `json:"allowed"`; Reason string `json:"reason"` }
func deny(why string)(Decision,error){return Decision{Allowed:false,Reason:why},ErrDenied}

func Evaluate(raw []byte,c Config)(Decision,error){
 if len(raw)==0 || len(raw)>65536 {return deny("invalid message size")}
 if len(c.PublicKey)!=ed25519.PublicKeySize || c.TrustedIssuer=="" || c.Audience=="" || c.Now==nil || c.AllowedActions==nil || c.AllowedResourcePrefix=="" {return deny("guardian unconfigured")}
 var msg map[string]json.RawMessage
 if err:=json.Unmarshal(raw,&msg);err!=nil{return deny("malformed JSON")}
 // Reject duplicate keys and non-integer numbers: this narrow encoding profile
 // is not full RFC 8785. Do not claim cross-language conformance yet.
 if err:=strictShape(raw);err!=nil{return deny("unsupported JSON encoding")}
 value:=func(key string)string{var s string;_ = json.Unmarshal(msg[key],&s);return s}
 if value("lip_version")!="0.3"||value("message_type")!="intent"||value("issuer")!=c.TrustedIssuer||value("audience")!=c.Audience {return deny("envelope mismatch")}
 issued,err:=time.Parse(time.RFC3339Nano,value("issued_at"));if err!=nil{return deny("issued_at invalid")}
 expires,err:=time.Parse(time.RFC3339Nano,value("expires_at"));if err!=nil{return deny("expires_at invalid")}
 now:=c.Now()
 if now.Before(issued.Add(-30*time.Second))||!now.Before(expires)||!expires.After(issued)||expires.Sub(issued)>10*time.Minute{return deny("intent outside allowed validity")}
 var intent struct{ Action string `json:"action"`;Resource string `json:"resource"`;Purpose string `json:"purpose"` }
 if err:=json.Unmarshal(msg["intent"],&intent);err!=nil{return deny("intent invalid")}
 if !c.AllowedActions[intent.Action]||intent.Purpose==""||!strings.HasPrefix(intent.Resource,c.AllowedResourcePrefix){return deny("policy denied")}
 var dimensions map[string]json.RawMessage
 if err:=json.Unmarshal(msg["dimensions"],&dimensions);err!=nil{return deny("dimensions invalid")}
 for _,field:=range []string{"chronos","logos","topos","physis"}{if len(dimensions[field])==0{return deny("missing dimension")}}
 var proof struct { Type string `json:"type"`;JWS string `json:"jws"` }
 if err:=json.Unmarshal(msg["proof"],&proof);err!=nil||proof.Type!="jws-detached"{return deny("missing proof")}
 bits:=strings.Split(proof.JWS,".");if len(bits)!=3||bits[1]!=""{return deny("invalid detached JWS")}
 headerBytes,err:=base64.RawURLEncoding.DecodeString(bits[0]);if err!=nil{return deny("invalid JWS header")}
 var header struct{Alg string `json:"alg"`;Typ string `json:"typ"`;Kid string `json:"kid"`}
 if err:=json.Unmarshal(headerBytes,&header);err!=nil||header.Alg!="EdDSA"||header.Typ!="application/lip+json"||header.Kid=="" {return deny("disallowed JWS header")}
 sig,err:=base64.RawURLEncoding.DecodeString(bits[2]);if err!=nil{return deny("invalid signature encoding")}
 delete(msg,"proof")
 canonical,err:=json.Marshal(msg);if err!=nil{return deny("canonicalisation failed")}
 payload:=bits[0]+"."+base64.RawURLEncoding.EncodeToString(canonical)
 if !ed25519.Verify(c.PublicKey,[]byte(payload),sig){return deny("signature invalid")}
 // Future: validate chronos windows and challenge/grant lifecycle.
 return Decision{Allowed:true,Reason:"signature and configured basic policy accepted; no grant issued"},nil
}
// Utility for future digest binding tests; not used as a grant verifier.
func BindingDigest(binding any)(string,error){
 b,err:=json.Marshal(binding);if err!=nil{return "",err}
 h:=sha256.Sum256(b)
 return "sha-256:"+base64.RawURLEncoding.EncodeToString(h[:]),nil
}
func EqualDigest(a,b string)bool{
 if len(a)!=len(b)||!strings.HasPrefix(a,"sha-256:"){return false}
 return subtle.ConstantTimeCompare([]byte(a),[]byte(b))==1
}
// Allow only JSON without escapes and non-ASCII characters for the initial
// experimental canonicalisation profile. Reject unknown numeric encodings.
func strictShape(raw []byte)error {
 if !json.Valid(raw){return errors.New("invalid JSON")}
 for _,b:=range raw{if b>=128{return errors.New("non-ASCII JSON unsupported")}}
 // json.Unmarshal allows duplicate members, so use a recursive token scanner.
 dec:=json.NewDecoder(strings.NewReader(string(raw)));dec.UseNumber()
 if err:=checkValue(dec);err!=nil{return err}
 var extra any
 if dec.Decode(&extra)==nil{return errors.New("trailing data")}
 return nil
}
func checkValue(dec *json.Decoder)error{
 t,err:=dec.Token();if err!=nil{return err}
 switch v:=t.(type){
 case json.Delim:
  switch v {
  case '{':
   seen:=map[string]bool{}
   for dec.More(){
    k,err:=dec.Token();if err!=nil{return err}
    name,ok:=k.(string);if !ok||seen[name]{return errors.New("duplicate or invalid key")}
    seen[name]=true
    if err:=checkValue(dec);err!=nil{return err}
   }
   _,err:=dec.Token();return err
  case '[':
   for dec.More(){if err:=checkValue(dec);err!=nil{return err}}
   _,err:=dec.Token();return err
  default:return errors.New("unexpected delimiter")
  }
 case json.Number:
  text:=string(v)
  if strings.ContainsAny(text,".eE")||strings.HasPrefix(text,"-0"){return fmt.Errorf("unsupported numeric form")}
 }
 return nil
}
