package guardian

import (
 "errors"
 "sync"
 "testing"
 "time"
)
func challengeFixture(t *testing.T)(*Challenges,VerifiedIntent,Challenge,*time.Time){
 t.Helper()
 now:=time.Date(2026,10,17,20,0,0,0,time.UTC)
 store,err:=NewChallenges(func()time.Time{return now},time.Minute)
 if err!=nil{t.Fatal(err)}
 intent:=VerifiedIntent{ID:"urn:uuid:11111111-1111-4111-8111-111111111111",Issuer:"spiffe://example.org/agent/a",Audience:"https://guardian.example.org",Digest:"sha-256:fixture"}
 ch,err:=store.Issue(intent);if err!=nil{t.Fatal(err)}
 return store,intent,ch,&now
}
func matching(i VerifiedIntent,c Challenge)VerifiedAttestation{
 return VerifiedAttestation{InReplyTo:c.ID,Issuer:i.Issuer,Audience:i.Audience,Digest:i.Digest,Nonce:c.Nonce,Evidence:[]byte("verified-example")}
}
func allowEvidence(_ VerifiedIntent,a VerifiedAttestation)error {
 if string(a.Evidence)!="verified-example"{return errors.New("bad evidence")}
 return nil
}
func TestChallengeSuccessAndReplayDenial(t *testing.T){
 s,i,c,_:=challengeFixture(t)
 if err:=s.Consume(c.ID,matching(i,c),allowEvidence);err!=nil{t.Fatal(err)}
 if err:=s.Consume(c.ID,matching(i,c),allowEvidence);!errors.Is(err,ErrChallengeInvalid){t.Fatalf("replay accepted: %v",err)}
}
func TestChallengeMismatchConsumes(t *testing.T){
 for _,change:=range []func(*VerifiedAttestation){
  func(a *VerifiedAttestation){a.Nonce="wrong"},
  func(a *VerifiedAttestation){a.Digest="wrong"},
  func(a *VerifiedAttestation){a.Issuer="wrong"},
  func(a *VerifiedAttestation){a.Audience="wrong"},
  func(a *VerifiedAttestation){a.InReplyTo="wrong"},
 }{
  s,i,c,_:=challengeFixture(t)
  a:=matching(i,c);change(&a)
  if err:=s.Consume(c.ID,a,allowEvidence);!errors.Is(err,ErrChallengeInvalid){t.Fatalf("mismatch accepted: %v",err)}
  if err:=s.Consume(c.ID,matching(i,c),allowEvidence);!errors.Is(err,ErrChallengeInvalid){t.Fatalf("mismatch did not consume: %v",err)}
 }
}
func TestChallengeExpiry(t *testing.T){
 s,i,c,now:=challengeFixture(t)
 *now=now.Add(time.Minute)
 if err:=s.Consume(c.ID,matching(i,c),allowEvidence);!errors.Is(err,ErrChallengeInvalid){t.Fatalf("expiry accepted: %v",err)}
}
func TestVerifierRequiredAndOneTime(t *testing.T){
 s,i,c,_:=challengeFixture(t)
 if err:=s.Consume(c.ID,matching(i,c),nil);!errors.Is(err,ErrEvidenceDenied){t.Fatal(err)}
 if err:=s.Consume(c.ID,matching(i,c),allowEvidence);err!=nil{t.Fatal("nil verifier should not consume challenge")}
 s,i,c,_=challengeFixture(t)
 if err:=s.Consume(c.ID,matching(i,c),func(VerifiedIntent,VerifiedAttestation)error{return errors.New("denied")});!errors.Is(err,ErrEvidenceDenied){t.Fatal(err)}
 if err:=s.Consume(c.ID,matching(i,c),allowEvidence);!errors.Is(err,ErrChallengeInvalid){t.Fatal("denial must consume")}
}
func TestDuplicateOutstanding(t *testing.T){
 s,i,_,_:=challengeFixture(t)
 if _,err:=s.Issue(i);!errors.Is(err,ErrChallengeInvalid){t.Fatal(err)}
}
func TestConcurrentConsumptionOnlyOnce(t *testing.T){
 s,i,c,_:=challengeFixture(t)
 var wg sync.WaitGroup
 successes:=make(chan bool,20)
 for k:=0;k<20;k++{wg.Add(1);go func(){defer wg.Done();successes<-s.Consume(c.ID,matching(i,c),allowEvidence)==nil}()}
 wg.Wait();close(successes)
 n:=0;for ok:=range successes{if ok{n++}}
 if n!=1{t.Fatalf("expected one consumer, got %d",n)}
}
