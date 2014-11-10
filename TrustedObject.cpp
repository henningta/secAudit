#include "TrustedObject.hpp"
#include <stdexcept>
#include "utils.hpp"
//This is temporary so the code compiles, Dont use this                 
TrustedObject::TrustedObject(){
  cryptsuite::loadRSAPublicKey(TRUSTED_PUB,&mPublic);
  cryptsuite::loadRSAPrivateKey(TRUSTED_PRIV,&mPrivate);
  mkr.set_ID(T_ID);
}
//ID needs to be unique!                                                
void 
TrustedObject::addPublicKeys(std::string ID, EVP_PKEY * PublicKey){
  keyTable[ID] = PublicKey;

}
                             
Message TrustedObject::verifyInitMessage(Message M0){
  
  std::vector< unsigned char > X0=M0.get_payload("X0");
  std::vector< unsigned char > SIGNSKuX0 = M0.get_payload("SIGNSKuX0");
  unsigned char * decrypt;
  unsigned char * sign;
  unsigned char * hash;

  size_t decLen = cryptsuite::pkDecrypt(&X0[0],X0.size(),&decrypt, mPrivate);
  cryptsuite::pkDecrypt(&SIGNSKuX0[0],SIGNSKuX0.size(),&sign, mPrivate);
  EVP_PKEY * key=keyTable[M0.get_ID()];
  if( !cryptsuite::verifySignature(decrypt, decLen, sign ,key)){
    throw std::runtime_error("Signature did not verify");
  }

  mkr.set_ID(T_ID);
  mkr.set_MessageState(MessageState::VER_INIT_RESP);
  mkr.clear_payload();
  
  std::string IDlog="TODO:";
  int hashLen = cryptsuite::calcMD(&X0[0],X0.size(),&hash);
  std::string HashX0 ( (char *)hash , hashLen);
  std::string X1 = ""+numToString< int >(MessageState::VER_INIT_RESP)+IDlog+HashX0;

  //TODO:verify Untrusted cert  std::vector< unsigned char > SIGNSKuX0 = M0.get_payload("Cu");

 
  delete hash;
  delete sign;
  delete decrypt;
  return mkr.get_message();
}


