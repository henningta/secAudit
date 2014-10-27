#include "TrustedObject.hpp"


TrustedObject::TrustedObject(EVP_PKEY PublicKey,EVP_PKEY PrivateKey){
  //TODO:
}
//This is temporary so the code compiles, Dont use this                 
TrustedObject::TrustedObject(){
  //TODO:
}
//ID needs to be unique!                                                
void 
TrustedObject::addPublicKeys(std::string ID, std::string PublicKey){
  //TODO:

}
                             
Message TrustedObject::verifyInitMessage(Message M0){

  //TODO:
  return mkr.get_message();
}


