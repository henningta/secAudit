#include "VerificationObject.hpp"

//This one is a two parter to mimic the protocall
//Jackson Reed
   
Message 
VerificationObject::verifyEntryStart(Log & log , int n){
  //1 v recives a copy done
  //2 v goes through the hash chain and assures that each entry is correct

  //3 generate message
  //4 form message with
  //p,  IDlog, f,yf,zf,n
  //5 return msg
  

  return mkr.get_message();
}

Message
VerificationObject::verifyEntryTwo(Log & log , int n){

 return mkr.get_message();
}                  

Message 
VerificationObject::verifyAllStart(Log & log){
  return mkr.get_message();
} 

Message
VerificationObject::verifyAllTwo(Log & log){
  return mkr.get_message();
}


