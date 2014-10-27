#include "message.hpp"
#include <string.h>
#include <stdexcept>
//message.cpp
//Jackson Reed                                                            

////////////////////////////
PayLoad::PayLoad(){
  len=0;
}
PayLoad::~PayLoad(){
  if(len>0)
    free(payload);
}

////////////////////////
Message::Message(std::string ID, MessageState state){
  mP= state;
  mID=ID;
}

Message::Message(){
  //Not Used
}



Message::~Message(){
  //Not used
}

MessageState 
Message::get_p() {
  return mP;
}
                                             
std::string 
Message::get_ID(){
  return mID;
}
 
std::vector<unsigned char>  
Message::get_payload(std::string name){

  std::map<std::string, PayLoad>::iterator it = payloads.find(name);

  if(it == payloads.end()){
    throw std::invalid_argument(name);  
  }

  size_t leng=it->second.len;
  std::vector< unsigned char > ret(leng);
  memcpy(&ret[0],it->second.payload,leng);
  return ret;

}

int
Message::get_payload_size(std::string name){
  std::map<std::string, PayLoad>::iterator it = payloads.find(name);

  if(it == payloads.end()){
    throw std::invalid_argument(name);
  }

  return it->second.len;
}

////////////////////////


void 
MessageMaker::set_encrypt(std::string name, size_t leng ,unsigned char * unencrypted, EVP_PKEY *pkey){

  PayLoad pay;
  pay.len=cryptsuite::pkEncrypt( unencrypted, leng, &(pay.payload), pkey);
}

void 
MessageMaker::set_sign(std::string name, size_t leng ,unsigned char * unencrypted, EVP_PKEY *pkey){

  PayLoad pay;\
  pay.payload=(unsigned char *)malloc(sizeof(unsigned char)*leng);
  pay.len=(size_t)cryptsuite::createSignature( unencrypted , leng , pay.payload , pkey );

}

void 
MessageMaker::set(std::string name, size_t leng ,unsigned char * unencrypted){
  PayLoad pay;
  pay.payload=(unsigned char *)malloc(sizeof(unsigned char)*leng);
  memcpy(pay.payload,unencrypted,leng);
  pay.len=leng;
  msg.payloads[name]=pay;
}

void 
MessageMaker::clear_payload(){
  msg.payloads.clear();
}                                                        

Message 
MessageMaker::get_message(){
  return msg;
}

MessageMaker::MessageMaker(std::string ID,MessageState state){
  msg = Message(ID,state);  

}
MessageMaker::MessageMaker(){
  msg=Message("UNINITIALIZED",MessageState::UNINITIALIZED);
}

void
MessageMaker::set_ID(std::string ID){
  msg.mID =ID;
}

void
MessageMaker::set_MessageState(MessageState state){
  msg.mP=state;
}

MessageMaker::~MessageMaker(){
  //not used
}
