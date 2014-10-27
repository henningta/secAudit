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
    delete payload;
}

////////////////////////
Message::Message(){
}

Message::~Message(){

}

MessageState 
Message::get_p() {
  return p;
}
                                             
std::string 
Message::get_ID(){
  return ID;
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
MessageMaker::set_encrypt(std::string name, size_t len ,unsigned char * unencrypted, EVP_PKEY key){

}

void 
MessageMaker::set_sign(std::string name, size_t len ,unsigned char * unencrypted, EVP_PKEY key){

}

void 
MessageMaker::set(std::string name, size_t len ,unsigned char * unencrypted, EVP_PKEY key){}

void 
MessageMaker::clear_payload(){

}                                                        

Message 
MessageMaker::get_message(){
  return msg;
}

MessageMaker::MessageMaker(){


}
MessageMaker::~MessageMaker(){

}
