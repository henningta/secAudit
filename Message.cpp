#include "Message.hpp"
#include "cryptsuite.hpp"
#include <string.h>
#include <stdexcept>
//Message.cpp
//Jackson Reed

////////////////////////////
PayLoad::PayLoad(){
	len=0;
}
PayLoad::~PayLoad(){

  //if(len>0)
    //delete(payload);
}

////////////////////////
Message::Message(std::string ID, MessageState state) {
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

Message::Message(const Message& other ){
  mP=other.mP;
  mID=other.mID;
  std::map<std::string, PayLoad>::const_iterator it = other.payloads.begin();
  for ( ;it!=other.payloads.end();it++ ){
    unsigned char * mem = (unsigned char *)new char[it->second.len];
    memcpy((void *)mem,it->second.payload,it->second.len);
    PayLoad py;
    py.len=it->second.len;
    py.payload=mem;
    payloads[it->first]=py;

  }


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
MessageMaker::set_pkencrypt(std::string name, size_t leng ,unsigned char * unencrypted, EVP_PKEY *pkey){

	PayLoad pay;
	pay.len=cryptsuite::pkEncrypt( unencrypted, leng, &(pay.payload), pkey);
	msg.payloads[name]=pay;
}

void
MessageMaker::set_symencrypt(std::string name, size_t leng,unsigned char * unencrypted, unsigned char *key){

	PayLoad pay;
	pay.len=cryptsuite::symEncrypt( unencrypted, leng, &(pay.payload), key);
	msg.payloads[name]=pay;
}

void
MessageMaker::set_sign(std::string name, size_t leng ,unsigned char * unencrypted, EVP_PKEY *pkey){

	PayLoad pay;

	if(cryptsuite::createSignature( unencrypted , leng , &(pay.payload) , pkey )) {
		pay.len = SIG_BYTES;
		msg.payloads[name]=pay;
	} else {
		pay.len = 0;
	}

}

void
MessageMaker::set(std::string name, size_t leng ,unsigned char * unencrypted){
	PayLoad pay;
	pay.payload=(unsigned char *)new char[leng+1];
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

MessageMaker::MessageMaker(std::string ID, MessageState state){
	msg = Message(ID, state);
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
