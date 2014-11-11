#include "Message.hpp"
#include "cryptsuite.hpp"
#include <string.h>
#include <stdexcept>
//Message.cpp
//Jackson Reed

////////////////////////
Message::Message(std::string ID, MessageState state) {
	mP= state;
	mID=ID;
}

Message::Message() {

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
	memcpy(&ret[0],it->second.payload.get(),leng);
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


int 
MessageMaker::set_pkencrypt(std::string name, size_t leng ,unsigned char * unencrypted, EVP_PKEY *pkey) {

	PayLoad pay;
	unsigned char * cp;
	if ( (pay.len = cryptsuite::pkEncrypt(unencrypted, leng, &cp, pkey)) > 0 ) {
		pay.payload.reset(cp);
		msg.payloads[name]=pay;
		return 1;

	} else {
		return 0;

	}
}

int
MessageMaker::set_symencrypt(std::string name, size_t leng,unsigned char * unencrypted, unsigned char *key) {

	PayLoad pay;
	unsigned char * cp;
	
	if ( (pay.len = cryptsuite::symEncrypt(unencrypted, leng, &cp, key)) > 0 ) {
		pay.payload.reset(cp);
		msg.payloads[name]=pay;
		return 1;

	} else {
		return 0;

	}
}

int
MessageMaker::set_sign(std::string name, size_t leng ,unsigned char * unencrypted, EVP_PKEY *pkey){

	PayLoad pay;
	unsigned char * cp;
	if ( cryptsuite::createSignature(unencrypted,leng , &cp , pkey) ) {
		pay.payload.reset(cp);
	  	pay.len = SIG_BYTES;
	  	msg.payloads[name]=pay;
		return 1;

	} else {
		return 0;

	}

}

void
MessageMaker::set(std::string name, size_t leng ,unsigned char * unencrypted){
	PayLoad pay;
	pay.payload.reset(new unsigned char[leng+1]());
	memcpy(pay.payload.get(),unencrypted,leng);
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
