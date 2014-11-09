#ifndef __MESSAGE_HPP__
#define __MESSAGE_HPP__

#include <map>
#include <string>
#include <memory>
#include <vector>
#include "cryptsuite.hpp"
//Jackson Reed




enum MessageState{ VER_INIT_REQ , VER_INIT_RESP , BAD_REQUEST , UNINITIALIZED };//this is refered to as "p" in the paper

class MessageMaker;
class PayLoad;

class Message {
  friend class MessageMaker;

private:
  MessageState mP;
  std::string mID;
  std::map<std::string, PayLoad> payloads;

public:
  MessageState get_p();
  Message(std::string ID, MessageState state);
  Message();
  std::string get_ID();
  std::vector< unsigned char >  get_payload(std::string name);
  int get_payload_size(std::string name);
  ~Message();
};


class MessageMaker{
public:
  //public key
  void set_encrypt(std::string name, size_t leng ,unsigned char * unencrypted, EVP_PKEY * pkey);

  void set_sign(std::string name, size_t leng ,unsigned char * unencrypted, EVP_PKEY * pkey);
  
  
  void set(std::string name, size_t leng ,unsigned char * unencrypted);
  void set_ID(std::string);
  void set_MessageState(MessageState);
  void clear_payload();
  Message get_message();
  //ID is the name of the fuction calling message maker
  MessageMaker(std::string ID, MessageState state);
  MessageMaker();
  ~MessageMaker();

private:
  Message msg;
};


class PayLoad{
  friend class MessageMaker;
  friend class Message;
public:
  ~PayLoad();
  PayLoad();
private:
  size_t len;
  unsigned char * payload;
};

#endif
