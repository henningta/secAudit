#ifndef __MESSAGE_HPP__
#define __MESSAGE_HPP__

#include<map>
#include<string>
#include <memory>
#include <vector>
#include"cryptsuite.hpp"
//Jackson Reed

enum MessageState{VER_INIT_REQ};//this is refered to as "p" in the paper

class MessageMaker;
class PayLoad;

class Message {
  friend class MessageMaker;

private:
  MessageState p;
  std::string ID;
  std::map<std::string, PayLoad> payloads;

public:
  MessageState get_p(); //enum?                                           
  Message();
  std::string get_ID();
  std::vector< unsigned char >  get_payload(std::string name);
  int get_payload_size(std::string name);
  ~Message();
};


class MessageMaker{
public:

  void set_encrypt(std::string name, size_t len ,unsigned char * unencrypted, EVP_PKEY key);
  void set_sign(std::string name, size_t len ,unsigned char * unencrypted, EVP_PKEY key);
  void set(std::string name, size_t len ,unsigned char * unencrypted, EVP_PKEY key);

  void clear_payload();
  Message get_message();
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
private:
  size_t len;
  unsigned char * payload;
  PayLoad();
};

#endif
