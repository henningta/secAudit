#include "VerificationObject.hpp"
#include <stdexcept>
#include <iostream>
#include "cryptsuite.hpp"
#include "utils.hpp"
#include "Common.hpp"
#include <iostream> 
#include <fstream>  

extern FILE* fpErr;

//This one is a two parter to mimic the protocall
//Jackson Reed

//Part one verfies well formidness of log   
Message 
VerificationObject::verifyEntryStart(Log & log , int n){

  std::vector<LogEntry> logs =log.getEntries();
  std::vector<LogEntry>::iterator it = logs.begin();
  it++;
  int i =1;
  for (;it != logs.end(); ++it){
    if (i>n)//only verify entries up to n
      break;

    std::string msg = it->getYj();
    std::string check="";
    it--;
    std::string oldY= it->getYj();
    it++;
    check= Common::hashY(oldY,it->getEncryptedDj(),it->getEntryType());

    if(msg.compare(check)!=0){
      fprintf(fpErr, "Error: Hash of Enrty %d is bad.\n",i);

      throw std::runtime_error("Failed verification");
    } 
    i++;
  }   

  mkr.set_MessageState(MessageState::VER_N_START);
  mkr.clear_payload();
  mkr.set_ID(V_ID);

  std::string IDlog=log.getLogName();
  std::string p = numToString<int>(MessageState::VER_N_START);
  std::string f = numToString<int>(n);
  std::string Yf = logs.back().getYj();
  std::string Zf = logs.back().getZj();
  std::string Q = numToString<int>(n);

  mkr.set("IDlog",IDlog.length(),(unsigned char *)&IDlog[0]);
  mkr.set("p",p.length(),(unsigned char *)&p[0]);
  mkr.set("f",f.length(),(unsigned char *)&f[0]);
  mkr.set("Yf",Yf.length(),(unsigned char *)&Yf[0]);
  mkr.set("Zf",Zf.length(),(unsigned char *)&Zf[0]);
  mkr.set("Q",Q.length(),(unsigned char *)&Q[0]);

  return mkr.get_message();
}

Message
VerificationObject::verifyEntryTwo(Log & log ,Message m ,int n,unsigned char *keyN){


  unsigned char * unencrypt;
  std::string enc= log.getEntry(n).getEncryptedDj();
  size_t sizStr=
    cryptsuite::symDecrypt((unsigned char *)&enc[0], enc.length(),&unencrypt, keyN);
  std::string out((char * )unencrypt,sizStr);
  std::cout<<out<<"\n";


 return mkr.get_message();
}                  

Message 
VerificationObject::verifyAllStart(Log & log){
  std::vector<LogEntry> logs =log.getEntries();
  std::vector<LogEntry>::iterator it = logs.begin();
  it++;
  int i =1;
  for (;it != logs.end(); ++it){
    std::string msg = it->getZj();
    std::string check="";
    it--;
    std::string oldY= it->getYj();
    it++;
    check= Common::hashY(oldY,it->getEncryptedDj(),it->getEntryType());

    if(msg.compare(check)!=0){
      fprintf(fpErr, "Error: Hash of Enrty %d is bad.\n",i);
      throw std::runtime_error("Failed verification");
    }
    i++;
  }

 
  mkr.set_MessageState(MessageState::VER_START);
  mkr.clear_payload();
  mkr.set_ID(V_ID);

  std::string IDlog=log.getLogName();
  std::string p = numToString<int>(MessageState::VER_START);
  std::string f = numToString<int>(logs.size());
  std::string Yf = logs.back().getYj();
  std::string Zf = logs.back().getZj();
  std::string Q = numToString<int>(0);

  for (size_t i =1;i<logs.size();i++)
    Q=Q+","+numToString<int>(i);

  mkr.set("IDlog",IDlog.length(),(unsigned char *)&IDlog[0]);
  mkr.set("p",p.length(),(unsigned char *)&p[0]);
  mkr.set("f",f.length(),(unsigned char *)&f[0]);

  mkr.set("Yf",Yf.length(),(unsigned char *)&Yf[0]);
  mkr.set("Zf",Zf.length(),(unsigned char *)&Zf[0]);
  mkr.set("Q",Q.length(),(unsigned char *)&Q[0]);



  return mkr.get_message();
} 

Message
VerificationObject::verifyAllTwo(Log & log,Message status,
				 std::vector<unsigned char *> keys, 
				 std::string filename){


  
  std::filebuf fb;
  fb.open (filename.c_str(),std::ios::out);
  std::ostream os(&fb);


  std::vector<LogEntry> logs =log.getEntries();
  std::vector<LogEntry>::iterator it = logs.begin();
  std::vector<unsigned char *>::iterator key = keys.begin();

  for (;it != logs.end(); ++it){

    unsigned char * unencrypt;
    std::string enc= it->getEncryptedDj();
    size_t sizStr=
      cryptsuite::symDecrypt((unsigned char *)&enc[0]
			     ,enc.length(),&unencrypt, *key);
    std::string out((char * )unencrypt,sizStr);
    os<<out<<"\n";
    key++;
  } 
  fb.close();
  
 return mkr.get_message();
}


