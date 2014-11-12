#include "VerificationObject.hpp"
#include <stdexcept>

extern FILE* fpErr;

//This one is a two parter to mimic the protocall
//Jackson Reed

//Part one verfies well formidness of log   
Message 
VerificationObject::verifyEntryStart(Log & log , int n){
  //1 v recives a copy done
  //2 v goes through the hash chain and assures that each entry is correct
  std::vector<LogEntry> logs =log.getEntries();
  std::vector<LogEntry>::iterator it = logs.begin();
  it++;
  int i =1;
  for (;it != logs.end(); ++it){
    if (i>n)//only verify entries up to n
      break;

    std::string msg = it->getZj();
    std::string check="";
    it--;
    std::string oldY= it->getYj();
    it++;
    check= hashY(oldY,it->getEncryptedDj(),it->getEntryType());

    if(msg.compare(check)!=0){
      fprintf(fpErr, "Error: Hash of Enrty %d is bad.\n",i);

      throw std::runtime_error("Bad Hash");
    } 
    i++;
  }   
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
    check= hashY(oldY,it->getEncryptedDj(),it->getEntryType());

    if(msg.compare(check)!=0){
      fprintf(fpErr, "Error: Hash of Enrty %d is bad.\n",i);
      throw std::runtime_error("Bad Hash");
    }
    i++;
  }

  //TODO: make message

  return mkr.get_message();
} 

Message
VerificationObject::verifyAllTwo(Log & log){
  return mkr.get_message();
}


