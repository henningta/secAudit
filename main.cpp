// stl
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdexcept>
#include <iostream>
#include <exception>

// user
#include "Log.hpp"
#include "TrustedObject.hpp"
#include "UntrustedObject.hpp"
#include "utils.hpp"
#include "VerificationObject.hpp"

const std::string help ="Usage:\n createlog <file-name.log>\n add <message_string>\n closelog \n verify <entry_no> \n verifyall <log-file-name.log> <out-file-name.txt>\n";

/**
 * do_command
 *
 * Takes input from user and executes command
 *
 * @param 	cmd 	command to be executed
 * @param 	untrustedObject
 * @param 	trustedObject
 * @param 	verificationObject
 * @authors Jackson Reed, Travis Henning
 */
void do_command(
		std::string cmd,
		UntrustedObject & untrustedObject,
		TrustedObject & trustedObject,
		VerificationObject & verificationObject) {

  std::size_t pos;


  if((pos=cmd.find("createlog")) != std::string::npos){
    std::vector<std::string> cmdTokens = split(cmd, ' ');
    if(cmdTokens.size()==2) {
	Message M0 = untrustedObject.createLog(cmdTokens[1]);
	Message M1 = trustedObject.verifyInitMessage(M0);
	untrustedObject.verifyInitResponse(M1);
	std::cout << "Created " << cmdTokens[1] << "\n";
    }
    else {
      std::cout << help;
    }

  }

  else if ((pos=cmd.find("add")) != std::string::npos) {
    std::vector<std::string> cmdTokens = split(cmd, ' ');
    if(cmdTokens.size() == 2) {
      untrustedObject.addEntry(cmdTokens[1], LOG_ENTRY_APPEND);
      std::cout << "Added log entry number "
	+ numToString(untrustedObject.getNumEntries() - 1)
	+ "\n";
    }
    else {
      std::cout << help;
    }

  }

  else if ((pos=cmd.find("closelog")) != std::string::npos) {
    untrustedObject.closeLog();
    std::cout << "Closed " + untrustedObject.getLogName() + "\n";
  }


  else if ((pos=cmd.find("verifyall")) != std::string::npos) {


    std::vector<std::string> cmdTokens = split(cmd, ' ');
    if(cmdTokens.size()==3){
      std::cout << "verifyall : " << cmdTokens[1] << " " << cmdTokens[2] <<"\n";
      if (untrustedObject.logIsOpen()) {
		  std::cout << "Failed verification\n";
		  return;
	  }

	  Log lg;
      if (!lg.openExisting(cmdTokens[1])) {
		  std::cout << "Failed verification\n";
		  return;
	  }
      //int n=std::stoi(cmdTokens[1]);
      ClosedLogEntries closed = untrustedObject.getClosedLogEntries();

      Message resp=
	verificationObject.verifyAllStart(lg);
      std::vector<std::string> keys
	= trustedObject.verificationResponse(resp,lg,closed);
      verificationObject.verifyAllTwo(lg,resp,keys,cmdTokens[2]);

    }
    else {
      std::cout << help;
    }

  }

  else if ((pos=cmd.find("verify")) != std::string::npos) {
    std::vector<std::string> cmdTokens = split(cmd, ' ');

    if(cmdTokens.size() == 2) {
		if (!untrustedObject.logIsOpen()) {
			std::cout << "Failed verification\n";
			return;
		}

      Log &log =untrustedObject.getOpenedLog();
      int n=std::stoi(cmdTokens[1]);
      ClosedLogEntries closed = untrustedObject.getClosedLogEntries();
      Message resp=
	verificationObject.verifyEntryStart(log,n);
      std::vector<std::string> keys
	= trustedObject.verificationResponse(resp,log,closed);
      verificationObject.verifyEntryTwo(log,resp,n,
					(unsigned char *)&(keys[0][0]));

    }
    else {
      std::cout << help;
    }

  }




  else {
    std::cout << help;
  }
}

/**
 * main
 *
 * @authors Jackson Reed, Travis Henning
 */
int main (int argc, char **argv) {
  UntrustedObject untrustedObject;
  TrustedObject trustedObject;
  VerificationObject verificationObject;

  std::string cmd="";
  std::cout<<help;

  while (1){
    std::cout << ">";
    std::getline(std::cin,cmd);
    try{
      do_command(cmd, untrustedObject, trustedObject,
		 verificationObject);
    } catch(std::exception& e) {
      std::cout << e.what() << "\n";
    }
  }

  exit (0);
}
