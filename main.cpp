#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdexcept>
#include <iostream>
#include <exception>

#include "Log.hpp"
#include "utils.hpp"


const std::string help ="Usage:\n createlog <file-name.log>\n add <message_string>\n closelog \n verify <entry_no> \n verifyall <log-file-name.log> <out-file-name.txt>\n";

// travis henning
bool createLog(const std::string & logName) {
	Log log(logName);
	return log.open();
}

// jackson reed
void
do_command(std::string cmd) {


	std::size_t pos;
	if((pos=cmd.find("createlog")) != std::string::npos){
		std::vector<std::string> cmdTokens = split(cmd, ' ');
		if(cmdTokens.size() == 3){
			if(cmdTokens[0].find("-") == std::string::npos){
				std::cout<<help;
			} else {
				std::cout<<"createlog : "<<cmdTokens[2]<<"\n";
			}
		} else if(cmdTokens.size()==2) {
			if (createLog(cmdTokens[1])) {
				std::cout << "createlog : " << cmdTokens[1] << "\n";
			} else {
				std::cout << "Log creation failed.\n";
			}
		} else {
			std::cout<<help;
		}
	}
	else if ((pos=cmd.find("add"))!= std::string::npos) {
		std::vector<std::string> cmdTokens = split(cmd, ' ');
		if(cmdTokens.size()==3){
			if(cmdTokens[0].find("-")== std::string::npos){
				std::cout<<help;
			}
			else
				std::cout<<"add : "<<cmdTokens[2]<<"\n";
		}
		else if(cmdTokens.size()==2)
			std::cout<<"add : "<<cmdTokens[1]<<"\n";
		else
			std::cout<<help;
	}
	else if ((pos=cmd.find("closelog"))!= std::string::npos){
		std::cout<<"closelog\n";
	}
	else if ((pos=cmd.find("verify"))!= std::string::npos){
		std::vector<std::string> cmdTokens = split(cmd, ' ');
		std::cout<<"verify :"<<cmdTokens[2]<<"\n";
		if(cmdTokens.size()==3){
			if(cmdTokens[0].find("-")== std::string::npos){
				std::cout<<help;
			}

			else
				std::cout<<"verify : "<<cmdTokens[2]<<"\n";
		}
		else if(cmdTokens.size()==2)
			std::cout<<"verify : "<<cmdTokens[1]<<"\n";
		else
			std::cout<<help;

	}
	else if ((pos=cmd.find("verifyall"))!= std::string::npos){
		std::vector<std::string> cmdTokens = split(cmd, ' ');
		std::cout<<"verifyall : "<<cmdTokens[2]<<" "<<cmdTokens[3]<<"\n";
		if(cmdTokens.size()==4){
			if(cmdTokens[0].find("-")== std::string::npos){
				std::cout<<help;
			}

			else
				std::cout<<"verifyall : "<<cmdTokens[2]<<" "<<cmdTokens[3]<<"\n";
		}
		else if(cmdTokens.size()==3)
			std::cout<<"verifyall : "<<cmdTokens[1]<<" "<<cmdTokens[2]<<"\n";
		else
			std::cout<<help;
	}

	else{
		std::cout<<help;
		//throw (20);
	}

}

// jackson reed
int main (int argc, char **argv) {
	std::string cmd="";
	for(int i =1; i< argc; i++){
		cmd+=argv[i];
		cmd+=" ";
	}
	cmd = cmd.substr(0, cmd.size()-1);
	try{
		do_command(cmd);
	}
	catch(std::exception& e){
		std::cout<<e.what()<<"\n";
	}
	while (1){
		std::cout<<">";
		std::getline(std::cin,cmd);
		try{
			do_command(cmd);
		}
		catch(std::exception& e){
			std::cout<<e.what()<<"\n";
		}
	}

	exit (0);
}
