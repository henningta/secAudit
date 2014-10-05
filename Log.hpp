#ifndef __LOG_HPP__
#define __LOG_HPP__

#include "Message.hpp"

class Log {
public:
	void open();
	void close();
	void append(Message & message);
};

#endif // __LOG_HPP__
