

#ifndef MESSAGE_H
#define MESSAGE_H

#include "NetMessage.h"
#include "MessageType.h"

class Message{
	
	private: 
		MessageType type;
		
	public:
		Message( MessageType );
		Message( char* ,int );
		NetMessage* stringify();
		MessageType getType();
		
};

#endif