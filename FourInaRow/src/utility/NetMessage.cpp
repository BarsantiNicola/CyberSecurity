#include "NetMessage.h"

namespace utility{
	
	NetMessage::NetMessage( unsigned char* message, int length ){

		this->message = message;
		this->len = len;
		
	}

	unsigned char* NetMessage::getMessage(){
		return this->message;
	}
	
	int NetMessage::length(){
		return this->len;
	}
	
}
