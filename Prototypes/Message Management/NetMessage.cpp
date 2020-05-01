#include "NetMessage.h"

NetMessage::NetMessage( char* message , int messageLen ){
	
	this->len = messageLen;
	this->message = message;
	
}

char* NetMessage::getMessage(){
	return this->message;
}

int NetMessage::length(){
	return this->len;
}