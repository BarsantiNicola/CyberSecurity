#include "Message.h"
#include <cstdlib>
Message::Message( MessageType t ){
	
	this->type = t;
	
}

Message::Message( char* s , int len ){
	if( s != NULL && len > 0 ){
		this->type = (MessageType)s[0];
	}
}

MessageType Message::getType(){
	return this->type;
}

NetMessage* Message::stringify(){
	char *ret;
	ret = (char*)malloc(1);
	*ret = (char)this->type;
	return new NetMessage(ret,1);
}