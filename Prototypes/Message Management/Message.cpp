#include "Message.h"
#include <cstdlib>
#include <iostream>
#include <sys/time.h>
#include <cstring>

using namespace std;

Message::Message( MessageType t ){
	
	this->type = t;
	struct timeval tp;
	gettimeofday(&tp, NULL);
	timestamp = tp.tv_sec * 1000 + tp.tv_usec / 1000;
	
}

Message::Message( char* s , int len ){
	
	this->timestamp = 0;
	char *s2 = (char*)malloc(len-1);
	for( int a = 0; a<len-1;a++)
		s2[a] = s[a+1];
	if( s != NULL && len > 0 ){
		
		this->type = (MessageType)s[0];
		for( int a = 0; a<len-1;a++)
			if( this->timestamp == 0 )
				this->timestamp = (int)s2[a]-48;
			else
				this->timestamp = this->timestamp*10 + ((int)s2[a]-48);

	}
}

MessageType Message::getType(){
	return this->type;
}

long int Message::getTimeStamp(){
	return this->timestamp;
}

NetMessage* Message::stringify(){
	char *ret;
	char *stamp; 
	int len;
	string ss = to_string( timestamp);
	len = ss.length();
	stamp = (char*)malloc(len);
	stamp = strcpy(stamp,ss.c_str());
	len += 1;
	ret = (char*)malloc(len);
	ret[0] = (char)this->type;
	for(int a = 1;a<len;a++){
		ret[a] = ss[a-1];
	
	}
	return new NetMessage(ret,len);
}