
#ifndef NET_MESSAGE_H
#define NET_MESSAGE_H

class NetMessage{
	
	private: 
		char* message;
		int   len;
		
	public:
		NetMessage( char* message , int messageLength );
		char* getMessage();
		int length();
};
#endif