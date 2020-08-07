
#ifndef NET_MESSAGE
#define NET_MESSAGE

namespace utility{
	

	class NetMessage{
	
	private:
		unsigned char* message;
		int len;

	public:
		NetMessage( unsigned char* MESSAGE , int LENGTH );
		unsigned char* getMessage();
		int length();

	};

}

#endif
