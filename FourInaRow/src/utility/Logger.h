#ifndef LOGGER
#define LOGGER

#include <iostream>
using namespace std;

namespace utility{

	enum Verbose{
		NO_VERBOSE,
		VERBOSE,
		VERY_VERBOSE
	} threshold;
	
	class Logger{
		private:
			Verbose level;
			string name;

		public:
			Logger( Verbose level );
			template <typename T> 
			Logger operator<<(T value);
	};
}
	
#endif

