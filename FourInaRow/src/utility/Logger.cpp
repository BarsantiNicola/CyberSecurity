#include "Logger.h"

	
namespace utility {

	Logger::Logger( Verbose level ){
		this->level = level;
	}
	
	template <typename T> 
		Logger Logger::operator<<(T value){
			if( threshold < level )
				cout<<"-->["<<this->name<<"] "<<value;
			return *this;
		}
	
}




