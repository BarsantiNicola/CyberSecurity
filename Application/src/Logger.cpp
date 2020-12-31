

#include "Logger.h"

static Verbose threshold = VERY_VERBOSE;

void Logger::setThreshold( Verbose t){
    threshold = t;
}
Logger::Logger( Verbose level ){
    this->level = level;
}

void Logger::flush(){

    cout.flush();

}

Logger Logger::operator<<(int value){

    if( this->level == VERBOSE  && threshold >= this->level ) {
        cout << "\033[0;31m" << value << "\033[0m";
        return *this;
    }

    if( threshold >= this->level  )
        cout<<value;
    return *this;
}

Logger Logger::operator<<(double value){

    if( this->level == VERBOSE  && threshold >= this->level ) {
        cout << "\033[0;31m" << value << "\033[0m";
        return *this;
    }

    if( threshold >= this->level  )
        if( value )
            cout<<value;
        else
            cout<<value;
    return *this;
}

Logger Logger::operator<<(bool value){

    if( this->level == VERBOSE  && threshold >= this->level ) {
        cout << "\033[0;31m" << value << "\033[0m";
        return *this;
    }

    if( threshold >= this->level  )
        if( value )
            cout<<"true";
        else
            cout<<"false";
    return *this;
}

Logger Logger::operator<<(unsigned int value){

    if( this->level == VERBOSE  && threshold >= this->level ) {
        cout << "\033[0;31m" << value << "\033[0m";
        return *this;
    }

    if( threshold >= this->level  )
        if( value )
            cout<<value;
        else
            cout<<value;
    return *this;
}

Logger Logger::operator<<(Verbose value){

    if( this->level == VERBOSE  && threshold >= this->level ) {
        cout << "\033[0;31m" << value << "\033[0m";
        return *this;
    }

    if( threshold >= this->level  )
        switch(value){
            case NO_VERBOSE:   cout<<"NO_VERBOSE";
                               break;
            case VERBOSE:      cout<<"VERBOSE";
                               break;
            case VERY_VERBOSE: cout<<"VERY_VERBOSE";
                               break;
            default:           cout<<"UNKNOWN";
                               break;
        }

    return *this;
}

Logger Logger::operator<<(unsigned char* value){

    if( this->level == VERBOSE  && threshold >= this->level ) {
        cout << "\033[0;31m" << value << "\033[0m";
        return *this;
    }

    if( threshold >= this->level )
        cout<<value;
    return *this;
}

Logger Logger::operator<<(char* value){

    if( this->level == VERBOSE  && threshold >= this->level ) {
        cout << "\033[0;31m" << value << "\033[0m";
        return *this;
    }
    if( threshold >= this->level )
        cout<<value;
    return *this;
}

Logger Logger::operator<<(char value){

    if( this->level == VERBOSE  && threshold >= this->level ) {
        cout << "\033[0;31m" << value << "\033[0m";
        return *this;
    }

    if( threshold >= this->level )
        cout<<value;
    return *this;
}

Logger Logger::operator<<(string value){

    if( this->level == VERBOSE  && threshold >= this->level ) {
        cout << "\033[0;31m" << value << "\033[0m";
        return *this;
    }

    if( threshold >= this->level )
        cout<<value;
    return *this;
}

Logger Logger::operator<<(const char* value){

    if( this->level == VERBOSE  && threshold >= this->level ) {
        cout << "\033[0;31m" << value << "\033[0m";
        return *this;
    }

    if( threshold >= this->level  )
        cout<<value;
    return *this;
}









