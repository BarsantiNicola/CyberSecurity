

#include "Logger.h"

static Verbose threshold = VERY_VERBOSE;

void Logger::setThreshold( Verbose t){
    threshold = t;
}
Logger::Logger( Verbose level ){
    this->level = level;
}

Logger Logger::operator<<(int value){

    if( threshold >= this->level  )
        cout<<value;
    return *this;
}

Logger Logger::operator<<(double value){

    if( threshold >= this->level  )
        if( value )
            cout<<value;
        else
            cout<<value;
    return *this;
}

Logger Logger::operator<<(bool value){

    if( threshold >= this->level  )
        if( value )
            cout<<"true";
        else
            cout<<"false";
    return *this;
}

Logger Logger::operator<<(Verbose value){

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

    if( threshold >= this->level )
        cout<<value;
    return *this;
}

Logger Logger::operator<<(char* value){
    if( threshold >= this->level )
        cout<<value;
    return *this;
}

Logger Logger::operator<<(char value){
    if( threshold >= this->level )
        cout<<value;
    return *this;
}

Logger Logger::operator<<(string value){
    if( threshold >= this->level )
        cout<<value;
    return *this;
}

Logger Logger::operator<<(const char* value){

    if( threshold >= this->level  )
        cout<<value;
    return *this;
}

void Logger::test(){

    Logger::setThreshold( NO_VERBOSE );
    base << "Test very_verbose"<<'\n';
    base <<"\t---BASE OK"<<'\n';
    verbose <<"\t---VERBOSE OK"<<'\n';
    vverbose <<"\t---VERY VERBOSE OK"<<'\n';
    Logger::setThreshold( VERBOSE );
    base << "Test verbose"<<'\n';
    base <<"\t---BASE OK"<<'\n';
    verbose <<"\t---VERBOSE OK"<<'\n';
    vverbose <<"\t---VERY VERBOSE ERROR"<<'\n';
    Logger::setThreshold( VERY_VERBOSE);
    base << "Test no verbose"<<'\n';
    base <<"\t---BASE OK"<<'\n';
    verbose <<"\t---VERBOSE ERROR"<<'\n';
    vverbose <<"\t---VERY VERBOSE ERROR"<<'\n';

}







