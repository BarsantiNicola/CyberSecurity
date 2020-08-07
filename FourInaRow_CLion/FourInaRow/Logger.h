
#ifndef FOURINAROW_LOGGER_H
#define FOURINAROW_LOGGER_H

#include <iostream>
#include "utility/NetMessage.h"

using namespace std;

enum Verbose{
    NO_VERBOSE,
    VERBOSE,
    VERY_VERBOSE
};

class Logger{
    private:
        Verbose level;                            //  verbose level of the Logger

    public:
        Logger( Verbose level );                  
        Logger operator<<(int value);             //  some ridefinitions for the operator <<, more will be added soon
        Logger operator<<(double value);
        Logger operator<<(bool value);
        Logger operator<<(char* value);
        Logger operator<<(unsigned char* value);
        Logger operator<<(const char* value);
        Logger operator<<(char value);
        Logger operator<<(string value);
        Logger operator<<(Verbose value);
        static void test();                       //  test module



};

extern Verbose threshold;                         //  global variable which defines the verbosity of the program, need just to be redefined to be used(example in the main.cpp)
static Logger base(NO_VERBOSE);                   //  global loggers to write in the three types of verbosity
static Logger verbose(VERBOSE);
static Logger vverbose(VERY_VERBOSE);

#endif //FOURINAROW_LOGGER_H
