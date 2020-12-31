

#ifndef FOURINAROW_LOGGER_H
#define FOURINAROW_LOGGER_H

#include <iostream>
#include "utility/Message.h"

using namespace std;

enum Verbose{
    NO_VERBOSE,
    VERBOSE,
    VERY_VERBOSE
};

    /////////////////////////////////////////////////////////////////////////////////////
    //                                                                                 //
    //                                   LOGGER                                        //
    //    Implements a simple Logger of three level of verbosity. It will be used      //
    //    in all the classes to organize the output of the program.                    //
    //                                                                                 //
    /////////////////////////////////////////////////////////////////////////////////////

class Logger{
    private:
        Verbose level;

    public:
        Logger( Verbose level );
        Logger operator<<(int value);
        Logger operator<<(unsigned int value);
        Logger operator<<(double value);
        Logger operator<<(bool value);
        Logger operator<<(char* value);
        Logger operator<<(unsigned char* value);
        Logger operator<<(const char* value);
        Logger operator<<(char value);
        Logger operator<<(string value);
        Logger operator<<(Verbose value);
        static void setThreshold(Verbose threshold);        //  set the global verbose threshold
        void flush();

};

static Logger base(NO_VERBOSE);         //  Logger for basic output(it will be showed everytime)
static Logger verbose(VERBOSE);         //  Logger for verbosing output(it will be showed only if threshold>=VERBOSE)
static Logger vverbose(VERY_VERBOSE);   //  Logger very verbosing output(it will be showed only if threshold=VERY_VERBOSE)

#endif //FOURINAROW_LOGGER_H
