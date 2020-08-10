
#ifndef FOURINAROW_NETMESSAGE_H
#define FOURINAROW_NETMESSAGE_H

#include <ostream>
#include <cstring>
#include "../Logger.h"
namespace utility{

    /////////////////////////////////////////////////////////////////////////////////////
    //                                                                                 //
    //                                   NETMESSAGE                                    //
    //    The class is designed as a container for the string that the application     //
    //    needs to send. It permits easily to get the information and its length.      //
    //    It permits also to convert the class to the Message form to be easily readed //
    //    and modified.                                                                //
    //                                                                                 //
    /////////////////////////////////////////////////////////////////////////////////////

    class NetMessage {
        private:
            unsigned char* message;
            int len;
        public:
            NetMessage(unsigned char* message , int length );
            ~NetMessage();
            unsigned char* getMessage();
            int length();
            static void test();                                 //  test function
    };

}
#endif //FOURINAROW_NETMESSAGE_H
