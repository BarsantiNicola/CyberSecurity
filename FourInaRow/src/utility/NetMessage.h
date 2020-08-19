
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
            unsigned int len;
            void myCopy( unsigned char* dest, unsigned char* source, int len );
        public:
            NetMessage(unsigned char* message , unsigned int length );  //  COSTRUCTOR FOR CONNECTION_MANAGER
            NetMessage(NetMessage& value);
            ~NetMessage();

            unsigned char* getMessage();                        //  GIVES THE CONTENT OF THE CLASS
            unsigned int length();                              //  GIVES THE LENGTH OF CONTENT
            static void test();                                 //  TEST FUNCTION
            NetMessage* giveWithLength();                       //  VERSION FOR EASY NET COMMUNICATION

    };

}
#endif //FOURINAROW_NETMESSAGE_H
