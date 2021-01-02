
#ifndef FOURINAROW_NETMESSAGE_H
#define FOURINAROW_NETMESSAGE_H

#include <ostream>
#include <cstring>
#include "../Logger.h"

namespace utility{

    //////////////////////////////////////////////////////////////////////////////////////
    //                                                                                  //
    //                                   NETMESSAGE                                     //
    //    The class is designed as a container for the messages which needs to be sent  //
    //    on the network. All the lower-level function which works with the network     //
    //    expect this class as a content to be sent or received. In conjunction with    //
    //    the utility::Converter class permits to easily transform a utility::Message   //
    //    to utility::NetMessage and vice-versa. This permits to give an easy access to //
    //    the content of a message from the upper level functions(utility::Message) and //
    //    separate it from the lower-level structural needs.                            //
    //                                                                                  //
    //    FOR MESSAGE/NETMESSAGE CONVERTION LOOK AT utility::Converter                  //
    //                                                                                  //
    //////////////////////////////////////////////////////////////////////////////////////

    class NetMessage {

        private:

            unsigned char* message;                                             //  CONTENT OF NETMESSAGE
            unsigned int len;                                                   //  LENGTH OF NETMESSAGE CONTENT

            void myCopy( unsigned char* dest, unsigned char* source, int len ); //  UTILITY FUNCTION SIMILAR TO MEMSET

        public:

            //  CONSTRUCTORS & DESTRUCTORS
            NetMessage(unsigned char* message , unsigned int length );
            NetMessage(NetMessage& value);                              //  COPY-CONSTRUCTOR
            ~NetMessage();

            //  GETTERS
            unsigned char* getMessage();                                //  GIVES THE CONTENT OF THE CLASS
            unsigned int length();                                      //  GIVES THE LENGTH OF CONTENT

    };

}
#endif //FOURINAROW_NETMESSAGE_H
