
#ifndef FOURINAROW_CONVERTER_H
#define FOURINAROW_CONVERTER_H
#include "NetMessage.h"
#include "Message.h"

namespace utility{

    //////////////////////////////////////////////////////////////////////////////////////
    //                                                                                  //
    //                                   CONVERTER                                      //
    //    The class implements a series of statis methods to convert a Message class    //
    //    into a NetMessage one and viceversa. It performs a verification of the fields //
    //    to avoid the generation of incorrect messages.                                //
    //                                                                                  //
    //////////////////////////////////////////////////////////////////////////////////////

class Converter {

    private:
        static bool verifyMessage( MessageType type , Message message );                             //  verify the presence of all the needed fields
        static bool verifyCompact( MessageType type , Message message );                             //  verify the presence of all the needed fields for a compactMessage
        static bool checkField( const unsigned char* field, int len);                                //  verify a field doesn't contain &"
        static int computeNextField( NetMessage message , int position, Message* newMessage );       //  extract a field from the NetMessage string
        static bool setField( char fieldName, unsigned char* fieldValue , int len, Message* msg );   //  set a field extracted from a NetMessage string

    public:
        static NetMessage* encodeMessage(MessageType type , Message message );   //  translate a Message into a NetMessage basing on the given type, return NULL if it doesn't contain all the correct fields
        static Message* decodeMessage( NetMessage message );                     //  translate a NetMessage into a Message, it could fail if the NetMessage isn't properly formatted returning a NULL pointer
        static NetMessage* compactForm( MessageType type, Message message );     //  translate a Message in a more compact form to perform signatures and hashes, it's contained in a NetMessage just for semplicity to give content and its length
        static bool test();                                                      //  simple example of usage and testing of class functioning

};

}
#endif //FOURINAROW_CONVERTER_H
