
#ifndef FOURINAROW_CONVERTER_H
#define FOURINAROW_CONVERTER_H

#include "NetMessage.h"
#include "Message.h"

namespace utility{

    //////////////////////////////////////////////////////////////////////////////////////
    //                                                                                  //
    //                                   CONVERTER                                      //
    //    The class implements a series of statics methods to convert a utility::Message//
    //    class into a utility::NetMessage class and vice-versa.                        //
    //    It also performs a verification of the presence of all the necessary fields   //
    //    to avoid the generation of incorrect messages and verify their content to     //
    //    sanitize tainted data.                                                        //
    //                                                                                  //
    //////////////////////////////////////////////////////////////////////////////////////

class Converter {

    private:
        static int writeField( unsigned char* value , char fieldTag , unsigned char* field , int len , int pos , bool finish );   //  function to concatenate the field of a message with an identifier to generate the netMessage
        static int writeCompactField( unsigned char* value , unsigned char* field , int len , int pos , bool finish );            //  function to concatenate the field of a message to generate a string
        static bool verifyMessage( MessageType type , Message message );                             //  verify the presence of all the needed fields to generate a utility::NetMessage
        static bool verifyCompact( MessageType type , Message message );                             //  verify the presence of all the needed fields for a compactMessage
        static bool checkField( const unsigned char* field, int len, bool sanitize );                //  verify a field doesn't contain &" and eventually sanitizes its content
        static int computeNextField( NetMessage message , int position, Message* newMessage );       //  extract a field from the NetMessage string
        static bool setField( char fieldName, unsigned char* fieldValue , int len, Message* msg );   //  set a field extracted from a NetMessage string into a Message
        static unsigned char* concTwoField(unsigned char* firstField,unsigned int firstFieldSize,unsigned char* secondField,unsigned int secondFieldSize,unsigned char separator,unsigned int numberSeparator);  //  concatenate two fields(used by AES)
        static bool sanitize( char value );                 //  using a whitelist verify the character is allowed

    public:
        static NetMessage* encodeMessage(MessageType type , Message message );   //  translate a Message into a NetMessage basing on the given type, return NULL if it doesn't contain all the correct fields
        static Message* decodeMessage( NetMessage message );                     //  translate a NetMessage into a Message, it could fail if the NetMessage isn't properly formatted returning a NULL pointer
        static NetMessage* compactForm( MessageType type, Message message );     //  translate a Message in a more compact form to perform signatures and hashes, it's contained in a NetMessage just for semplicity to give content and its length
        static NetMessage* compactForm( MessageType type, Message message, int* lengthPlaintext );  // generates two string, one for the plan fields and the other for the fields which need to be encrypted(used by AES)

};

}
#endif //FOURINAROW_CONVERTER_H
