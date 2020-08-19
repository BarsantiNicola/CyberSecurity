#include "NetMessage.h"

namespace utility {

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                   COSTRUCTORS/DESTRUCTORS                                 //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////


    //  costructor for generation of a NetMessage starting from the byte array received by the Connection Manager
    NetMessage::NetMessage(unsigned char *mess, unsigned int length) {

        if( !mess || length == 0 ){

            verbose << "-->[NetMessage][Costructor] Error invalid arguments. Operation Aborted" << '\n';
            this->message = nullptr;
            this->len = 0;
            return;

        }

        vverbose<<"-->[NetMessage][Costructor] Generation of message: "<<mess<<'\t'<<" LEN: "<<length<<'\n';
        this->message = new unsigned char[length];
        if( this->message ) {

            myCopy( this->message,  mess, length);
            this->len = length;
            vverbose << "-->[NetMessage][Costructor] Message generated" << '\n';

        }else {

            this->message = nullptr;
            this->len = 0;
            verbose << "-->[NetMessage][Costructor] Error during the allocation of memory. Operation Aborted." << '\n';

        }

    }

    //  costructor to allow the passage of NetMessage as a non-pointer function argument
    NetMessage::NetMessage(NetMessage& value ){

        if( !value.getMessage() ){
            vverbose << "-->[NetMessage][Costructor] Message generated" << '\n';
            this->message = nullptr;
            this->len = 0;
            return;
        }

        this->message = new unsigned char[value.length()];
        if( this->message ) {

            myCopy(this->message, value.getMessage(), value.length());
            this->len = value.length();
            vverbose << "-->[NetMessage][Costructor] Message generated" << '\n';

        }else
            verbose <<"-->[NetMessage][Costructor] Error during the allocation of memory. Operation Aborted."<<'\n';

    }

    void NetMessage::myCopy( unsigned char* dest, unsigned char* source, int len ){

        for( int a = 0; a<len;a++ )
            dest[a] = source[a];

    }

    NetMessage::~NetMessage(){

        delete[] this->message;
        vverbose<<"-->[NetMessage][Destructor] Message destroyed"<<'\n';

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                            GETTERS                                        //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  return the content of the netmessage as an unsigned char* array
    unsigned char* NetMessage::getMessage(){

        if( !this->message || !this->len ) return nullptr;

        unsigned char* ret = new unsigned char[this->len];
        myCopy( ret,  this->message , this->len);

        return ret;

    }

    //  return the length of the getMessage unsigned char* array
    unsigned int NetMessage::length(){

        return this->len;

    }

    void myCopy( unsigned char* dest, unsigned char* source, int len ){

        for( int a = 0; a<len;a++ )
            dest[a] = source[a];

    }

    NetMessage* NetMessage::giveWithLength(){

        unsigned int newLen = this->len+to_string(this->len).length()+1;
        int numberLen = to_string(this->len).length();
        unsigned char* newMsg = new unsigned char[this->len+numberLen+1];

        for( int a = 0; a<newLen; a++ )
            newMsg[a] = '\0';

        myCopy( newMsg , (unsigned char*)to_string(this->len).c_str(), numberLen);
        newMsg[numberLen++] = '%';

        for( int a = 0; a<this->len; a++ )
            newMsg[a+numberLen] = this->message[a];

        NetMessage* ret =  new NetMessage( newMsg , newLen );
        delete[] newMsg;

        return ret;

    }


    //  function with an example of usage of the class which performs a test for its correctness
    void NetMessage::test(){

        NetMessage msg((unsigned char*)"messaggio di prova" , strlen("messaggio di prova"));
        base<<"CONTENT: " << msg.getMessage()<<" LENGTH: "<<msg.length()<<'\n';

    }

}