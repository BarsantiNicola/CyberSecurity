#include "NetMessage.h"

namespace utility {

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                   COSTRUCTORS/DESTRUCTORS                                 //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////


    //  costructor for the generation of a NetMessage starting from a byte array
    NetMessage::NetMessage( unsigned char *mess, unsigned int length ) {

        //  verification of arguments validity
        if( !mess || length<1 ){

            verbose << "--> [NetMessage][Costructor] Error invalid arguments. Empty netmessage generated" << '\n';
            this->message = nullptr;
            this->len = 0;
            return;

        }

        try {

            this->message = new unsigned char[length];
            myCopy( this->message,  mess, length);
            this->len = length;

            vverbose << "--> [NetMessage][Costructor] Message correctly generated: [\t";
            for( int a = 0; a<len; a++ )
                vverbose<<this->message[a];
            vverbose<<"\t]\n";


        }catch( bad_alloc e ){

            this->message = nullptr;
            this->len = 0;
            verbose << "--> [NetMessage][Costructor] Error during the allocation of memory. Empty netmessage generated" << '\n';

        }

    }

    //  copy-constructor
    NetMessage::NetMessage( NetMessage& value ){

        //  verification of arguments validity
        if( !value.getMessage() ){

            verbose << "--> [NetMessage][Costructor] Invalid arguments, empty netmessage generated" << '\n';
            this->message = nullptr;
            this->len = 0;
            return;

        }

        try{

            this->message = new unsigned char[value.length()];
            myCopy(this->message, value.getMessage(), value.length());
            this->len = value.length();

        }catch( bad_alloc e ){

            this->message = nullptr;
            this->len = 0;
            verbose << "--> [NetMessage][Costructor] Error during the allocation of memory. Empty netmessage generated" << '\n';

        }

    }

    //  utility function similar to std::memset
    void NetMessage::myCopy( unsigned char* dest, unsigned char* source, int len ){

        //  verification of arguments validity. No control is needed on len(function resilient to len<=0)
        if( !dest || !source ){

            verbose << "--> [NetMessage][Costructor] Error invalid arguments. Operation Aborted" << '\n';
            return;

        }

        for( int a = 0; a<len; a++ )
            dest[a] = source[a];

    }

    NetMessage::~NetMessage(){

        if( this->message )
            delete[] this->message;

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                            GETTERS                                        //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  return the content of the netmessage as an unsigned char* array
    unsigned char* NetMessage::getMessage(){

        //  verification of used variables
        if( !this->message || !this->len ) return nullptr;

        try {

            unsigned char *ret = new unsigned char[this->len];
            myCopy( ret, this->message, this->len );
            return ret;

        }catch( bad_alloc e ){

            verbose << "--> [NetMessage][getMessage] Error during the allocation of memory. Empty message given" << '\n';
            return nullptr;

        }

    }

    //  return the length of the getMessage unsigned char* array
    unsigned int NetMessage::length(){

        return this->len;

    }

}