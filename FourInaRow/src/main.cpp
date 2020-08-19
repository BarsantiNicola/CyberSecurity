#include <iostream>
#include "cipher/CipherRSA.h"
#include "Logger.h"
#include "utility/Message.h"
#include "utility/NetMessage.h"
#include "utility/Converter.h"
using namespace utility;



    int main() {

        Logger::setThreshold( VERBOSE );
        base<<"------------------------------------------------------------"<<"\n\n";
        Message* prova = new Message();
        prova->setMessage((unsigned char*)"ciao",4);
        prova->setCurrent_Token(5);
        prova->setNonce(6);
        cipher::CipherRSA* cipherRsa = new cipher::CipherRSA("bob","bobPassword");
        cipherRsa->sign( prova );
        NetMessage* message = Converter::encodeMessage(CHAT,*prova);
        unsigned char* msg = message->getMessage();
        for( int a = 0; a<message->length(); a++)
            cout<<msg[a];
        cout<<endl<<endl<<endl;
        delete[] msg;

        NetMessage* messageExpanded = message->giveWithLength();
        msg = messageExpanded->getMessage();
        for( int a = 0; a<messageExpanded->length(); a++)
            cout<<msg[a];
        cout<<endl;

        delete prova;
        delete message;
        delete cipherRsa;
        delete[] msg;

       // cipher::CipherRSA::test();
        //Converter::test();
        return 0;
    }



