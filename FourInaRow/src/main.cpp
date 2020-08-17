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
       // Converter::test();
        Message *m = new Message();
        m->setNonce(10);
        m->setUsername( "nicola" );
        m->setSignature( (unsigned char*)"prova" , 5 );
        m->setUsername( "username");
        m->setAdversary_1( "adv_1" );
        m->setAdversary_2( "adv_2" );
        m->setNonce( 15 );
        m->setServer_Certificate( (unsigned char*)"certificate" ,11);
        m->setPubKey( (unsigned char*)"pub_key" ,7 );
        m->setNetInformations( (unsigned char*)"127.0.0.1", 9 );
        m->setCurrent_Token( 13 );
        m->setChosenColumn( (unsigned char*)"column",6 );
        m->setMessage( (unsigned char*)"message" ,7);
        m->set_DH_key( (unsigned char*)"dh_key",6 );
        m->setUserList( "user_list" );
        m->setRankList( "rank_list" );

        NetMessage* msg = Converter::compactForm(WITHDRAW_REQ,*m);
        cout<<msg->getMessage()<<endl;
        return 0;
    }



