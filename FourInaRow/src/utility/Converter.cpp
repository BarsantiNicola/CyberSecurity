//
// Created by root on 09/08/20.
//

#include "Converter.h"

namespace utility{

    //  verifies the presence of all the fields needed to a given MessageType and that these don't contain a &" element
    bool Converter::verifyMessage(MessageType type , Message message ){

        switch( type ){
            case CERTIFICATE_REQ:
                if( message.getNonce() == NULL || Converter::checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length()))
                    return false;
                break;
            case CERTIFICATE:
                if( message.getNonce() == NULL || message.getServer_Certificate().empty() || message.getSignature().empty()  || checkField( (unsigned char*)message.getServer_Certificate().c_str(), message.getServer_Certificate().length()) || checkField( (unsigned char*)message.getSignature().c_str(),message.getSignature().length())  || checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length()))
                    return false;
                break;
            case LOGIN_REQ:
                if( message.getNonce() == NULL || message.getUsername().empty() || message.getSignature().empty() || checkField((unsigned char*)message.getUsername().c_str(),message.getUsername().length()) || checkField( (unsigned char*)message.getSignature().c_str(),message.getSignature().length())  || checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length()))
                    return false;
                break;
            case LOGIN_OK:
                if( message.getNonce() == NULL || message.getSignature().empty()  || checkField( (unsigned char*)message.getSignature().c_str(),message.getSignature().length())   || checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length()))
                    return false;
                break;
            case LOGIN_FAIL:
                if( message.getNonce() == NULL || message.getSignature().empty() || checkField( (unsigned char*)message.getSignature().c_str(),message.getSignature().length())   || checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length()))
                    return false;
                break;
            case KEY_EXCHANGE:
                if( message.getNonce() == NULL || message.get_DH_key().empty() || message.getSignature().empty()|| checkField( (unsigned char*)message.get_DH_key().c_str() , message.get_DH_key().length()) || checkField( (unsigned char*)message.getSignature().c_str(),message.getSignature().length())  || checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length()))
                    return false;
                break;
            case USER_LIST_REQ:
                if( message.getNonce() == NULL ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length()))
                    return false;
                break;
            case USER_LIST:
                if( message.getNonce() == NULL || message.getUserList().empty() || checkField((unsigned char*)message.getUserList().c_str(),message.getUserList().length()) ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length()))
                    return false;
                break;
            case RANK_LIST_REQ:
                if( message.getNonce() == NULL ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length()))
                    return false;
                break;
            case RANK_LIST:
                if( message.getNonce() == NULL || message.getRankList().empty() || checkField((unsigned char*)message.getRankList().c_str(),message.getRankList().length()) ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length()))
                    return false;
                break;
            case MATCH:
                if( message.getNonce() == NULL || message.getUsername().empty() || checkField((unsigned char*)message.getUsername().c_str(),message.getUsername().length()) ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length()))
                    return false;
                break;
            case ACCEPT:
                if( message.getNonce() == NULL || message.getAdversary_1().empty() || message.getAdversary_2().empty() || checkField((unsigned char*)message.getAdversary_1().c_str(),message.getAdversary_1().length()) || checkField((unsigned char*)message.getAdversary_2().c_str(),message.getAdversary_2().length()) ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length()))
                    return false;
                break;
            case REJECT:
                if( message.getNonce() == NULL || message.getAdversary_1().empty() || message.getAdversary_2().empty() || checkField((unsigned char*)message.getAdversary_1().c_str(),message.getAdversary_1().length()) || checkField((unsigned char*)message.getAdversary_2().c_str(),message.getAdversary_2().length()) ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length()))
                    return false;
                break;
            case WITHDRAW_REQ:
                if( message.getUsername().empty() || message.getNonce() == NULL || checkField((unsigned char*)message.getUsername().c_str(),message.getUsername().length()) ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length()))
                    return false;
                break;
            case WITHDRAW_OK:
                if( message.getNonce()== NULL ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length()))
                    return false;
                break;
            case LOGOUT_REQ:
                if( message.getNonce() == NULL ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length()))
                    return false;
                break;
            case LOGOUT_OK:
                if( message.getNonce() == NULL ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length()))
                    return false;
                break;
            case GAME_PARAM:
                if( message.getNonce() == NULL || message.getNetInformations().empty() || message.getPubKey().empty() || checkField((unsigned char*)message.getNetInformations().c_str(),message.getNetInformations().length()) || checkField((unsigned char*)message.getPubKey().c_str(),message.getPubKey().length()) ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length()))
                    return false;
                break;
            case MOVE:
                if( message.getCurrent_Token() == NULL || message.getChosenColumn() == NULL || checkField((unsigned char*)to_string(*message.getCurrent_Token()).c_str(),to_string(*message.getCurrent_Token()).length()) || checkField((unsigned char*)to_string(*message.getChosenColumn()).c_str(),to_string(*message.getChosenColumn()).length()))
                    return false;
                break;
            case CHAT:
                if( message.getCurrent_Token() == NULL || message.getMessage().empty() || checkField((unsigned char*)message.getMessage().c_str(),message.getMessage().length()) || checkField((unsigned char*)to_string(*message.getCurrent_Token()).c_str(),to_string(*message.getCurrent_Token()).length()))
                    return false;
                break;
            case ACK:
                if( message.getCurrent_Token() == NULL || checkField((unsigned char*)to_string(*message.getCurrent_Token()).c_str(),to_string(*message.getCurrent_Token()).length()))
                    return false;
                break;
            case DISCONNECT:
                if( message.getNonce() == NULL || checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length()))
                    return false;
                break;
        }
        return true;
    }

    //  translate a Message class into a NetMessage after have controlled the validity of the Message fields
    NetMessage* Converter::encodeMessage(MessageType type , Message msg ){

        if( !verifyMessage(type,msg))
            return NULL;

        string value = "y=\"";
        value.append(to_string(type));

        switch (type){
            case CERTIFICATE_REQ:

                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case CERTIFICATE:
                value.append("&c=\"");
                value.append(msg.getServer_Certificate());
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"&s=\"");
                value.append(msg.getSignature());
                value.append("\"");
                break;
            case LOGIN_REQ:
                value.append("\"&u=\"");
                value.append(msg.getUsername());
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"&s=\"");
                value.append(msg.getSignature());
                value.append("\"");
                break;
            case LOGIN_OK:
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"&s=\"");
                value.append(msg.getSignature());
                value.append("\"");
                break;
            case LOGIN_FAIL:
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"&s=\"");
                value.append(msg.getSignature());
                value.append("\"");
                break;
            case KEY_EXCHANGE:
                value.append("\"&d=\"");
                value.append(msg.get_DH_key());
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"&s=\"");
                value.append(msg.getSignature());
                value.append("\"");
                break;
            case USER_LIST_REQ:
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case USER_LIST:
                value.append("\"&l=\"");
                value.append(msg.getUserList());
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case RANK_LIST_REQ:
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case RANK_LIST:
                value.append("\"&r=\"");
                value.append(msg.getRankList());
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case MATCH:
                value.append("\"&u=\"");
                value.append(msg.getUsername());
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case ACCEPT:
                value.append("\"&a=\"");
                value.append(msg.getAdversary_1());
                value.append("\"&b=\"");
                value.append(msg.getAdversary_2());
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case REJECT:
                value.append("\"&a=\"");
                value.append(msg.getAdversary_1());
                value.append("\"&b=\"");
                value.append(msg.getAdversary_2());
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case WITHDRAW_REQ:
                value.append("\"&u=\"");
                value.append(msg.getUsername());
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case WITHDRAW_OK:
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case LOGOUT_REQ:
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case LOGOUT_OK:
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case GAME_PARAM:
                value.append("\"&k=\"");
                value.append(msg.getPubKey());
                value.append("\"&i=\"");
                value.append(msg.getNetInformations());
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case MOVE:
                value.append("\"&t=\"");
                value.append(to_string(*(msg.getCurrent_Token())));
                value.append("\"&c=\"");
                value.append(to_string(*(msg.getChosenColumn())));
                value.append("\"");
                break;
            case CHAT:
                value.append("\"&t=\"");
                value.append(to_string(*(msg.getCurrent_Token())));
                value.append("\"");
                break;
            case ACK:
                value.append("\"&t=\"");
                value.append(to_string(*(msg.getCurrent_Token())));
                break;
            case DISCONNECT:
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            default:
                return NULL;
        }

        return new NetMessage( (unsigned char*)value.c_str(), value.length());
    }

    //  Translate a NetMessage into a Message, if it find an incorrect syntax, it stop the analysis giving a class
    //  that contains only the fields extracted until the error
    Message* Converter::decodeMessage( NetMessage message ){
        Message* msg = new Message();
        int pos = 0;

        do{
            pos = computeNextField( message , pos , msg );
        }while( pos != -1 );

        return msg;

    }

    //  extract a field of the NetMessage starting from the given position. It will return the new position for the next field
    //  or -1 if it found an incorrect syntax
    int Converter::computeNextField( NetMessage msg , int position, Message* newMessage ){
        unsigned char* text = msg.getMessage();
        char field;
        bool found = false;
        int lowPos,highPos = -1;
        unsigned char* value;

        if( position >= msg.length() -2)
            return -1;
        if( text[position+1] == '=' && text[position+2] == '"')
            field = text[position];
        else
            return -1;

        position = position+3;
        lowPos = position;
        while( position < (msg.length()) ){
            if( position == msg.length()-1)
                if( text[position] == '"'){
                    highPos = position - 1;
                    position = position + 2;
                    found = true;
                    break;
                }else
                    break;

            if( text[position] == '"' && text[position+1] == '&') {
                highPos = position - 1;
                position = position + 2;
                found = true;
                break;
            }

            position++;
        }
        int pos = 0;

        if( found ) {
            value = new unsigned char[highPos - lowPos];
            for (int a = lowPos; a <= highPos; a++) {
                value[pos] = text[a];
                pos++;
            }
            setField(field, value, newMessage);
            return position;
        }
        return -1;
    }

    //  set a field of a Message class using the encoded information extracted from the NetMessage
    bool Converter::setField( char fieldName , unsigned char* fieldValue , Message* msg ){
        int c;
        switch(fieldName) {
            case 'a':
                msg->setAdversary_1(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 'b':
                msg->setAdversary_2(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 'c':
                msg->setServer_Certificate(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 'd':
                msg->set_DH_key(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 'i':
                msg->setNetInformations(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 'l':
                msg->setUserList(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 'k':
                msg->setPubKey(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 'm':
                msg->set_DH_key(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 'n':
                msg->setNonce(stoi(string(reinterpret_cast<char*>(fieldValue))));
                break;
            case 'r':
                msg->setRankList(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 's':
                msg->setSignature(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 't':
                msg->setCurrent_Token(stoi(string(reinterpret_cast<char*>(fieldValue))));
                break;
            case 'u':
                msg->setUsername(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 'y':
                msg->setMessageType((MessageType)stoi(string(reinterpret_cast<char*>(fieldValue))));
                break;
            default:
                return false;
        }
        return true;

    }

    //  verify the presence of the &" sequence into a given field
    bool Converter::checkField( unsigned char* field , int len){
        bool warn = false;

        for( int a= 0; a<len;a++){
            if( field[a] == '&')
                if( warn )
                    return true;
                else
                    continue;

            if( field[a] == '"' )
                warn = true;
            else
                warn = false;
        }
        return false;
    }

    bool Converter::test(){
        Message* m = new Message();
        m->setSignature( "signature" );
        Message* m2 = new Message();

        m->setUsername( "username");
        m->setAdversary_1( "adv_1" );
        m->setAdversary_2( "adv_2" );
        m->setNonce( 13 );
        m->setServer_Certificate( "certificate" );
        m->setPubKey( "pub_key" );
        m->setNetInformations( "127.0.0.1" );
        m->setCurrent_Token( 13 );
        m->setChosenColumn( 13 );
        m->setMessage( ",message" );
        m->set_DH_key( "dh_key" );
        m->setUserList( "user_list" );
        m->setRankList( "rank_list" );

        m2->setUsername( "us\"&ername");
        m2->setAdversary_1( "adv_1\"&" );
        m2->setAdversary_2( "ad\"&v_2" );
        m2->setNonce( 13 );
        m2->setServer_Certificate( "certificat\"&e" );
        m2->setPubKey( "pu\"&b_key" );
        m2->setNetInformations( "127\"&.0.0.1" );
        m2->setCurrent_Token( 13 );
        m2->setChosenColumn( 13 );
        m2->setMessage( "mes\"&sage" );
        m2->set_DH_key( "\"&dh_key" );
        m2->setUserList( "user_list\"&" );
        m2->setRankList( "rank_\"&list" );

        if( Converter::encodeMessage(CERTIFICATE_REQ,*m)== NULL) return false;
        if( Converter::encodeMessage(CERTIFICATE,*m)== NULL) return false;
        if( Converter::encodeMessage(LOGIN_REQ,*m)== NULL) return false;
        if( Converter::encodeMessage(LOGIN_OK,*m)== NULL) return false;
        if( Converter::encodeMessage(LOGIN_FAIL,*m)== NULL) return false;
        if( Converter::encodeMessage(KEY_EXCHANGE,*m)== NULL) return false;
        if( Converter::encodeMessage(USER_LIST_REQ,*m)== NULL) return false;
        if( Converter::encodeMessage(USER_LIST,*m)== NULL) return false;
        if( Converter::encodeMessage(RANK_LIST_REQ,*m)== NULL) return false;
        if( Converter::encodeMessage(RANK_LIST,*m)== NULL) return false;
        if( Converter::encodeMessage(MATCH,*m)== NULL) return false;
        if( Converter::encodeMessage(ACCEPT,*m)== NULL) return false;
        if( Converter::encodeMessage(REJECT,*m)== NULL) return false;
        if( Converter::encodeMessage(WITHDRAW_REQ,*m)== NULL) return false;
        if( Converter::encodeMessage(WITHDRAW_OK,*m)== NULL) return false;
        if( Converter::encodeMessage(LOGOUT_REQ,*m)== NULL) return false;
        if( Converter::encodeMessage(LOGOUT_OK,*m)== NULL) return false;
        if( Converter::encodeMessage(GAME_PARAM,*m)== NULL) return false;
        if( Converter::encodeMessage(MOVE,*m)== NULL) return false;
        if( Converter::encodeMessage(ACK,*m)== NULL) return false;
        if( Converter::encodeMessage(CHAT,*m)== NULL) return false;
        if( Converter::encodeMessage(DISCONNECT,*m)== NULL) return false;

        if( Converter::encodeMessage(CERTIFICATE,*m2)!= NULL) return false;
        if( Converter::encodeMessage(LOGIN_REQ,*m2)!= NULL) return false;
        if( Converter::encodeMessage(LOGIN_OK,*m2)!= NULL) return false;
        if( Converter::encodeMessage(LOGIN_FAIL,*m2)!= NULL) return false;
        if( Converter::encodeMessage(KEY_EXCHANGE,*m2)!= NULL) return false;
        if( Converter::encodeMessage(USER_LIST,*m2)!= NULL) return false;
        if( Converter::encodeMessage(RANK_LIST,*m2)!= NULL) return false;
        if( Converter::encodeMessage(MATCH,*m2)!= NULL) return false;
        if( Converter::encodeMessage(GAME_PARAM,*m2)!= NULL) return false;
        if( Converter::encodeMessage(CHAT,*m2)!= NULL) return false;


        delete m;
        delete m2;
        return true;

    }

}