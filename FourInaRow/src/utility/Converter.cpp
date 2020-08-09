//
// Created by root on 09/08/20.
//

#include "Converter.h"

namespace utility{

    bool Converter::verifyMessage(MessageType type , Message message ){

        switch( type ){
            case CERTIFICATE_REQ:
                if( message.getNonce() == NULL )
                    return false;
            case CERTIFICATE:
                if( message.getNonce() == NULL || message.getServer_Certificate()== NULL || message.getSignature() == NULL )
                    return false;
            case LOGIN_REQ:
                if( message.getNonce() == NULL || message.getUsername().empty() || message.getSignature() == NULL )
                    return false;
            case LOGIN_OK:
                if( message.getNonce() == NULL || message.getSignature() == NULL )
                    return false;
            case LOGIN_FAIL:
                if( message.getNonce() == NULL || message.getSignature() == NULL )
                    return false;
            case KEY_EXCHANGE:
                if( message.getNonce() == NULL || message.get_DH_key() == NULL || message.getSignature() == NULL )
                    return false;
            case USER_LIST_REQ:
                if( message.getNonce() == NULL )
                    return false;
            case USER_LIST:
                if( message.getNonce() == NULL || message.getUserList().empty() )
                    return false;
            case RANK_LIST_REQ:
                if( message.getNonce() == NULL )
                    return false;
            case RANK_LIST:
                if( message.getNonce() == NULL || message.getRankList().empty() )
                    return false;
            case MATCH:
                if( message.getNonce() == NULL || message.getUsername().empty() )
                    return false;
            case ACCEPT:
                if( message.getNonce() == NULL || message.getAdversary_1().empty() || message.getAdversary_2().empty() )
                    return false;
            case REJECT:
                if( message.getNonce() == NULL || message.getAdversary_1().empty() || message.getAdversary_2().empty() )
                    return false;
            case WITHDRAW_REQ:
                if( message.getNonce() == NULL )
                    return false;
            case WITHDRAW_OK:
                if( message.getNonce()== NULL )
                    return false;
            case LOGOUT_REQ:
                if( message.getNonce() == NULL )
                    return false;
            case LOGOUT_OK:
                if( message.getNonce() == NULL )
                    return false;
            case GAME_PARAM:
                if( message.getNonce() == NULL || message.getNetInformations().empty() || message.getPubKey() == NULL )
                    return false;
            case MOVE:
                if( message.getCurrent_Token() == NULL || message.getChosenColumn() == NULL )
                    return false;
            case CHAT:
                if( message.getCurrent_Token() == NULL || message.getMessage().empty())
                    return false;
            case ACK:
                if( message.getCurrent_Token() == NULL )
                    return false;
            case DISCONNECT:
                if( message.getNonce() == NULL )
                    return false;
        }
        return true;
    }

    NetMessage* Converter::encodeMessage(MessageType type , Message msg ){

        char* value = new char[6];
        strcpy(value,"type=\"");
        strcat(value,to_string(type).c_str());

        switch (type){
            case CERTIFICATE_REQ:

                strcat(value,"\"&nonce=\"");
                strcat(value,to_string(*(msg.getNonce())).c_str());
                strcat(value,"\"");
                break;
            case CERTIFICATE:

                strcat(value,"\"&server_certificate=\"");
                        strcat(value,(const char*)msg.getServer_Certificate());
                        strcat(value,"\"&nonce=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"&signature=\"");
                        strcat(value,(char*)msg.getSignature());
                        strcat(value,"\"");
                        break;
                    case LOGIN_REQ:
                        strcat(value,to_string(msg.getMessageType()).c_str());
                        strcat(value,"\"&username=\"");
                        strcat(value,msg.getUsername().c_str());
                        strcat(value,"\"&nonce=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"&signature=\"");
                        strcat(value,(char*)msg.getSignature());
                        strcat(value,"\"");
                        break;
                    case LOGIN_OK:
                        strcat(value,"\"&nonce=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"&signature=\"");
                        strcat(value,(char*)msg.getSignature());
                        strcat(value,"\"");
                        break;
                    case LOGIN_FAIL:
                        strcat(value,"\"&nonce=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"&signature=\"");
                        strcat(value,(char*)msg.getSignature());
                        strcat(value,"\"");
                        break;
                    case KEY_EXCHANGE:
                        strcat(value,"\"&dh_param=\"");
                        strcat(value,(const char*)msg.get_DH_key());
                        strcat(value,"\"&nonce=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"&signature=\"");
                        strcat(value,(char*)msg.getSignature());
                        strcat(value,"\"");
                        break;
                    case USER_LIST_REQ:
                        strcat(value,"\"&nonce=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"");
                        break;
                    case USER_LIST:
                        strcat(value,"\"&user_list=\"");
                        strcat(value,msg.getUserList().c_str());
                        strcat(value,"\"&nonce=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"");
                        break;
                    case RANK_LIST_REQ:
                        strcat(value,"\"&nonce=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"");
                        break;
                    case RANK_LIST:
                        strcat(value,"\"&rank_list=\"");
                        strcat(value,msg.getRankList().c_str());
                        strcat(value,"\"&nonce=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"");
                        break;
                    case MATCH:
                        strcat(value,"\"&username=\"");
                        strcat(value,msg.getUsername().c_str());
                        strcat(value,"\"&nonce=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"");
                        break;
                    case ACCEPT:
                        strcat(value,"\"&username_1=\"");
                        strcat(value,msg.getAdversary_1().c_str());
                        strcat(value,"\"&username_2=\"");
                        strcat(value,msg.getAdversary_2().c_str());
                        strcat(value,"\"&nonce=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"");
                        break;
                    case REJECT:
                        strcat(value,"\"&username_1=\"");
                        strcat(value,msg.getAdversary_1().c_str());
                        strcat(value,"\"&username_2=\"");
                        strcat(value,msg.getAdversary_2().c_str());
                        strcat(value,"\"&nonce=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"");
                        break;
                    case WITHDRAW_REQ:
                        strcat(value,"\"&username=\"");
                        strcat(value,msg.getUsername().c_str());
                        strcat(value,"\"&nonce=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"");
                        break;
                    case WITHDRAW_OK:
                        strcat(value,"\"&nonce=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"");
                        break;
                    case LOGOUT_REQ:
                        strcat(value,"\"&nonce=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"");
                        break;
                    case LOGOUT_OK:
                        strcat(value,"\"&nonce=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"");
                        break;
                    case GAME_PARAM:
                        strcat(value,"\"&user_key=\"");
                        strcat(value,(const char*)msg.getPubKey());
                        strcat(value,"\"&net=\"");
                        strcat(value,msg.getNetInformations().c_str());
                        strcat(value,"\"&nonce=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"");
                        break;
                    case MOVE:
                        strcat(value,"\"&current_token=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"&chosen_col=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"");
                        break;
                    case CHAT:
                        strcat(value,"\"&current_token=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"");
                        break;
                    case ACK:
                        strcat(value,"\"&message=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"&current_token=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"");
                        break;
                    case DISCONNECT:
                        strcat(value,"\"&nonce=\"");
                        strcat(value,to_string(*(msg.getNonce())).c_str());
                        strcat(value,"\"");
                        break;
                    default:
                        return NULL;
                }

                return new NetMessage( (unsigned char*) value , sizeof(value));

            }



}