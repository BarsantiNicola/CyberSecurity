//
// Created by root on 09/08/20.
//

#include "Converter.h"

namespace utility{

    //  verifies the presence of all the fields needed to a given MessageType and that these don't contain a &" element
    bool Converter::verifyMessage(MessageType type , Message message ){
        vverbose<<"--> [Converter][verifyMessage] Verification of message"<<'\n';
        switch( type ){
            case CERTIFICATE_REQ:
                vverbose<<"--> [Converter][verifyMessage] Check CERTIFICATE_REQ"<<'\n';
                if( message.getNonce() == nullptr || Converter::checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure"<<'\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification CERTIFICATE_REQ success"<<'\n';
                break;
            case CERTIFICATE:
                vverbose<<"--> [Converter][verifyMessage] Check CERTIFICATE"<<'\n';
                if( message.getNonce() == nullptr || message.getServer_Certificate().empty() || message.getSignature().empty()  || checkField( (unsigned char*)message.getServer_Certificate().c_str(), message.getServer_Certificate().length()) || checkField( (unsigned char*)message.getSignature().c_str(),message.getSignature().length())  || checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length())){
                    verbose<<"--> [Converter][verifyMessage] Verification failure"<<'\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification CERTIFICATE success"<<'\n';
                break;
            case LOGIN_REQ:
                vverbose<<"--> [Converter][verifyMessage] Check LOGIN_REQ"<<'\n';
                if( message.getNonce() == nullptr || message.getUsername().empty() || message.getSignature().empty() || checkField((unsigned char*)message.getUsername().c_str(),message.getUsername().length()) || checkField( (unsigned char*)message.getSignature().c_str(),message.getSignature().length())  || checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure"<<'\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification LOGIN_REQ success"<<'\n';
                break;
            case LOGIN_OK:
                vverbose<<"--> [Converter][verifyMessage] Check LOGIN_OK"<<'\n';
                if( message.getNonce() == nullptr || message.getSignature().empty()  || checkField( (unsigned char*)message.getSignature().c_str(),message.getSignature().length())   || checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length())){
                    verbose<<"--> [Converter][verifyMessage] Verification failure"<<'\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification LOGIN_OK success"<<'\n';
                break;
            case LOGIN_FAIL:
                vverbose<<"--> [Converter][verifyMessage] Check LOGIN_FAIL"<<'\n';
                if( message.getNonce() == nullptr || message.getSignature().empty() || checkField( (unsigned char*)message.getSignature().c_str(),message.getSignature().length())   || checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure"<<'\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification LOGIN_FAIL success"<<'\n';
                break;
            case KEY_EXCHANGE:
                vverbose<<"--> [Converter][verifyMessage] Check KEY_EXCHANGE"<<'\n';
                if( message.getNonce() == nullptr || message.get_DH_key().empty() || message.getSignature().empty()|| checkField( (unsigned char*)message.get_DH_key().c_str() , message.get_DH_key().length()) || checkField( (unsigned char*)message.getSignature().c_str(),message.getSignature().length())  || checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure"<<'\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification KEY_EXCHANGE success"<<'\n';
                break;
            case USER_LIST_REQ:
                vverbose<<"--> [Converter][verifyMessage] Check USER_LIST_REQ"<<'\n';
                if( message.getNonce() == nullptr ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure"<<'\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification USER_LIST_REQ success"<<'\n';
                break;
            case USER_LIST:
                vverbose<<"--> [Converter][verifyMessage] Check USER_LIST"<<'\n';
                if( message.getNonce() == nullptr || message.getUserList().empty() || checkField((unsigned char*)message.getUserList().c_str(),message.getUserList().length()) ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length())) {
                    verbose << "--> [Converter][verifyMessage] Verification failure" << '\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification USER_LIST success"<<'\n';
                break;
            case RANK_LIST_REQ:
                vverbose<<"--> [Converter][verifyMessage] Check RANK_LIST_REQ"<<'\n';
                if( message.getNonce() == nullptr ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure"<<'\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification RANK_LIST_REQ success"<<'\n';
                break;
            case RANK_LIST:
                vverbose<<"--> [Converter][verifyMessage] Check RANK_LIST"<<'\n';
                if( message.getNonce() == nullptr || message.getRankList().empty() || checkField((unsigned char*)message.getRankList().c_str(),message.getRankList().length()) ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure"<<'\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification RANK_LIST success"<<'\n';
                break;
            case MATCH:
                vverbose<<"--> [Converter][verifyMessage] Check MATCH"<<'\n';
                if( message.getNonce() == nullptr || message.getUsername().empty() || checkField((unsigned char*)message.getUsername().c_str(),message.getUsername().length()) ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure"<<'\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification MATCH success"<<'\n';
                break;
            case ACCEPT:
                vverbose<<"--> [Converter][verifyMessage] Check ACCEPT"<<'\n';
                if( message.getNonce() == nullptr || message.getAdversary_1().empty() || message.getAdversary_2().empty() || checkField((unsigned char*)message.getAdversary_1().c_str(),message.getAdversary_1().length()) || checkField((unsigned char*)message.getAdversary_2().c_str(),message.getAdversary_2().length()) ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure"<<'\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification ACCEPT success"<<'\n';
                break;
            case REJECT:
                vverbose<<"--> [Converter][verifyMessage] Check REJECT"<<'\n';
                if( message.getNonce() == nullptr || message.getAdversary_1().empty() || message.getAdversary_2().empty() || checkField((unsigned char*)message.getAdversary_1().c_str(),message.getAdversary_1().length()) || checkField((unsigned char*)message.getAdversary_2().c_str(),message.getAdversary_2().length()) ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure"<<'\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification REJECT success"<<'\n';
                break;
            case WITHDRAW_REQ:
                vverbose<<"--> [Converter][verifyMessage] Check WITHDRAW_REQ"<<'\n';
                if( message.getUsername().empty() || message.getNonce() == nullptr || checkField((unsigned char*)message.getUsername().c_str(),message.getUsername().length()) ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length())) {
                    verbose << "--> [Converter][verifyMessage] Verification failure" << '\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification WITHDRAW_REQ success"<<'\n';
                break;
            case WITHDRAW_OK:
                vverbose<<"--> [Converter][verifyMessage] Check WITHDRAW_OK"<<'\n';
                if( message.getNonce()== nullptr ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure"<<'\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification WITHDRAW_OK success"<<'\n';
                break;
            case LOGOUT_REQ:
                vverbose<<"--> [Converter][verifyMessage] Check LOGOUT_REQ"<<'\n';
                if( message.getNonce() == nullptr ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length())) {
                    verbose << "--> [Converter][verifyMessage] Verification failure" << '\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification LOGOUT_REQ success"<<'\n';
                break;
            case LOGOUT_OK:
                vverbose<<"--> [Converter][verifyMessage] Check LOGOUT_OK"<<'\n';
                if( message.getNonce() == nullptr ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length())) {
                    verbose << "--> [Converter][verifyMessage] Verification failure" << '\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification LOGOUT_OK success"<<'\n';
                break;
            case GAME_PARAM:
                vverbose<<"--> [Converter][verifyMessage] Check GAME_PARAM"<<'\n';
                if( message.getNonce() == nullptr || message.getNetInformations().empty() || message.getPubKey().empty() || checkField((unsigned char*)message.getNetInformations().c_str(),message.getNetInformations().length()) || checkField((unsigned char*)message.getPubKey().c_str(),message.getPubKey().length()) ||  checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length())) {
                    verbose << "--> [Converter][verifyMessage] Verification failure" << '\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification GAME_PARAM success"<<'\n';
                break;
            case MOVE:
                vverbose<<"--> [Converter][verifyMessage] Check MOVE"<<'\n';
                if( message.getCurrent_Token() == nullptr || message.getChosenColumn() == nullptr || checkField((unsigned char*)to_string(*message.getCurrent_Token()).c_str(),to_string(*message.getCurrent_Token()).length()) || checkField((unsigned char*)to_string(*message.getChosenColumn()).c_str(),to_string(*message.getChosenColumn()).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure"<<'\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification MOVE success"<<'\n';
                break;
            case CHAT:
                vverbose<<"--> [Converter][verifyMessage] Check CHAT"<<'\n';
                if( message.getCurrent_Token() == nullptr || message.getMessage().empty() || checkField((unsigned char*)message.getMessage().c_str(),message.getMessage().length()) || checkField((unsigned char*)to_string(*message.getCurrent_Token()).c_str(),to_string(*message.getCurrent_Token()).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure"<<'\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification CHAT success"<<'\n';
                break;
            case ACK:
                vverbose<<"--> [Converter][verifyMessage] Check ACK"<<'\n';
                if( message.getCurrent_Token() == nullptr || checkField((unsigned char*)to_string(*message.getCurrent_Token()).c_str(),to_string(*message.getCurrent_Token()).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure"<<'\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification ACK success"<<'\n';
                break;
            case DISCONNECT:
                vverbose<<"--> [Converter][verifyMessage] Check DISCONNECT"<<'\n';
                if( message.getNonce() == nullptr || checkField((unsigned char*)to_string(*message.getNonce()).c_str(),to_string(*(message.getNonce())).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure"<<'\n';
                    return false;
                }
                break;
            default:
                verbose<<"--> [Converter][verifyMessage] Error message type undefined: " <<type <<'\n';
                return false;
        }
        return true;
    }

    //  translate a Message class into a NetMessage after have controlled the validity of the Message fields
    NetMessage* Converter::encodeMessage(MessageType type , Message msg ){
        vverbose<<"--> [Converter][encodeMessage] Starting encoding of Message"<<'\n';
        if( !verifyMessage(type,msg))
            return nullptr;

        string value = "y=\"";
        value.append(to_string(type));

        switch (type){
            case CERTIFICATE_REQ:
                vverbose<<"--> [Converter][encodeMessage] Encoding CERTIFICATE_REQ"<<'\n';
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case CERTIFICATE:
                vverbose<<"--> [Converter][encodeMessage] Encoding CERTIFICATE"<<'\n';
                value.append("\"&c=\"");
                value.append(msg.getServer_Certificate());
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"&s=\"");
                value.append(msg.getSignature());
                value.append("\"");
                break;
            case LOGIN_REQ:
                vverbose<<"--> [Converter][encodeMessage] Encoding LOGIN_REQ"<<'\n';
                value.append("\"&u=\"");
                value.append(msg.getUsername());
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"&s=\"");
                value.append(msg.getSignature());
                value.append("\"");
                break;
            case LOGIN_OK:
                vverbose<<"--> [Converter][encodeMessage] Encoding LOGIN_OK"<<'\n';
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"&s=\"");
                value.append(msg.getSignature());
                value.append("\"");
                break;
            case LOGIN_FAIL:
                vverbose<<"--> [Converter][encodeMessage] Encoding LOGIN_FAIL"<<'\n';
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"&s=\"");
                value.append(msg.getSignature());
                value.append("\"");
                break;
            case KEY_EXCHANGE:
                vverbose<<"--> [Converter][encodeMessage] Encoding KEY_EXCHANGE"<<'\n';
                value.append("\"&d=\"");
                value.append(msg.get_DH_key());
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"&s=\"");
                value.append(msg.getSignature());
                value.append("\"");
                break;
            case USER_LIST_REQ:
                vverbose<<"--> [Converter][encodeMessage] Encoding USER_LIST_REQ"<<'\n';
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case USER_LIST:
                vverbose<<"--> [Converter][encodeMessage] Encoding USER_LIST"<<'\n';
                value.append("\"&l=\"");
                value.append(msg.getUserList());
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case RANK_LIST_REQ:
                vverbose<<"--> [Converter][encodeMessage] Encoding RANK_LIST_REQ"<<'\n';
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case RANK_LIST:
                vverbose<<"--> [Converter][encodeMessage] Encoding RANK_LIST"<<'\n';
                value.append("\"&r=\"");
                value.append(msg.getRankList());
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case MATCH:
                vverbose<<"--> [Converter][encodeMessage] Encoding MATCH"<<'\n';
                value.append("\"&u=\"");
                value.append(msg.getUsername());
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case ACCEPT:
                vverbose<<"--> [Converter][encodeMessage] Encoding ACCEPT"<<'\n';
                value.append("\"&a=\"");
                value.append(msg.getAdversary_1());
                value.append("\"&b=\"");
                value.append(msg.getAdversary_2());
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case REJECT:
                vverbose<<"--> [Converter][encodeMessage] Encoding REJECT"<<'\n';
                value.append("\"&a=\"");
                value.append(msg.getAdversary_1());
                value.append("\"&b=\"");
                value.append(msg.getAdversary_2());
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case WITHDRAW_REQ:
                vverbose<<"--> [Converter][encodeMessage] Encoding WITHDRAW_REQ"<<'\n';
                value.append("\"&u=\"");
                value.append(msg.getUsername());
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case WITHDRAW_OK:
                vverbose<<"--> [Converter][encodeMessage] Encoding WITHDRAW_OK"<<'\n';
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case LOGOUT_REQ:
                vverbose<<"--> [Converter][encodeMessage] Encoding LOGOUT_REQ"<<'\n';
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case LOGOUT_OK:
                vverbose<<"--> [Converter][encodeMessage] Encoding LOGOUT_OK"<<'\n';
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case GAME_PARAM:
                vverbose<<"--> [Converter][encodeMessage] Encoding GAME_PARAM"<<'\n';
                value.append("\"&k=\"");
                value.append(msg.getPubKey());
                value.append("\"&i=\"");
                value.append(msg.getNetInformations());
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            case MOVE:
                vverbose<<"--> [Converter][encodeMessage] Encoding MOVE"<<'\n';
                value.append("\"&t=\"");
                value.append(to_string(*(msg.getCurrent_Token())));
                value.append("\"&v=\"");
                value.append(to_string(*(msg.getChosenColumn())));
                value.append("\"");
                break;
            case CHAT:
                vverbose<<"--> [Converter][encodeMessage] Encoding CHAT"<<'\n';
                value.append("\"&t=\"");
                value.append(to_string(*(msg.getCurrent_Token())));
                value.append("\"&h=\"");
                value.append(msg.getMessage());
                value.append("\"");
                break;
            case ACK:
                vverbose<<"--> [Converter][encodeMessage] Encoding ACK"<<'\n';
                value.append("\"&t=\"");
                value.append(to_string(*(msg.getCurrent_Token())));
                value.append("\"");
                break;
            case DISCONNECT:
                vverbose<<"--> [Converter][encodeMessage] Encoding DISCONNECT"<<'\n';
                value.append("\"&n=\"");
                value.append(to_string(*(msg.getNonce())));
                value.append("\"");
                break;
            default:
                verbose<<"--> [Converter][encodeMessage] Error Undefined MessageType"<<type<<'\n';
                return nullptr;
        }

        vverbose<<"--> [Converter][encodeMessage] Encoded completed, encoded message: "<<value<<'\n';
        return new NetMessage( (unsigned char*)value.c_str(), value.length());
    }

    //  Translate a NetMessage into a Message, if it find an incorrect syntax, it stop the analysis giving a class
    //  that contains only the fields extracted until the error
    Message* Converter::decodeMessage( NetMessage message ){
        vverbose<<"--> [Converter][decodeMessage] Starting decoding of netMessage: "<<message.getMessage()<<'\n';
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
        vverbose<<"--> [Converter][decodeMessage] Compute field, position: "<<position<<'\n';
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
        vverbose<<"-->[Converter][decodeMessage] Extracted fieldName: "<<field<<'\n';
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
            vverbose<<"--> [Converter][decodeMessage] Field value extracted, value: "<<value<<'\n';
            setField(field, value, newMessage);
            return position;
        }
        verbose<<"--> [Converter][decodeMessage] Syntax Error, unable to extract the field"<<'\n';
        return -1;
    }

    //  set a field of a Message class using the encoded information extracted from the NetMessage
    bool Converter::setField( char fieldName , unsigned char* fieldValue , Message* msg ){
        vverbose<<"--> [Converter][setField] Setting the message variable"<<'\n';
        int c;
        switch(fieldName) {
            case 'a':
                vverbose<<"--> [Converter][setField] Identified variable: Adversary_1"<<'\n';
                msg->setAdversary_1(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 'b':
                vverbose<<"--> [Converter][setField] Identified variable: Adversary_2"<<'\n';
                msg->setAdversary_2(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 'c':
                vverbose<<"--> [Converter][setField] Identified variable: Server_Certificate"<<'\n';
                msg->setServer_Certificate(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 'd':
                vverbose<<"--> [Converter][setField] Identified variable: Diffie-Hellman parameter"<<'\n';
                msg->set_DH_key(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 'i':
                vverbose<<"--> [Converter][setField] Identified variable: NetInformations"<<'\n';
                msg->setNetInformations(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 'l':
                vverbose<<"--> [Converter][setField] Identified variable: UserList"<<'\n';
                msg->setUserList(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 'k':
                vverbose<<"--> [Converter][setField] Identified variable: Public Key"<<'\n';
                msg->setPubKey(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 'n':
                vverbose<<"--> [Converter][setField] Identified variable: Nonce"<<'\n';
                msg->setNonce(stoi(string(reinterpret_cast<char*>(fieldValue))));
                break;
            case 'r':
                vverbose<<"--> [Converter][setField] Identified variable: RankList"<<'\n';
                msg->setRankList(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 's':
                vverbose<<"--> [Converter][setField] Identified variable: Signature"<<'\n';
                msg->setSignature(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 't':
                vverbose<<"--> [Converter][setField] Identified variable: CurrentToken"<<'\n';
                msg->setCurrent_Token(stoi(string(reinterpret_cast<char*>(fieldValue))));
                break;
            case 'v':
                vverbose<<"--> [Converter][setField] Identified variable: ChosenColumn"<<'\n';
                msg->setChosenColumn(stoi(string(reinterpret_cast<char*>(fieldValue))));
                break;
            case 'u':
                vverbose<<"--> [Converter][setField] Identified variable: Username"<<'\n';
                msg->setUsername(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 'h':
                vverbose<<"--> [Converter][setField] Identified variable: Message"<<'\n';
                msg->setMessage(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 'y':
                vverbose<<"--> [Converter][setField] Identified variable: MessageType"<<'\n';
                msg->setMessageType((MessageType)stoi(string(reinterpret_cast<char*>(fieldValue))));
                break;
            default:
                verbose<<"--> [Converter][setField] Error, undefined field name: "<<fieldName<<'\n';
                return false;
        }
        vverbose<<"--> [Converter][setField] Setting completed"<<'\n';
        return true;

    }

    //  verify the presence of the &" sequence into a given field
    bool Converter::checkField( unsigned const char* field , int len){
        vverbose<<"--> [Converter][checkField] Verification of Message consistence"<<'\n';
        bool warn = false;

        for( int a= 0; a<len;a++){
            if( field[a] == '&')
                if( warn ) {
                    verbose<<"--> [Converter][checkField] Error, sequence \"& founded into the field"<<'\n';
                    return true;
                }else {
                    continue;
                }
            if( field[a] == '"' )
                warn = true;
            else
                warn = false;
        }
        vverbose<<"--> [Converter][checkField] Verification success"<<'\n';
        return false;
    }

    bool Converter::test(){
        Message* m = new Message();
        m->setSignature( "signature" );
        Message* m2 = new Message();
        NetMessage* encoded;

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

        if( Converter::encodeMessage(CERTIFICATE_REQ,*m)== nullptr) return false;
        if( Converter::encodeMessage(CERTIFICATE,*m)== nullptr) return false;
        if( Converter::encodeMessage(LOGIN_REQ,*m)== nullptr) return false;
        if( Converter::encodeMessage(LOGIN_OK,*m)== nullptr) return false;
        if( Converter::encodeMessage(LOGIN_FAIL,*m)== nullptr) return false;
        if( Converter::encodeMessage(KEY_EXCHANGE,*m)== nullptr) return false;
        if( Converter::encodeMessage(USER_LIST_REQ,*m)== nullptr) return false;
        if( Converter::encodeMessage(USER_LIST,*m)== nullptr) return false;
        if( Converter::encodeMessage(RANK_LIST_REQ,*m)== nullptr) return false;
        if( Converter::encodeMessage(RANK_LIST,*m)== nullptr) return false;
        if( Converter::encodeMessage(MATCH,*m)== nullptr) return false;
        if( Converter::encodeMessage(ACCEPT,*m)== nullptr) return false;
        if( Converter::encodeMessage(REJECT,*m)== nullptr) return false;
        if( Converter::encodeMessage(WITHDRAW_REQ,*m)== nullptr) return false;
        if( Converter::encodeMessage(WITHDRAW_OK,*m)== nullptr) return false;
        if( Converter::encodeMessage(LOGOUT_REQ,*m)== nullptr) return false;
        if( Converter::encodeMessage(LOGOUT_OK,*m)== nullptr) return false;
        if( Converter::encodeMessage(GAME_PARAM,*m)== nullptr) return false;
        if( Converter::encodeMessage(MOVE,*m)== nullptr) return false;
        if( Converter::encodeMessage(ACK,*m)== nullptr) return false;
        if( Converter::encodeMessage(CHAT,*m)== nullptr) return false;
        if( Converter::encodeMessage(DISCONNECT,*m)== nullptr) return false;

        if( Converter::encodeMessage(CERTIFICATE,*m2)!= nullptr) return false;
        if( Converter::encodeMessage(LOGIN_REQ,*m2)!= nullptr) return false;
        if( Converter::encodeMessage(LOGIN_OK,*m2)!= nullptr) return false;
        if( Converter::encodeMessage(LOGIN_FAIL,*m2)!= nullptr) return false;
        if( Converter::encodeMessage(KEY_EXCHANGE,*m2)!= nullptr) return false;
        if( Converter::encodeMessage(USER_LIST,*m2)!= nullptr) return false;
        if( Converter::encodeMessage(RANK_LIST,*m2)!= nullptr) return false;
        if( Converter::encodeMessage(MATCH,*m2)!= nullptr) return false;
        if( Converter::encodeMessage(GAME_PARAM,*m2)!= nullptr) return false;
        if( Converter::encodeMessage(CHAT,*m2)!= nullptr) return false;
        delete m2;

        encoded = Converter::encodeMessage(CERTIFICATE_REQ,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != CERTIFICATE_REQ || m2->getNonce() == nullptr )  return false;
        delete m2;
        delete encoded;
        verbose<<"CERTIFICATE_REQ"<<'\n';

        encoded = Converter::encodeMessage(CERTIFICATE,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != CERTIFICATE || m2->getNonce() == nullptr || m2->getServer_Certificate().empty() || m2->getSignature().empty())  return false;
        delete m2;
        delete encoded;
        verbose<<"CERTIFICATE"<<'\n';

        encoded = Converter::encodeMessage(LOGIN_REQ,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != LOGIN_REQ || m2->getNonce() == nullptr || m2->getUsername().empty() || m2->getSignature().empty())  return false;
        delete m2;
        delete encoded;
        verbose<<"LOGIN_REQ"<<'\n';

        encoded = Converter::encodeMessage(LOGIN_OK,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != LOGIN_OK || m2->getNonce() == nullptr || m2->getSignature().empty())  return false;
        delete m2;
        delete encoded;
        verbose<<"LOGIN_OK"<<'\n';

        encoded = Converter::encodeMessage(LOGIN_FAIL,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != LOGIN_FAIL || m2->getNonce() == nullptr || m2->getSignature().empty())  return false;
        delete m2;
        delete encoded;
        verbose<<"LOGIN_FAIL"<<'\n';

        encoded = Converter::encodeMessage(KEY_EXCHANGE,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != KEY_EXCHANGE || m2->getNonce() == nullptr || m2->get_DH_key().empty()  || m2->getSignature().empty())  return false;
        delete m2;
        delete encoded;
        verbose<<"KEY_EXCHANGE"<<'\n';

        encoded = Converter::encodeMessage(USER_LIST_REQ,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != USER_LIST_REQ || m2->getNonce() == nullptr )  return false;
        delete m2;
        delete encoded;
        verbose<<"USER_LIST_REQ"<<'\n';

        encoded = Converter::encodeMessage(USER_LIST,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != USER_LIST || m2->getNonce() == nullptr || m2->getUserList().empty() )  return false;
        delete m2;
        delete encoded;
        verbose<<"USER_LIST"<<'\n';

        encoded = Converter::encodeMessage(RANK_LIST_REQ,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != RANK_LIST_REQ || m2->getNonce() == nullptr  )  return false;
        delete m2;
        delete encoded;
        verbose<<"RANK_LIST_REQ"<<'\n';

        encoded = Converter::encodeMessage(RANK_LIST,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != RANK_LIST || m2->getNonce() == nullptr || m2->getRankList().empty() )  return false;
        delete m2;
        delete encoded;
        verbose<<"RANK_LIST"<<'\n';

        encoded = Converter::encodeMessage(MATCH,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != MATCH || m2->getNonce() == nullptr || m2->getUsername().empty() )  return false;
        delete m2;
        delete encoded;
        verbose<<"MATCH"<<'\n';

        encoded = Converter::encodeMessage(ACCEPT,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != ACCEPT || m2->getNonce() == nullptr || m2->getAdversary_1().empty() || m2->getAdversary_2().empty())  return false;
        delete m2;
        delete encoded;
        verbose<<"ACCEPT"<<'\n';

        encoded = Converter::encodeMessage(REJECT,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != REJECT || m2->getNonce() == nullptr || m2->getAdversary_1().empty() || m2->getAdversary_2().empty() )  return false;
        delete m2;
        delete encoded;
        verbose<<"REJECT"<<'\n';

        encoded = Converter::encodeMessage(WITHDRAW_REQ,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != WITHDRAW_REQ || m2->getNonce() == nullptr || m2->getUsername().empty() )  return false;
        delete m2;
        delete encoded;
        verbose<<"WITHDRAW_REQ"<<'\n';

        encoded = Converter::encodeMessage(WITHDRAW_OK,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != WITHDRAW_OK || m2->getNonce() == nullptr )  return false;
        delete m2;
        delete encoded;
        verbose<<"WITHDRAW_OK"<<'\n';

        encoded = Converter::encodeMessage(LOGOUT_REQ,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != LOGOUT_REQ || m2->getNonce() == nullptr )  return false;
        delete m2;
        delete encoded;
        verbose<<"LOGOUT_REQ"<<'\n';

        encoded = Converter::encodeMessage(LOGOUT_OK,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != LOGOUT_OK || m2->getNonce() == nullptr )  return false;
        delete m2;
        delete encoded;
        verbose<<"LOGOUT_OK"<<'\n';

        encoded = Converter::encodeMessage(GAME_PARAM,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != GAME_PARAM || m2->getNonce() == nullptr || m2->getPubKey().empty() || m2->getNetInformations().empty())  return false;
        delete m2;
        delete encoded;
        verbose<<"GAME_PARAM"<<'\n';

        encoded = Converter::encodeMessage(MOVE,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != MOVE || m2->getCurrent_Token() == nullptr || m2->getChosenColumn() == nullptr )  return false;
        delete m2;
        delete encoded;
        verbose<<"MOVE"<<'\n';

        encoded = Converter::encodeMessage(CHAT,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != CHAT || m2->getCurrent_Token() == nullptr || m2->getMessage().empty() )  return false;
        delete m2;
        delete encoded;
        verbose<<"CHAT"<<'\n';

        encoded = Converter::encodeMessage(ACK,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != ACK  || m2->getCurrent_Token() == nullptr )  return false;
        delete m2;
        delete encoded;
        verbose<<"ACK"<<'\n';

        encoded = Converter::encodeMessage(DISCONNECT,*m);
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != DISCONNECT || m2->getNonce() == nullptr )  return false;
        delete m2;
        delete encoded;
        verbose<<"DISCONNECT"<<'\n';

        delete m;

        return true;

    }

}