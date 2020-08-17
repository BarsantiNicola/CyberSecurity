
#include "Converter.h"

namespace utility{

    //  verifies the presence of all the fields needed to a given MessageType and that these don't contain a &" element
    bool Converter::verifyMessage(MessageType type , Message message  ){

        vverbose<<"--> [Converter][verifyMessage] Verification of message"<<'\n';
        int* nonce;
        unsigned char* nonceString, *server_certificate,*signature,*key,*net,*chosen_column,*chat;
        const char* app,*app2;
        switch( type ){

            case CERTIFICATE_REQ:

                vverbose<<"--> [Converter][verifyMessage] Check CERTIFICATE_REQ"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                if( Converter::checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Presence of <\"&>"<<'\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification CERTIFICATE_REQ success"<<'\n';
                break;

            case CERTIFICATE:
                vverbose<<"--> [Converter][verifyMessage] Check CERTIFICATE"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                server_certificate = message.getServerCertificate();
                if( !server_certificate ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Server Certificate"<<'\n';
                    delete nonce;
                    return false;
                }

                signature = message.getSignature();
                if( !signature ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Signature"<<'\n';
                    delete nonce;
                    delete[] server_certificate;
                    return false;
                }

                if( checkField( server_certificate, message.getServerCertificateLength()) || checkField( signature, message.getSignatureLen())  || checkField(nonceString, to_string(*nonce).length())){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Presence of <\"&>"<<'\n';
                    delete[] server_certificate;
                    delete nonce;
                    return false;
                }

                vverbose<<"--> [Converter][verifyMessage] Verification CERTIFICATE success"<<'\n';
                delete[] server_certificate;
                delete nonce;
                break;

            case LOGIN_REQ:
                vverbose<<"--> [Converter][verifyMessage] Check LOGIN_REQ"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                if( message.getUsername().empty() ){

                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Username"<<'\n';
                    return false;
                }
                app = message.getUsername().c_str();

                signature = message.getSignature();

                if (!signature) {
                    verbose << "--> [Converter][verifyMessage] Verification failure: Missing Signature" << '\n';
                    delete nonce;
                    return false;
                }

                if( checkField((const unsigned char*)app,message.getUsername().length()) || checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }
                delete[] signature;
                delete nonce;
                vverbose<<"--> [Converter][verifyMessage] Verification LOGIN_REQ success"<<'\n';
                break;

            case LOGIN_OK:
                vverbose<<"--> [Converter][verifyMessage] Check LOGIN_OK"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                signature = message.getSignature();
                if( !signature ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Signature"<<'\n';
                    delete nonce;
                    return false;
                }

                if( checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }
                delete[] signature;
                delete nonce;
                vverbose<<"--> [Converter][verifyMessage] Verification LOGIN_OK success"<<'\n';
                break;

            case LOGIN_FAIL:
                vverbose<<"--> [Converter][verifyMessage] Check LOGIN_FAIL"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                signature = message.getSignature();
                if( !signature ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Signature"<<'\n';
                    delete nonce;
                    return false;
                }
                if( checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }
                delete[] signature;
                delete nonce;
                vverbose<<"--> [Converter][verifyMessage] Verification LOGIN_FAIL success"<<'\n';
                break;

            case KEY_EXCHANGE:
                vverbose<<"--> [Converter][verifyMessage] Check KEY_EXCHANGE"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                signature = message.getSignature();
                if( !signature ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Signature"<<'\n';
                    delete nonce;
                    return false;
                }

                key = message.getDHkey();
                if( !key ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Diffie-Hellman Parameter"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }

                if( checkField( key , message.getDHkeyLength()) || checkField(signature,message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    delete[] signature;
                    delete[] key;
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification KEY_EXCHANGE success"<<'\n';
                delete nonce;
                delete[] signature;
                delete[] key;
                break;

            case USER_LIST_REQ:
                vverbose<<"--> [Converter][verifyMessage] Check USER_LIST_REQ"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                signature = message.getSignature();
                if( !signature ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Signature"<<'\n';
                    delete nonce;
                    return false;
                }

                if( checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }
                delete[] signature;
                delete nonce;
                vverbose<<"--> [Converter][verifyMessage] Verification USER_LIST_REQ success"<<'\n';
                break;

            case USER_LIST:
                vverbose<<"--> [Converter][verifyMessage] Check USER_LIST"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                signature = message.getSignature();
                if( !signature ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Signature"<<'\n';
                    delete nonce;
                    return false;
                }
                app = message.getUserList().c_str();
                if( checkField((const unsigned char*)app,message.getUserList().length()) || checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }
                delete[] signature;
                delete nonce;

                vverbose<<"--> [Converter][verifyMessage] Verification USER_LIST success"<<'\n';
                break;

            case RANK_LIST_REQ:
                vverbose<<"--> [Converter][verifyMessage] Check RANK_LIST_REQ"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                signature = message.getSignature();
                if( !signature ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Signature"<<'\n';
                    delete nonce;
                    return false;
                }

                if( checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }
                delete[] signature;
                delete nonce;
                vverbose<<"--> [Converter][verifyMessage] Verification RANK_LIST_REQ success"<<'\n';
                break;

            case RANK_LIST:
                vverbose<<"--> [Converter][verifyMessage] Check RANK_LIST"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                signature = message.getSignature();
                if( !signature ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Signature"<<'\n';
                    delete nonce;
                    return false;
                }
                app = message.getRankList().c_str();
                if( checkField((const unsigned char*)app,message.getRankList().length()) || checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }
                delete[] signature;
                delete nonce;
                vverbose<<"--> [Converter][verifyMessage] Verification RANK_LIST success"<<'\n';
                break;

            case MATCH:
                vverbose<<"--> [Converter][verifyMessage] Check MATCH"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                signature = message.getSignature();
                if( !signature ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Signature"<<'\n';
                    delete nonce;
                    return false;
                }
                app = message.getUsername().c_str();
                if( checkField((const unsigned char*)app,message.getUsername().length()) || checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }
                delete[] signature;
                delete nonce;

                vverbose<<"--> [Converter][verifyMessage] Verification MATCH success"<<'\n';
                break;

            case ACCEPT:
                vverbose<<"--> [Converter][verifyMessage] Check ACCEPT"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                signature = message.getSignature();
                if( !signature ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Signature"<<'\n';
                    delete nonce;
                    return false;
                }

                if( message.getAdversary_1().empty()){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Adversary1"<<'\n';
                    delete nonce;
                    return false;
                }
                app = message.getAdversary_1().c_str();

                if( message.getAdversary_2().empty()){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Adversary2"<<'\n';
                    delete nonce;
                    return false;
                }
                app2 = message.getAdversary_2().c_str();

                if( checkField((const unsigned char*)app,message.getAdversary_1().length()) || checkField((const unsigned char*)app2,message.getAdversary_2().length())  || checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }
                delete[] signature;
                delete nonce;
                vverbose<<"--> [Converter][verifyMessage] Verification ACCEPT success"<<'\n';
                break;

            case REJECT:
                vverbose<<"--> [Converter][verifyMessage] Check REJECT"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                signature = message.getSignature();
                if( !signature ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Signature"<<'\n';
                    delete nonce;
                    return false;
                }

                if( message.getAdversary_1().empty()){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Adversary1"<<'\n';
                    delete nonce;
                    return false;
                }
                app = message.getAdversary_1().c_str();

                if( message.getAdversary_2().empty()){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Adversary2"<<'\n';
                    delete nonce;
                    return false;
                }
                app2 = message.getAdversary_2().c_str();

                if( checkField((const unsigned char*)app,message.getAdversary_1().length()) || checkField((const unsigned char*)app2,message.getAdversary_2().length())  || checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }
                delete[] signature;
                delete nonce;
                vverbose<<"--> [Converter][verifyMessage] Verification REJECT success"<<'\n';
                break;

            case WITHDRAW_REQ:
                vverbose<<"--> [Converter][verifyMessage] Check WITHDRAW_REQ"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                signature = message.getSignature();
                if( !signature ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Signature"<<'\n';
                    delete nonce;
                    return false;
                }

                if( checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }
                delete[] signature;
                delete nonce;

                vverbose<<"--> [Converter][verifyMessage] Verification WITHDRAW_REQ success"<<'\n';
                break;

            case WITHDRAW_OK:
                vverbose<<"--> [Converter][verifyMessage] Check WITHDRAW_OK"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                signature = message.getSignature();
                if( !signature ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Signature"<<'\n';
                    delete nonce;
                    return false;
                }

                if( checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }
                delete[] signature;
                delete nonce;
                vverbose<<"--> [Converter][verifyMessage] Verification WITHDRAW_OK success"<<'\n';
                break;

            case LOGOUT_REQ:
                vverbose<<"--> [Converter][verifyMessage] Check LOGOUT_REQ"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                signature = message.getSignature();
                if( !signature ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Signature"<<'\n';
                    delete nonce;
                    return false;
                }

                if( checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }
                delete[] signature;
                delete nonce;
                vverbose<<"--> [Converter][verifyMessage] Verification LOGOUT_REQ success"<<'\n';
                break;

            case LOGOUT_OK:
                vverbose<<"--> [Converter][verifyMessage] Check LOGOUT_OK"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                signature = message.getSignature();
                if( !signature ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Signature"<<'\n';
                    delete nonce;
                    return false;
                }

                if( checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }
                delete[] signature;
                delete nonce;
                vverbose<<"--> [Converter][verifyMessage] Verification LOGOUT_OK success"<<'\n';
                break;

            case GAME_PARAM:
                vverbose<<"--> [Converter][verifyMessage] Check GAME_PARAM"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                signature = message.getSignature();
                if( !signature ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Signature"<<'\n';
                    delete nonce;
                    return false;
                }

                net = message.getNetInformations();
                if( !net ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Net Informations"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }

                key = message.getPubKey();
                if( !key ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Public Key"<<'\n';
                    delete nonce;
                    delete[] signature;
                    delete[] net;
                    return false;
                }

                if( checkField( signature, message.getSignatureLen())  || checkField(net,message.getNetInformationsLength()) || checkField(key,message.getPubKeyLength()) ||  checkField(nonceString,to_string(*nonce).length())) {
                    verbose << "--> [Converter][verifyMessage] Verification failure" << '\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification GAME_PARAM success"<<'\n';
                break;

            case MOVE:
                vverbose<<"--> [Converter][verifyMessage] Check MOVE"<<'\n';

                nonce = message.getCurrent_Token();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                signature = message.getSignature();
                if( !signature ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Signature"<<'\n';
                    delete nonce;
                    return false;
                }

                chosen_column = message.getChosenColumn();
                if( !chosen_column ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Misssing Chosen Column"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }

                if( checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length()) || checkField(chosen_column,message.getChosenColumnLength())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure"<<'\n';
                    delete nonce;
                    delete[] signature;
                    delete[] chosen_column;
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification MOVE success"<<'\n';
                delete nonce;
                delete[] signature;
                delete[] chosen_column;
                break;

            case CHAT:
                vverbose<<"--> [Converter][verifyMessage] Check CHAT"<<'\n';

                nonce = message.getCurrent_Token();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                signature = message.getSignature();
                if( !signature ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Signature"<<'\n';
                    delete nonce;
                    return false;
                }

                chat = message.getMessage();
                if( !chat ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Message"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }

                if( checkField( signature, message.getSignatureLen())  || checkField(chat,message.getMessageLength()) || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure"<<'\n';
                    delete nonce;
                    delete[] signature;
                    delete[] chat;
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification CHAT success"<<'\n';
                delete nonce;
                delete[] signature;
                delete[] chat;
                break;

            case ACK:
                vverbose<<"--> [Converter][verifyMessage] Check ACK"<<'\n';

                nonce = message.getCurrent_Token();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                signature = message.getSignature();
                if( !signature ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Signature"<<'\n';
                    delete nonce;
                    return false;
                }

                if( checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }
                vverbose<<"--> [Converter][verifyMessage] Verification ACK success"<<'\n';
                delete nonce;
                delete[] signature;
                break;

            case DISCONNECT:
                vverbose<<"--> [Converter][verifyMessage] Check DISCONNECT"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                signature = message.getSignature();
                if( !signature ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Signature"<<'\n';
                    delete nonce;
                    return false;
                }

                if( checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }
                delete[] signature;
                delete nonce;
                vverbose<<"--> [Converter][verifyMessage] Verification DISCONNECT success"<<'\n';
                break;

            default:
                verbose<<"--> [Converter][verifyMessage] Error message type undefined: " <<type <<'\n';
                return false;
        }
        return true;
    }

    //  verifies the presence of all the fields needed to a given MessageType and that these don't contain a &" element
    bool Converter::verifyCompact(MessageType type , Message message  ){
        vverbose<<"--> [Converter][verifyMessage] Verification of message"<<'\n';
        int* nonce;
        unsigned char* nonceString, *server_certificate,*key,*net,*chosen_column,*chat;
        const char* app,*app2;
        switch( type ){

            case CERTIFICATE_REQ:

                vverbose<<"--> [Converter][verifyCompact] Check CERTIFICATE_REQ"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                if( Converter::checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Presence of <\"&>"<<'\n';
                    return false;
                }
                vverbose<<"--> [Converter][verifyCompact] Verification CERTIFICATE_REQ success"<<'\n';
                break;

            case CERTIFICATE:
                vverbose<<"--> [Converter][verifyCompact] Check CERTIFICATE"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                server_certificate = message.getServerCertificate();
                if( !server_certificate ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Server Certificate"<<'\n';
                    delete nonce;
                    return false;
                }

                if( checkField( server_certificate, message.getServerCertificateLength()) || checkField(nonceString, to_string(*nonce).length())){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Presence of <\"&>"<<'\n';
                    delete[] server_certificate;
                    delete nonce;
                    return false;
                }

                vverbose<<"--> [Converter][verifyCompact] Verification CERTIFICATE success"<<'\n';
                delete[] server_certificate;
                delete nonce;
                break;

            case LOGIN_REQ:
                vverbose<<"--> [Converter][verifyCompact] Check LOGIN_REQ"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                if( message.getUsername().empty() ){

                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Username"<<'\n';
                    return false;
                }
                app = message.getUsername().c_str();


                if( checkField((const unsigned char*)app,message.getUsername().length()) || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    return false;
                }
                delete nonce;
                vverbose<<"--> [Converter][verifyCompact] Verification LOGIN_REQ success"<<'\n';
                break;

            case LOGIN_OK:
                vverbose<<"--> [Converter][verifyCompact] Check LOGIN_OK"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                if( checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    return false;
                }

                delete nonce;
                vverbose<<"--> [Converter][verifyCompact] Verification LOGIN_OK success"<<'\n';
                break;

            case LOGIN_FAIL:
                vverbose<<"--> [Converter][verifyCompact] Check LOGIN_FAIL"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                if( checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    return false;
                }
                delete nonce;
                vverbose<<"--> [Converter][verifyCompact] Verification LOGIN_FAIL success"<<'\n';
                break;

            case KEY_EXCHANGE:
                vverbose<<"--> [Converter][verifyCompact] Check KEY_EXCHANGE"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                key = message.getDHkey();
                if( !key ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Diffie-Hellman Parameter"<<'\n';
                    delete nonce;
                    return false;
                }

                if( checkField( key , message.getDHkeyLength()) || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    delete[] key;
                    return false;
                }
                vverbose<<"--> [Converter][verifyCompact] Verification KEY_EXCHANGE success"<<'\n';
                delete nonce;
                delete[] key;
                break;

            case USER_LIST_REQ:
                vverbose<<"--> [Converter][verifyCompact] Check USER_LIST_REQ"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                if(  checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    return false;
                }
                delete nonce;
                vverbose<<"--> [Converter][verifyCompact] Verification USER_LIST_REQ success"<<'\n';
                break;

            case USER_LIST:
                vverbose<<"--> [Converter][verifyCompact] Check USER_LIST"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                app = message.getUserList().c_str();
                if( checkField((const unsigned char*)app,message.getUserList().length()) || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    return false;
                }
                delete nonce;

                vverbose<<"--> [Converter][verifyCompact] Verification USER_LIST success"<<'\n';
                break;

            case RANK_LIST_REQ:
                vverbose<<"--> [Converter][verifyCompact] Check RANK_LIST_REQ"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                if( checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    return false;
                }
                delete nonce;
                vverbose<<"--> [Converter][verifyCompact] Verification RANK_LIST_REQ success"<<'\n';
                break;

            case RANK_LIST:
                vverbose<<"--> [Converter][verifyCompact] Check RANK_LIST"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                app = message.getRankList().c_str();
                if( checkField((const unsigned char*)app,message.getRankList().length()) || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    return false;
                }
                delete nonce;
                vverbose<<"--> [Converter][verifyCompact] Verification RANK_LIST success"<<'\n';
                break;

            case MATCH:
                vverbose<<"--> [Converter][verifyCompact] Check MATCH"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                app = message.getUsername().c_str();
                if( checkField((const unsigned char*)app,message.getUsername().length()) || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    return false;
                }
                delete nonce;

                vverbose<<"--> [Converter][verifyCompact] Verification MATCH success"<<'\n';
                break;

            case ACCEPT:
                vverbose<<"--> [Converter][verifyCompact] Check ACCEPT"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                if( message.getAdversary_1().empty()){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Adversary1"<<'\n';
                    delete nonce;
                    return false;
                }
                app = message.getAdversary_1().c_str();

                if( message.getAdversary_2().empty()){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Adversary2"<<'\n';
                    delete nonce;
                    return false;
                }
                app2 = message.getAdversary_2().c_str();

                if( checkField((const unsigned char*)app,message.getAdversary_1().length()) || checkField((const unsigned char*)app2,message.getAdversary_2().length())   || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    return false;
                }
                delete nonce;
                vverbose<<"--> [Converter][verifyCompact] Verification ACCEPT success"<<'\n';
                break;

            case REJECT:
                vverbose<<"--> [Converter][verifyCompact] Check REJECT"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                if( message.getAdversary_1().empty()){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Adversary1"<<'\n';
                    delete nonce;
                    return false;
                }
                app = message.getAdversary_1().c_str();

                if( message.getAdversary_2().empty()){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Adversary2"<<'\n';
                    delete nonce;
                    return false;
                }
                app2 = message.getAdversary_2().c_str();

                if( checkField((const unsigned char*)app,message.getAdversary_1().length()) || checkField((const unsigned char*)app2,message.getAdversary_2().length())  || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    return false;
                }
                delete nonce;
                vverbose<<"--> [Converter][verifyCompact] Verification REJECT success"<<'\n';
                break;

            case WITHDRAW_REQ:
                vverbose<<"--> [Converter][verifyCompact] Check WITHDRAW_REQ"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                if( checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    return false;
                }
                delete nonce;

                vverbose<<"--> [Converter][verifyCompact] Verification WITHDRAW_REQ success"<<'\n';
                break;

            case WITHDRAW_OK:
                vverbose<<"--> [Converter][verifyCompact] Check WITHDRAW_OK"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                if( checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    return false;
                }
                delete nonce;
                vverbose<<"--> [Converter][verifyCompact] Verification WITHDRAW_OK success"<<'\n';
                break;

            case LOGOUT_REQ:
                vverbose<<"--> [Converter][verifyCompact] Check LOGOUT_REQ"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                if( checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    return false;
                }
                delete nonce;
                vverbose<<"--> [Converter][verifyCompact] Verification LOGOUT_REQ success"<<'\n';
                break;

            case LOGOUT_OK:
                vverbose<<"--> [Converter][verifyCompact] Check LOGOUT_OK"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                if( checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    return false;
                }
                delete nonce;
                vverbose<<"--> [Converter][verifyCompact] Verification LOGOUT_OK success"<<'\n';
                break;

            case GAME_PARAM:
                vverbose<<"--> [Converter][verifyCompact] Check GAME_PARAM"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                net = message.getNetInformations();
                if( !net ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Net Informations"<<'\n';
                    delete nonce;
                    return false;
                }

                key = message.getPubKey();
                if( !key ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Public Key"<<'\n';
                    delete nonce;
                    delete[] net;
                    return false;
                }

                if( checkField(net,message.getNetInformationsLength()) || checkField(key,message.getPubKeyLength()) ||  checkField(nonceString,to_string(*nonce).length())) {
                    verbose << "--> [Converter][verifyCompact] Verification failure" << '\n';
                    delete nonce;
                    delete[] net;
                    delete[] key;
                    return false;
                }
                vverbose<<"--> [Converter][verifyCompact] Verification GAME_PARAM success"<<'\n';
                delete nonce;
                delete[] net;
                delete[] key;
                break;

            case MOVE:
                vverbose<<"--> [Converter][verifyCompact] Check MOVE"<<'\n';

                nonce = message.getCurrent_Token();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                chosen_column = message.getChosenColumn();
                if( !chosen_column ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Misssing Chosen Column"<<'\n';
                    delete nonce;
                    return false;
                }

                if( checkField(nonceString,to_string(*nonce).length()) || checkField(chosen_column,message.getChosenColumnLength())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure"<<'\n';
                    delete nonce;
                    delete[] chosen_column;
                    return false;
                }
                vverbose<<"--> [Converter][verifyCompact] Verification MOVE success"<<'\n';
                delete nonce;
                delete[] chosen_column;
                break;

            case CHAT:
                vverbose<<"--> [Converter][verifyCompact] Check CHAT"<<'\n';

                nonce = message.getCurrent_Token();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                chat = message.getMessage();
                if( !chat ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Message"<<'\n';
                    delete nonce;
                    return false;
                }

                if( checkField(chat,message.getMessageLength()) || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure"<<'\n';
                    delete nonce;
                    delete[] chat;
                    return false;
                }
                vverbose<<"--> [Converter][verifyCompact] Verification CHAT success"<<'\n';
                delete nonce;
                delete[] chat;
                break;

            case ACK:
                vverbose<<"--> [Converter][verifyCompact] Check ACK"<<'\n';

                nonce = message.getCurrent_Token();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                if( checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure"<<'\n';
                    delete nonce;
                    return false;
                }
                vverbose<<"--> [Converter][verifyCompact] Verification ACK success"<<'\n';
                delete nonce;
                break;

            case DISCONNECT:
                vverbose<<"--> [Converter][verifyCompact] Check DISCONNECT"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Nonce"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                if( checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Presence of <\"&>"<<'\n';
                    delete nonce;
                    return false;
                }
                delete nonce;
                vverbose<<"--> [Converter][verifyCompact] Verification DISCONNECT success"<<'\n';
                break;

            default:
                verbose<<"--> [Converter][verifyCompact] Error message type undefined: " <<type <<'\n';
                return false;
        }
        return true;
    }

    //  translate a Message class into a NetMessage after have controlled the validity of the Message fields
    NetMessage* Converter::encodeMessage(MessageType type , Message message){

        int len;
        unsigned char* value;

        vverbose<<"--> [Converter][encodeMessage] Starting encoding of Message"<<'\n';

        if(!verifyMessage( type, message )){

            verbose<<"--> [Converter][encodeMessage] Error during the verification of the message"<<'\n';
            return nullptr;

        }

        unsigned char* certificate,*key,*net,*sign;
        int* nonce;
        switch( type ){

            case CERTIFICATE_REQ:
                nonce = message.getNonce();
                len = 10+to_string(type).length()+to_string(*nonce).length();
                value = new unsigned char[len];
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str() );
                strcat( (char*)value , "\"&n=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str());
                strcat( (char*)value , "\"");
                break;

            case CERTIFICATE:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 20+to_string(type).length()+to_string(*nonce).length() + message.getServerCertificateLength()+message.getSignatureLen();
                value = new unsigned char[len];
                certificate  = message.getServerCertificate();
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str() );
                strcat( (char*)value , "\"&c=\"");
                strncat( (char*)value , (const char*)certificate , message.getServerCertificateLength());
                strcat( (char*)value , "\"&n=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");
                delete[] sign;
                delete[] certificate;
                break;

            case LOGIN_REQ:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 20+to_string(type).length()+to_string(*nonce).length()+message.getUsername().length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str() );
                strcat( (char*)value , "\"&u=\"");
                strcat( (char*)value , (char*)message.getUsername().c_str() );
                strcat( (char*)value , "\"&n=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");

                delete[] sign;
                break;

            case LOGIN_OK:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 15+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , "\"&n=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");
                delete[] sign;

                break;

            case LOGIN_FAIL:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 15+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , "\"&n=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");
                delete[] sign;

                break;

            case KEY_EXCHANGE:
                nonce = message.getNonce();
                sign = (unsigned char*)message.getSignature();
                len = 16+to_string(type).length()+to_string(*nonce).length()+message.getDHkeyLength()+message.getSignatureLen();
                value = new unsigned char[len];
                key = message.getDHkey();
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , "\"&d=\"");
                strncat( (char*)value , (const char*)key, message.getDHkeyLength());
                strcat( (char*)value , "\"&n=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");
                delete[] sign;

                delete[] key;
                break;

            case USER_LIST_REQ:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 15+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , "\"&n=\"");
                strcat( (char*)value ,to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");
                delete[] sign;

                break;

            case USER_LIST:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 20+to_string(type).length()+to_string(*nonce).length()+message.getUserList().length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , "\"&l=\"");
                strcat( (char*)value , message.getUserList().c_str());
                strcat( (char*)value , "\"&n=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");
                delete[] sign;

                break;

            case RANK_LIST_REQ:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 15+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , "\"&n=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");
                delete[] sign;

                break;

            case RANK_LIST:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 20+to_string(type).length()+to_string(*nonce).length()+message.getRankList().length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , "\"&r=\"");
                strcat( (char*)value , message.getRankList().c_str() );
                strcat( (char*)value , "\"&n=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");
                delete[] sign;

                break;

            case MATCH:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 20+to_string(type).length()+to_string(*nonce).length()+message.getUsername().length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , "\"&u=\"");
                strcat( (char*)value , message.getUsername().c_str());
                strcat( (char*)value , "\"&n=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");
                delete[] sign;

                break;

            case ACCEPT:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 25+to_string(type).length()+to_string(*nonce).length()+message.getAdversary_1().length()+message.getAdversary_2().length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , "\"&a=\"");
                strcat( (char*)value , message.getAdversary_1().c_str() );
                strcat( (char*)value , "\"&b=\"");
                strcat( (char*)value , message.getAdversary_2().c_str() );
                strcat( (char*)value , "\"&n=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");
                delete[] sign;

                break;

            case REJECT:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 25+to_string(type).length()+to_string(*nonce).length()+message.getAdversary_1().length()+message.getAdversary_2().length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , "\"&a=\"");
                strcat( (char*)value , message.getAdversary_1().c_str() );
                strcat( (char*)value , "\"&b=\"");
                strcat( (char*)value , message.getAdversary_2().c_str() );
                strcat( (char*)value , "\"&n=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");
                delete[] sign;

                break;

            case WITHDRAW_REQ:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 20+to_string(type).length()+to_string(*nonce).length()+message.getUsername().length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , "\"&u=\"");
                strcat( (char*)value , message.getUsername().c_str() );
                strcat( (char*)value , "\"&n=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");
                delete[] sign;

                break;

            case WITHDRAW_OK:
                nonce = message.getNonce();
                sign = (unsigned char*)message.getSignature();
                len = 15+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , "\"&n=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");
                delete[] sign;

                break;

            case LOGOUT_REQ:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 15+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , "\"&n=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");
                delete[] sign;

                break;

            case LOGOUT_OK:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 15+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , "\"&n=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");
                delete[] sign;

                break;

            case GAME_PARAM:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 25+to_string(type).length()+to_string(*nonce).length()+message.getPubKeyLength()+message.getNetInformationsLength()+message.getSignatureLen();
                value = new unsigned char[len];
                key = message.getPubKey();
                net = message.getNetInformations();
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , "\"&k=\"");
                strncat( (char*)value , (const char*)key , message.getPubKeyLength());
                strcat( (char*)value , "\"&i=\"");
                strncat( (char*)value , (const char*)net, message.getNetInformationsLength());
                strcat( (char*)value , "\"&n=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");
                delete[] sign;

                delete[] key;
                delete[] net;
                break;

            case MOVE:
                nonce = message.getCurrent_Token();
                sign = message.getSignature();
                len = 20+to_string(type).length()+to_string(*nonce).length()+message.getChosenColumnLength()+message.getSignatureLen();
                key = message.getChosenColumn();
                value = new unsigned char[len];
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , "\"&t=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&v=\"");
                strncat( (char*)value , (const char*)key, message.getChosenColumnLength());
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");
                delete[] sign;

                delete[] key;
                break;

            case CHAT:
                nonce = message.getCurrent_Token();
                sign = message.getSignature();
                len = 20+to_string(type).length()+to_string(*nonce).length()+message.getMessageLength()+message.getSignatureLen();
                value = new unsigned char[len];
                key = message.getMessage();
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , "\"&t=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&h=\"");
                strncat( (char*)value , (const char*)key, message.getMessageLength());
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");
                delete[] sign;

                delete[] key;
                break;

            case ACK:
                nonce = message.getCurrent_Token();
                sign = message.getSignature();
                len = 15+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , "\"&t=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");
                delete[] sign;

                break;

            case DISCONNECT:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 15+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcpy( (char*)value , "y=\"");
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , "\"&n=\"");
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&s=\"");
                strncat( (char*)value , (const char*)sign, message.getSignatureLen());
                strcat( (char*)value , "\"");
                delete[] sign;

                break;

            default:
                return nullptr;
        }
        delete nonce;

        return new NetMessage(value,len);

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

        vverbose<<"--> [Converter][computeNextField] Compute field, position: "<<position<<'\n';
        unsigned char* text = msg.getMessage();
        char field;
        bool found = false;
        int lowPos,highPos = -1;
        unsigned char* value;

        if( position >= msg.length() -3)
            return -1;

        if( text[position+1] == '=' && text[position+2] == '"') {
            field = text[position];
            vverbose<<"--> [Converter][computeNextField] Field founded: "<<field<<" Position: "<<position<<'\n';
        }else
            return -1;

        vverbose<<"-->[Converter][computeNextField] Extracted fieldName: "<<field<<'\n';
        position += 3;
        lowPos = position;
        while( position < msg.length() ){

            if( text[position] == '"' && position >= msg.length()-3 ){
                vverbose<<"--> [Converter][computeNextField] Field founded, Position: "<<position<<'\n';
                highPos = position-1;
                position = position + 2;
                found = true;
                break;
            }

            if( position<msg.length()-2 && text[position] == '"' && text[position+1] == '&'){
                vverbose<<"--> [Converter][computeNextField] Field founded, Position: "<<position<<'\n';
                highPos = position-1;
                position = position + 2;
                found = true;
                break;
            }

            position++;
        }

        int pos = 0;

        if( found ) {
            if( highPos - lowPos == 0 ) {
                value = new unsigned char[2];
                value[0] = '\0';
                value[1] = '\0';
            }else {
                value = new unsigned char[highPos - lowPos + 2];
                for (int a = 0; a < highPos - lowPos + 1; a++)
                    value[a] = '\0';
            }
            for (int a = lowPos; a <= highPos; a++) {
                value[pos] = text[a];
                pos++;
            }
            vverbose<<"--> [Converter][computeNextField] Field value extracted, value: "<<value<<'\n';
            setField(field, value, highPos-lowPos+1, newMessage);
            delete[] value;
            return position;
        }
        verbose<<"--> [Converter][computeNextField] Syntax Error, unable to extract the field"<<'\n';
        return -1;
    }

    //  set a field of a Message class using the encoded information extracted from the NetMessage
    bool Converter::setField( char fieldName , unsigned char* fieldValue , int len , Message* msg ){
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
                msg->setServer_Certificate(fieldValue, len );
                break;
            case 'd':
                vverbose<<"--> [Converter][setField] Identified variable: Diffie-Hellman parameter"<<'\n';
                msg->set_DH_key(fieldValue,len);
                break;
            case 'i':
                vverbose<<"--> [Converter][setField] Identified variable: NetInformations"<<'\n';
                msg->setNetInformations(fieldValue, len);
                break;
            case 'l':
                vverbose<<"--> [Converter][setField] Identified variable: UserList"<<'\n';
                msg->setUserList(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 'k':
                vverbose<<"--> [Converter][setField] Identified variable: Public Key"<<'\n';
                msg->setPubKey(fieldValue,len);
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
                msg->setSignature(fieldValue,len);
                break;
            case 't':
                vverbose<<"--> [Converter][setField] Identified variable: CurrentToken"<<'\n';
                msg->setCurrent_Token(stoi(string(reinterpret_cast<char*>(fieldValue))));
                break;
            case 'v':
                vverbose<<"--> [Converter][setField] Identified variable: ChosenColumn"<<'\n';
                msg->setChosenColumn(fieldValue,len);
                break;
            case 'u':
                vverbose<<"--> [Converter][setField] Identified variable: Username"<<'\n';
                msg->setUsername(string(reinterpret_cast<char*>(fieldValue)));
                break;
            case 'h':
                vverbose<<"--> [Converter][setField] Identified variable: Message"<<'\n';
                msg->setMessage(fieldValue,len);
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
    bool Converter::checkField( const unsigned char* field , int len){
        vverbose<<"--> [Converter][checkField] Verification of Message consistence"<<'\n';
        bool warn = false;

        for( int a= 0; a<len;a++){
            if( field[a] == '&') {
                if (warn) {
                    verbose << "--> [Converter][checkField] Error, sequence \"& founded into the field" << '\n';
                    return true;
                } else {
                    continue;
                }
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
        m->setSignature( (unsigned char*)"signature" ,10 );
        Message* m2 = new Message();
        NetMessage* encoded;

        m->setUsername( "username");
        m->setAdversary_1( "adv_1" );
        m->setAdversary_2( "adv_2" );
        m->setNonce( 13 );
        m->setServer_Certificate( (unsigned char*)"certificate" ,11);
        m->setPubKey( (unsigned char*)"pub_key" ,7 );
        m->setNetInformations( (unsigned char*)"127.0.0.1", 9 );
        m->setCurrent_Token( 13 );
        m->setChosenColumn( (unsigned char*)"column",6 );
        m->setMessage( (unsigned char*)"message" ,7);
        m->set_DH_key( (unsigned char*)"dh_key",6 );
        m->setUserList( "user_list" );
        m->setRankList( "rank_list" );

        m2->setUsername( "us\"&ername");
        m2->setAdversary_1( "adv_1\"&" );
        m2->setAdversary_2( "ad\"&v_2" );
        m2->setNonce( 13 );
        m2->setServer_Certificate( (unsigned char*)"certificat\"&e" ,14);
        m2->setPubKey( (unsigned char*)"pu\"&b_key" ,10);
        m2->setNetInformations( (unsigned char*)"127\"&.0.0.1" ,12 );
        m2->setCurrent_Token( 13 );
        m2->setChosenColumn( (unsigned char*)"column\"&",8 );
        m2->setMessage( (unsigned char*)"mes\"&sage" ,9);
        m2->set_DH_key( (unsigned char*)"\"&dh_key",9 );
        m2->setUserList( "user_list\"&" );
        m2->setRankList( "rank_\"&list" );
        verbose<<"-------------------0--------------------"<<'\n';

        encoded = Converter::encodeMessage(CERTIFICATE_REQ,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(CERTIFICATE,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(LOGIN_REQ,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(LOGIN_OK,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(LOGIN_FAIL,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(KEY_EXCHANGE,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(USER_LIST_REQ,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(USER_LIST,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(RANK_LIST_REQ,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(RANK_LIST,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(MATCH,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(ACCEPT,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(REJECT,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(WITHDRAW_REQ,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(WITHDRAW_OK, *m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(LOGOUT_REQ,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(LOGOUT_OK,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(GAME_PARAM,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(MOVE,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(CHAT,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(ACK,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        encoded = Converter::encodeMessage(DISCONNECT,*m);
        if( encoded == nullptr) return false;
        delete encoded;

        verbose<<"-----------------1---------------"<<'\n';

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

        verbose<<"------------------2--------------"<<'\n';

        encoded = Converter::encodeMessage(CERTIFICATE_REQ,*m);
        if( encoded == nullptr ){
            verbose<<"Error during encoding of CERTIFICATE_REQ"<<'\n';
            return false;
        }

        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != CERTIFICATE_REQ || m2->getNonce() == nullptr ){
            verbose<<"Error during test of CERTIFICATE_REQ"<<'\n';
            return false;
        }

        delete m2;
        delete encoded;
        verbose<<"CERTIFICATE_REQ"<<'\n';

        encoded = Converter::encodeMessage(CERTIFICATE,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of CERTIFICATE"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        verbose<<encoded->length()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != CERTIFICATE || m2->getNonce() == nullptr || m2->getServerCertificate() == nullptr || m2->getSignature() == nullptr ){
            vverbose<<"Error during test of CERTIFICATE"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;
        verbose<<"CERTIFICATE"<<'\n';

        encoded = Converter::encodeMessage(LOGIN_REQ,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of LOGIN_REQ"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != LOGIN_REQ || m2->getNonce() == nullptr || m2->getUsername().empty() || m2->getSignature() == nullptr ){
            vverbose<<"Error during test of LOGIN_REQ"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;
        verbose<<"LOGIN_REQ"<<'\n';

        encoded = Converter::encodeMessage(LOGIN_OK,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of LOGIN_OK"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != LOGIN_OK || m2->getNonce() == nullptr || m2->getSignature() == nullptr ){
            vverbose<<"Error during test of LOGIN_OK"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;

        verbose<<"LOGIN_OK"<<'\n';
        encoded = Converter::encodeMessage(LOGIN_FAIL,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of LOGIN_FAIL"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != LOGIN_FAIL || m2->getNonce() == nullptr || m2->getSignature() == nullptr ){
            vverbose<<"Error during test of LOGIN_FAIL"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;
        verbose<<"LOGIN_FAIL"<<'\n';

        encoded = Converter::encodeMessage(KEY_EXCHANGE,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of KEY_EXCHANGE"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != KEY_EXCHANGE || m2->getNonce() == nullptr || m2->getDHkey() == nullptr   || m2->getSignature() == nullptr ){
            vverbose<<"Error during test of KEY_EXCHANGE"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;
        verbose<<"KEY_EXCHANGE"<<'\n';

        encoded = Converter::encodeMessage(USER_LIST_REQ,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of USER_LIST_REQ"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != USER_LIST_REQ || m2->getNonce() == nullptr ){
            vverbose<<"Error during test of USER_LIST_REQ"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;
        verbose<<"USER_LIST_REQ"<<'\n';

        encoded = Converter::encodeMessage(USER_LIST,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of USER_LIST"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != USER_LIST || m2->getNonce() == nullptr || m2->getUserList().empty() ){
            vverbose<<"Error during test of USER_LIST"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;
        verbose<<"USER_LIST"<<'\n';

        encoded = Converter::encodeMessage(RANK_LIST_REQ,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of RANK_LIST_REQ"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != RANK_LIST_REQ || m2->getNonce() == nullptr  ){
            vverbose<<"Error during test of RANK_LIST_REQ"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;
        verbose<<"RANK_LIST_REQ"<<'\n';

        encoded = Converter::encodeMessage(RANK_LIST,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of RANK_LIST"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != RANK_LIST || m2->getNonce() == nullptr || m2->getRankList().empty() ){
            vverbose<<"Error during test of RANK_LIST"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;
        verbose<<"RANK_LIST"<<'\n';

        encoded = Converter::encodeMessage(MATCH,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of MATCH"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != MATCH || m2->getNonce() == nullptr || m2->getUsername().empty() ){
            vverbose<<"Error during test of MATCH"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;
        verbose<<"MATCH"<<'\n';

        encoded = Converter::encodeMessage(ACCEPT,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of ACCEPT"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != ACCEPT || m2->getNonce() == nullptr || m2->getAdversary_1().empty() || m2->getAdversary_2().empty()){
            vverbose<<"Error during test of ACCEPT"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;
        verbose<<"ACCEPT"<<'\n';

        encoded = Converter::encodeMessage(REJECT,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of REJECT"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != REJECT || m2->getNonce() == nullptr || m2->getAdversary_1().empty() || m2->getAdversary_2().empty() ){
            vverbose<<"Error during test of REJECT"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;
        verbose<<"REJECT"<<'\n';

        encoded = Converter::encodeMessage(WITHDRAW_REQ,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of WITHDRAW_REQ"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != WITHDRAW_REQ || m2->getNonce() == nullptr || m2->getUsername().empty() ){
            vverbose<<"Error during test of WITHDRAW_REQ"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;
        verbose<<"WITHDRAW_REQ"<<'\n';

        encoded = Converter::encodeMessage(WITHDRAW_OK,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of WITHDRAW_OK"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != WITHDRAW_OK || m2->getNonce() == nullptr ){
            vverbose<<"Error during test of WITHDRAW_OK"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;
        verbose<<"WITHDRAW_OK"<<'\n';

        encoded = Converter::encodeMessage(LOGOUT_REQ,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of LOGOUT_REQ"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != LOGOUT_REQ || m2->getNonce() == nullptr ){
            vverbose<<"Error during test of LOGOUT_REQ"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;
        verbose<<"LOGOUT_REQ"<<'\n';

        encoded = Converter::encodeMessage(LOGOUT_OK,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of LOGOUT_OK"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != LOGOUT_OK || m2->getNonce() == nullptr ){
            vverbose<<"Error during test of LOGOUT_OK"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;
        verbose<<"LOGOUT_OK"<<'\n';

        encoded = Converter::encodeMessage(GAME_PARAM,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of GAME_PARAM"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != GAME_PARAM || m2->getNonce() == nullptr || m2->getPubKey() == nullptr || m2->getNetInformations() == nullptr ){
            vverbose<<"Error during test of GAME_PARAM"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;
        verbose<<"GAME_PARAM"<<'\n';

        encoded = Converter::encodeMessage(MOVE,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of MOVE"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != MOVE || m2->getCurrent_Token() == nullptr || m2->getChosenColumn() == nullptr ){
            vverbose<<"Error during test of MOVE"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;
        verbose<<"MOVE"<<'\n';

        encoded = Converter::encodeMessage(CHAT,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of CHAT"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != CHAT || m2->getCurrent_Token() == nullptr || m2->getMessage() == nullptr ){
            vverbose<<"Error during test of CHAT"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;
        verbose<<"CHAT"<<'\n';

        encoded = Converter::encodeMessage(ACK,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of ACK"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != ACK  || m2->getCurrent_Token() == nullptr ){
            vverbose<<"Error during test of ACK"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;
        verbose<<"ACK"<<'\n';

        encoded = Converter::encodeMessage(DISCONNECT,*m);
        if( encoded == nullptr ){
            vverbose<<"Error during encoding of DISCONNECT"<<'\n';
            return false;
        }
        verbose<<encoded->getMessage()<<'\n';
        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != DISCONNECT || m2->getNonce() == nullptr ){
            vverbose<<"Error during test of DISCONNECT"<<'\n';
            return false;
        }
        delete m2;
        delete encoded;
        verbose<<"DISCONNECT"<<'\n';

        delete m;
        return true;

    }

    //  function to easily convert the message in a form that can easily be used to hash messages and create signatures.
    NetMessage* Converter::compactForm(MessageType type, Message message ) {

        int len;
        unsigned char* value;

        vverbose<<"--> [Converter][encodeMessage] Starting encoding of Message"<<'\n';

        if(!verifyCompact( type, message )){

            verbose<<"--> [Converter][encodeMessage] Error during the verification of the message"<<'\n';
            return nullptr;

        }

        unsigned char* certificate,*key,*net;
        int* nonce;
        switch( type ){

            case CERTIFICATE_REQ:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length();
                value = new unsigned char[len];
                strcat((char*)value, to_string(type).c_str() );
                strcat( (char*)value , to_string(*(nonce)).c_str());
                break;

            case CERTIFICATE:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length() + message.getServerCertificateLength()+message.getSignatureLen();
                value = new unsigned char[len];
                certificate  = message.getServerCertificate();
                strcat((char*)value, to_string(type).c_str() );
                strncat( (char*)value , (const char*)certificate , message.getServerCertificateLength());
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                delete[] certificate;
                break;

            case LOGIN_REQ:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getUsername().length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcat((char*)value, to_string(type).c_str() );
                strcat( (char*)value , to_string(*(nonce)).c_str() );

                break;

            case LOGIN_OK:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , to_string(*(nonce)).c_str() );

                break;

            case LOGIN_FAIL:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , to_string(*(nonce)).c_str() );

                break;

            case KEY_EXCHANGE:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getDHkeyLength()+message.getSignatureLen();
                value = new unsigned char[len];
                key = message.getDHkey();
                strcat((char*)value, to_string(type).c_str());
                strncat( (char*)value , (const char*)key, message.getDHkeyLength());
                strcat( (char*)value , to_string(*(nonce)).c_str() );

                delete[] key;
                break;

            case USER_LIST_REQ:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value ,to_string(*(nonce)).c_str() );
                strcat( (char*)value , "\"&s=\"");

                break;

            case USER_LIST:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getUserList().length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , message.getUserList().c_str());
                strcat( (char*)value , to_string(*(nonce)).c_str() );

                break;

            case RANK_LIST_REQ:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , to_string(*(nonce)).c_str() );

                break;

            case RANK_LIST:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getRankList().length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , message.getRankList().c_str() );
                strcat( (char*)value , to_string(*(nonce)).c_str() );

                break;

            case MATCH:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getUsername().length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , message.getUsername().c_str());
                strcat( (char*)value , to_string(*(nonce)).c_str() );

                break;

            case ACCEPT:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getAdversary_1().length()+message.getAdversary_2().length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , message.getAdversary_1().c_str() );
                strcat( (char*)value , message.getAdversary_2().c_str() );
                strcat( (char*)value , to_string(*(nonce)).c_str() );

                break;

            case REJECT:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getAdversary_1().length()+message.getAdversary_2().length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , message.getAdversary_1().c_str() );
                strcat( (char*)value , message.getAdversary_2().c_str() );
                strcat( (char*)value , to_string(*(nonce)).c_str() );

                break;

            case WITHDRAW_REQ:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getUsername().length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , message.getUsername().c_str() );
                strcat( (char*)value , to_string(*(nonce)).c_str() );

                break;

            case WITHDRAW_OK:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , to_string(*(nonce)).c_str() );

                break;

            case LOGOUT_REQ:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , to_string(*(nonce)).c_str() );

                break;

            case LOGOUT_OK:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , to_string(*(nonce)).c_str() );

                break;

            case GAME_PARAM:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getPubKeyLength()+message.getNetInformationsLength()+message.getSignatureLen();
                value = new unsigned char[len];
                key = message.getPubKey();
                net = message.getNetInformations();
                strcat((char*)value, to_string(type).c_str());
                strncat( (char*)value , (const char*)key , message.getPubKeyLength());
                strncat( (char*)value , (const char*)net, message.getNetInformationsLength());
                strcat( (char*)value , to_string(*(nonce)).c_str() );

                delete[] key;
                delete[] net;
                break;

            case MOVE:
                nonce = message.getCurrent_Token();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getChosenColumnLength()+message.getSignatureLen();
                key = message.getChosenColumn();
                value = new unsigned char[len];
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strncat( (char*)value , (const char*)key, message.getChosenColumnLength());

                delete[] key;
                break;

            case CHAT:
                nonce = message.getCurrent_Token();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getMessageLength()+message.getSignatureLen();
                value = new unsigned char[len];
                key = message.getMessage();
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , to_string(*(nonce)).c_str() );
                strncat( (char*)value , (const char*)key, message.getMessageLength());

                delete[] key;
                break;

            case ACK:
                nonce = message.getCurrent_Token();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , to_string(*(nonce)).c_str() );

                break;

            case DISCONNECT:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                strcat((char*)value, to_string(type).c_str());
                strcat( (char*)value , to_string(*(nonce)).c_str() );

                break;

            default:
                return nullptr;
        }
        delete nonce;

        return new NetMessage(value,len);
    }

}