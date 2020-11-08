
#include "Converter.h"

namespace utility{

    //  verifies the presence of all the fields needed to a given MessageType and that these don't contain a &" element
    bool Converter::verifyMessage(MessageType type , Message message  ){

        vverbose<<"--> [Converter][verifyMessage] Verification of message"<<'\n';
        int* nonce,*port;
        unsigned char* nonceString, portString,*server_certificate,*signature,*key,*net,*chosen_column,*chat,*list;
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

                port = message.getPort();
                if( !port ){

                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Port"<<'\n';
                    return false;
                }

                signature = message.getSignature();

                if (!signature) {
                    verbose << "--> [Converter][verifyMessage] Verification failure: Missing Signature" << '\n';
                    delete port;
                    delete nonce;
                    return false;
                }

                if( checkField((const unsigned char*)app,message.getUsername().length()) || checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Presence of <\"&>"<<'\n';
                    delete port;
                    delete nonce;
                    delete[] signature;
                    return false;
                }
                delete[] signature;
                delete port;
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

                list = message.getUserList();
                if( !list ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing User List"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }

                if( checkField( list,message.getUserListLen()) || checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length())) {
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

                list = message.getRankList();
                if( !list ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing User List"<<'\n';
                    delete nonce;
                    delete[] signature;
                    return false;
                }

                list = message.getRankList();
                if( checkField( list , message.getRankListLen()) || checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length())) {
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

                if( message.getUsername().empty()){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Adversary1"<<'\n';
                    delete nonce;
                    return false;
                }
                app = message.getUsername().c_str();

                if( checkField( signature, message.getSignatureLen())  || checkField(nonceString,to_string(*nonce).length()) ||  checkField((unsigned char*)app,message.getUsername().length()) ) {
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

            case GAME:
                verbose<<"--> [Converter][verifyMessage] Check GAME"<<'\n';

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
                
                vverbose<<"--> [Converter][verifyMessage] Verification GAME success"<<'\n';
                delete nonce;
                delete[] signature;
                delete[] chosen_column;
                break;

            case MOVE:
                vverbose<<"--> [Converter][verifyMessage] Check MOVE"<<'\n';

                nonce = message.getCurrent_Token();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Current Token\""<<'\n';
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
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Chosen Column"<<'\n';
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
                delete nonce;
                delete[] signature;
                delete[] chosen_column;
                vverbose<<"--> [Converter][verifyMessage] Verification MOVE success"<<'\n';
                break;

            case CHAT:
                vverbose<<"--> [Converter][verifyMessage] Check CHAT"<<'\n';

                nonce = message.getCurrent_Token();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Current Token\""<<'\n';
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
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Current Token"<<'\n';
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

            case ERROR:
                vverbose<<"--> [Converter][verifyMessage] Check ERROR"<<'\n';

                nonce = message.getNonce();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Nonce\""<<'\n';
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
                vverbose<<"--> [Converter][verifyMessage] Verification ERROR success"<<'\n';
                delete nonce;
                delete[] signature;
                delete[] chat;
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
        int* nonce,*port;
        unsigned char* nonceString, *server_certificate,*key,*net,*chosen_column,*chat,*list;
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

                port = message.getPort();
                if( !port ){

                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Port"<<'\n';
                    delete nonce;
                    return false;
                }

                if( message.getUsername().empty() ){

                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Username"<<'\n';
                    delete nonce;
                    delete port;
                    return false;
                }
                app = message.getUsername().c_str();


                if( checkField((const unsigned char*)app,message.getUsername().length()) || checkField(nonceString,to_string(*nonce).length())) {
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Presence of <\"&>"<<'\n';
                    delete port;
                    delete nonce;
                    return false;
                }
                delete port;
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

                list = message.getUserList();
                if( checkField( list ,message.getUserListLen()) || checkField(nonceString,to_string(*nonce).length())) {
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

                list = message.getRankList();
                if( checkField( list ,message.getRankListLen()) || checkField(nonceString,to_string(*nonce).length())) {
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

                if( message.getUsername().empty()){
                    verbose<<"--> [Converter][verifyMessage] Verification failure: Missing Adversary1"<<'\n';
                    delete nonce;
                    return false;
                }
                app = message.getUsername().c_str();

                if( checkField(nonceString,to_string(*nonce).length()) ||  checkField((unsigned char*)app,message.getUsername().length()) ) {
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

            case GAME:
                verbose<<"--> [Converter][verifyCompact] Check GAME"<<'\n';

                nonce = message.getCurrent_Token();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Current Token\""<<'\n';
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

                vverbose<<"--> [Converter][verifyCompact] Verification GAME success"<<'\n';
                delete nonce;
                delete[] chosen_column;
                break;

            case MOVE:
                vverbose<<"--> [Converter][verifyCompact] Check MOVE"<<'\n';

                nonce = message.getCurrent_Token();
                if( !nonce ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Current Token"<<'\n';
                    return false;
                }
                nonceString = (unsigned char*)to_string(*nonce).c_str();

                chosen_column = message.getChosenColumn();
                if( !chosen_column ){
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Chosen Column"<<'\n';
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
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Current Token"<<'\n';
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
                    verbose<<"--> [Converter][verifyCompact] Verification failure: Missing Current Token"<<'\n';
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

            case ERROR:
                vverbose<<"--> [Converter][verifyCompact] Check ERROR"<<'\n';

                nonce = message.getNonce();
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
                vverbose<<"--> [Converter][verifyCompact] Verification ERROR success"<<'\n';
                delete nonce;
                delete[] chat;
                break;
            default:
                verbose<<"--> [Converter][verifyCompact] Error message type undefined: " <<type <<'\n';
                return false;
        }
        return true;
    }

    //  translate a Message class into a NetMessage after have controlled the validity of the Message fields
    NetMessage* Converter::encodeMessage(MessageType type , Message message){

        int len = 0;
        unsigned char* value;


        vverbose<<"--> [Converter][encodeMessage] Starting encoding of Message"<<'\n';

        if(!verifyMessage( type, message )){

            verbose<<"--> [Converter][encodeMessage] Error during the verification of the message"<<'\n';
            return nullptr;

        }

        unsigned char* certificate,*key,*net,*sign,*chat;
        int* nonce,*port;
        int pos;
        switch( type ){

            case CERTIFICATE_REQ:
                nonce = message.getNonce();
                len = 13+to_string(type).length()+to_string(*nonce).length();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0,false  );
                pos = writeField(value , 'n', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,true  );
                break;

            case CERTIFICATE:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 29+to_string(type).length()+to_string(*nonce).length() + message.getServerCertificateLength()+message.getSignatureLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                certificate  = message.getServerCertificate();
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 'c', certificate,message.getServerCertificateLength(),pos, false  );
                pos = writeField(value , 'n', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );

                delete[] sign;
                delete[] certificate;
                break;

            case LOGIN_REQ:
                nonce = message.getNonce();
                port = message.getPort();
                sign = message.getSignature();
                len = 37+to_string(type).length()+to_string(*nonce).length()+message.getUsername().length()+message.getSignatureLen()+to_string(*port).length();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 'u', (unsigned char*)message.getUsername().c_str(), message.getUsername().length(), pos, false  );
                pos = writeField(value , 'j', (unsigned char*)to_string(*port).c_str(),to_string(*port).length(),pos,false  );
                pos = writeField(value , 'n', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );
                delete[] sign;
                break;

            case LOGIN_OK:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 21+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 'n', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );
                delete[] sign;

                break;

            case LOGIN_FAIL:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 21+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 'n', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );
                delete[] sign;

                break;

            case KEY_EXCHANGE:
                nonce = message.getNonce();
                sign = message.getSignature();
                key = message.getDHkey();
                len = 29+to_string(type).length()+to_string(*nonce).length()+message.getDHkeyLength()+message.getSignatureLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 'd', key, message.getDHkeyLength(), pos, false  );
                pos = writeField(value , 'n', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(), pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );
                delete[] sign;

                delete[] key;
                break;

            case USER_LIST_REQ:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 21+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 'n', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );
                delete[] sign;

                break;

            case USER_LIST:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 29+to_string(type).length()+to_string(*nonce).length()+message.getUserListLen()+message.getSignatureLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 'l', message.getUserList() ,message.getUserListLen(), pos,false  );
                pos = writeField(value , 'n', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );
                delete[] sign;

                break;

            case RANK_LIST_REQ:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 21+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 'n', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );
                delete[] sign;

                break;

            case RANK_LIST:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 29+to_string(type).length()+to_string(*nonce).length()+message.getRankListLen()+message.getSignatureLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 'r', message.getRankList(), message.getRankListLen(), pos,false  );
                pos = writeField(value , 'n', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(), pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );
                delete[] sign;

                break;

            case MATCH:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 29+to_string(type).length()+to_string(*nonce).length()+message.getUsername().length()+message.getSignatureLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 'u', (unsigned char*)message.getUsername().c_str(), message.getUsername().length(), pos,false  );
                pos = writeField(value , 'n', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(), pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );
                delete[] sign;

                break;

            case ACCEPT:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 37+to_string(type).length()+to_string(*nonce).length()+message.getAdversary_1().length()+message.getAdversary_2().length()+message.getSignatureLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 'a', (unsigned char*)message.getAdversary_1().c_str(), message.getAdversary_1().length(), pos,false  );
                pos = writeField(value , 'b', (unsigned char*)message.getAdversary_2().c_str(), message.getAdversary_2().length(), pos,false  );
                pos = writeField(value , 'n', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(), pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );
                delete[] sign;

                break;

            case REJECT:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 37+to_string(type).length()+to_string(*nonce).length()+message.getAdversary_1().length()+message.getAdversary_2().length()+message.getSignatureLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 'a', (unsigned char*)message.getAdversary_1().c_str(), message.getAdversary_1().length(), pos,false  );
                pos = writeField(value , 'b', (unsigned char*)message.getAdversary_2().c_str(), message.getAdversary_2().length(), pos,false  );
                pos = writeField(value , 'n', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(), pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );
                delete[] sign;

                break;

            case WITHDRAW_REQ:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 29+to_string(type).length()+to_string(*nonce).length()+message.getUsername().length()+message.getSignatureLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 'u', (unsigned char*)message.getUsername().c_str(), message.getUsername().length(), pos,false  );
                pos = writeField(value , 'n', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(), pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );

                delete[] sign;

                break;

            case WITHDRAW_OK:
                nonce = message.getNonce();
                sign = (unsigned char*)message.getSignature();
                len = 21+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 'n', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );
                delete[] sign;

                break;

            case LOGOUT_REQ:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 21+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 'n', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );
                delete[] sign;

                break;

            case LOGOUT_OK:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 21+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 'n', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );
                delete[] sign;

                break;

            case GAME_PARAM:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 37+to_string(type).length()+to_string(*nonce).length()+message.getPubKeyLength()+message.getNetInformationsLength()+message.getSignatureLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                key = message.getPubKey();
                net = message.getNetInformations();
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 'k', key ,message.getPubKeyLength(),pos,false  );
                pos = writeField(value , 'i', net ,message.getNetInformationsLength(),pos,false  );
                pos = writeField(value , 'n', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );
                delete[] sign;
                delete[] key;
                delete[] net;
                break;

            case GAME:
                nonce = message.getCurrent_Token();
                sign = message.getSignature();
                len = 29+to_string(type).length()+to_string(*nonce).length()+message.getChosenColumnLength()+message.getSignatureLen()+message.getSignatureAESLen();
                key = message.getChosenColumn();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 't', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeField(value , 'v', key,message.getChosenColumnLength(),pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,false );
                if( message.getSignatureAESLen() != 0 ) 
                	pos = writeField(value, 'w' , message.getSignatureAES(), message.getSignatureAESLen(), pos , true );
                delete[] sign;

                delete[] key;
                break;

            case MOVE:
                nonce = message.getCurrent_Token();
                sign = message.getSignature();
                len = 29+to_string(type).length()+to_string(*nonce).length()+message.getChosenColumnLength()+message.getSignatureLen()+message.getSignatureAESLen();
                key = message.getChosenColumn();

                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 't', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeField(value , 'v', key,message.getChosenColumnLength(),pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );
                delete[] sign;
                delete[] key;
                break;

            case CHAT:
                nonce = message.getCurrent_Token();
                sign = message.getSignature();
                len = 29+to_string(type).length()+to_string(*nonce).length()+message.getMessageLength()+message.getSignatureLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                key = message.getMessage();
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 't', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeField(value , 'h', key, message.getMessageLength(), pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );
                delete[] sign;

                delete[] key;
                break;

            case ACK:
                nonce = message.getCurrent_Token();
                sign = message.getSignature();
                len = 21+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 't', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );
                delete[] sign;

                break;

            case DISCONNECT:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 21+to_string(type).length()+to_string(*nonce).length()+message.getSignatureLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 'n', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );
                delete[] sign;

                break;
            case ERROR:
                nonce = message.getNonce();
                sign = message.getSignature();
                len = 29+to_string(type).length()+to_string(*nonce).length()+message.getMessageLength()+message.getSignatureLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                key = message.getMessage();
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeField(value , 'y', (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeField(value , 'n', (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeField(value , 'h', key, message.getMessageLength(), pos,false  );
                pos = writeField(value , 's', sign, message.getSignatureLen(), pos,true  );
                delete[] sign;

                delete[] key;
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

            if( text[position] == '"' && position == msg.length()-2 ){
                vverbose<<"--> [Converter][computeNextField] Field founded, Position: "<<position<<'\n';
                highPos = position-1;
                position = position + 2;
                found = true;
                break;
            }

            if( position<msg.length()-5 && text[position] == '"' && text[position+1] == '&' && text[position+2] == '&' && text[position+3] == '&' && text[position+4] == '&'){
                vverbose<<"--> [Converter][computeNextField] Field founded, Position: "<<position<<'\n';
                highPos = position-1;
                position = position + 5;
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
                for (int a = 0; a < highPos - lowPos+2; a++)
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
                msg->setUserList(fieldValue , len );
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
                msg->setRankList(fieldValue , len);
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
            case 'w':
                vverbose<<"--> [Converter][setField] Identified variable: Signature AES"<<'\n';
                msg->setSignatureAES( fieldValue, len );
                break;
            case 'j':
                vverbose<<"--> [Converter][setField] Identified variable: UDP Port"<<'\n';
                msg->setPort( stoi(string(reinterpret_cast<char*>(fieldValue))) );
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

        for( int a= 4; a<len;a++)
            if( field[a] == '&'&& field[a-1] == '&' && field[a-2] == '&' && field[a-3] == '&' && field[a-4] == '"' ) {
                verbose << "--> [Converter][checkField] Error, sequence \"&&&& founded into the field: ";
                for(int a = 0; a<len;a++)
                	verbose<<field[a];
                verbose<< '\n';
                return true;
            }

        vverbose<<"--> [Converter][checkField] Verification success"<<'\n';
        return false;
    }

    //  example of usage of the class Converter and testing of its functionality
    bool Converter::test(){
        Message* m = new Message();
        m->setSignature( (unsigned char*)"signature12345" ,14 );
        Message* m2 = new Message();
        NetMessage* encoded;

        m->setUsername( "username_prova");
        m->setAdversary_1( "adv_1" );
        m->setAdversary_2( "adv_2" );
        m->setNonce( 13 );
        m->setServer_Certificate( (unsigned char*)"certifirrrrcate" ,15);
        m->setPubKey( (unsigned char*)"pub_key" ,7 );
        m->setNetInformations( (unsigned char*)"127.0.0.1", 9 );
        m->setCurrent_Token( 13 );
        m->setChosenColumn( (unsigned char*)"column",6 );
        m->setMessage( (unsigned char*)"message" ,7);
        m->set_DH_key( (unsigned char*)"dh_key",6 );
        m->setUserList( (unsigned char*)"user_list" , 9 );
        m->setRankList( (unsigned char*)"rank_list" , 9);

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
        m2->setUserList( (unsigned char*)"user_list\"&" , 11);
        m2->setRankList( (unsigned char*)"rank_\"&list" , 11);
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

        encoded = Converter::encodeMessage(ERROR,*m);
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
        if( Converter::encodeMessage(ERROR,*m2)!= nullptr) return false;
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
        if( m2->getMessageType() != USER_LIST || m2->getNonce() == nullptr || m2->getUserList() == nullptr ){
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
        if( m2->getMessageType() != RANK_LIST || m2->getNonce() == nullptr || m2->getRankList() == nullptr ){
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

        encoded = Converter::encodeMessage(ERROR,*m);
        if( encoded == nullptr ){
            verbose<<"Error during encoding of ERROR"<<'\n';
            return false;
        }

        m2 = Converter::decodeMessage(*encoded);
        if( m2->getMessageType() != ERROR || m2->getNonce() == nullptr ){
            verbose<<"Error during test of ERROR"<<'\n';
            return false;
        }

        delete m2;
        delete encoded;
        verbose<<"ERROR"<<'\n';

        delete m;
        return true;

    }

    //  function to easily convert the message in a form that can easily be used to hash messages and create signatures.
    NetMessage* Converter::compactForm(MessageType type, Message message ) {

        int len;
        unsigned char *value;

        vverbose << "--> [Converter][compactForm] Starting encoding of Message" << '\n';

        if (!verifyCompact(type, message)){

            verbose<<"--> [Converter][compactForm] Error during the verification of the message"<<'\n';
            return nullptr;

        }

        unsigned char* certificate,*key,*net;
        int* nonce,*port;
        int pos;
        switch( type ){

            case CERTIFICATE_REQ:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value ,  (unsigned char*)to_string(type).c_str(),to_string(type).length(),0,false  );
                pos = writeCompactField(value ,  (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,true  );
                break;

            case CERTIFICATE:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length() + message.getServerCertificateLength();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                certificate  = message.getServerCertificate();
                pos = writeCompactField(value ,  (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value ,  certificate,message.getServerCertificateLength(),pos, false  );
                pos = writeCompactField(value ,  (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,true  );

                delete[] certificate;
                break;

            case LOGIN_REQ:
                nonce = message.getNonce();
                port = message.getPort();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getUsername().length()+to_string(*port).length();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value ,  (unsigned char*)message.getUsername().c_str(), message.getUsername().length(), pos, false  );
                pos = writeCompactField(value ,  (unsigned char*)to_string(*port).c_str(),to_string(*port).length(),pos,false );
                pos = writeCompactField(value ,  (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,true  );

                break;

            case LOGIN_OK:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,true  );

                break;

            case LOGIN_FAIL:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,true  );

                break;

            case KEY_EXCHANGE:
                nonce = message.getNonce();
                key = message.getDHkey();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getDHkeyLength();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , key, message.getDHkeyLength(), pos, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(), pos,true  );

                delete[] key;
                break;

            case USER_LIST_REQ:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,true  );

                break;

            case USER_LIST:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getUserListLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , message.getUserList(),message.getUserListLen(), pos,false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,true  );

                break;

            case RANK_LIST_REQ:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,true  );

                break;

            case RANK_LIST:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getRankListLen();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , message.getRankList(), message.getRankListLen(), pos,false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(), pos,true  );

                break;

            case MATCH:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getUsername().length();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)message.getUsername().c_str(), message.getUsername().length(), pos,false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(), pos,true  );

                break;

            case ACCEPT:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getAdversary_1().length()+message.getAdversary_2().length();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)message.getAdversary_1().c_str(), message.getAdversary_1().length(), pos,false  );
                pos = writeCompactField(value , (unsigned char*)message.getAdversary_2().c_str(), message.getAdversary_2().length(), pos,false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(), pos,true  );

                break;

            case REJECT:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getAdversary_1().length()+message.getAdversary_2().length();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)message.getAdversary_1().c_str(), message.getAdversary_1().length(), pos,false  );
                pos = writeCompactField(value , (unsigned char*)message.getAdversary_2().c_str(), message.getAdversary_2().length(), pos,false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(), pos,true  );

                break;

            case WITHDRAW_REQ:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getUsername().length();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)message.getUsername().c_str(), message.getUsername().length(), pos,false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(), pos,true  );

                break;

            case WITHDRAW_OK:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,true  );

                break;

            case LOGOUT_REQ:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,true  );

                break;

            case LOGOUT_OK:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,true  );

                break;

            case GAME_PARAM:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getPubKeyLength()+message.getNetInformationsLength();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                key = message.getPubKey();
                net = message.getNetInformations();
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , key ,message.getPubKeyLength(),pos,false  );
                pos = writeCompactField(value , net ,message.getNetInformationsLength(),pos,false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,true  );
                delete[] key;
                delete[] net;
                break;

            case GAME:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getChosenColumnLength();
                key = message.getChosenColumn();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeCompactField(value , key,message.getChosenColumnLength(),pos,true  );

                delete[] key;
                break;

            case MOVE:
                nonce = message.getCurrent_Token();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getChosenColumnLength();
                key = message.getChosenColumn();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeCompactField(value , message.getMessage(), message.getMessageLength(), pos,false  );
                pos = writeCompactField(value , key,message.getChosenColumnLength(),pos,true  );

                delete[] key;
                break;

            case CHAT:
                nonce = message.getCurrent_Token();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getMessageLength();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                key = message.getMessage();
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeCompactField(value , key, message.getMessageLength(), pos,true  );

                delete[] key;
                break;

            case ACK:
                nonce = message.getCurrent_Token();
                len = 1+to_string(type).length()+to_string(*nonce).length();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,true  );

                break;

            case DISCONNECT:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,true  );

                break;
            case ERROR:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getMessageLength();
                value = new unsigned char[len];
                if( !value ){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                key = message.getMessage();
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeCompactField(value , key, message.getMessageLength(), pos,true  );

                delete[] key;
                break;
            default:
                return nullptr;
        }
        delete nonce;

        return new NetMessage(value,len);

    }

 
/*
compact function for AES
*/
NetMessage* Converter::compactForm(MessageType type, Message message ,int* lengthPlaintext) {

        int len;
        
        unsigned char *value;

        vverbose << "--> [Converter][compactForm] Starting encoding of Message" << '\n';

        if (!verifyCompact(type, message)){

            verbose<<"--> [Converter][compactForm] Error during the verification of the message"<<'\n';
            return nullptr;

        }

        unsigned char* certificate,*key,*net;
        int* nonce;
        int pos;
        switch( type ){

            case CERTIFICATE_REQ:
                nonce = message.getNonce();
                len = to_string(type).length()+to_string(*nonce).length();
                *lengthPlaintext=len;
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value ,  (unsigned char*)to_string(type).c_str(),to_string(type).length(),0,false  );
                pos = writeCompactField(value ,  (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false );
                break;

            case CERTIFICATE:
                nonce = message.getNonce();
                len = to_string(type).length()+to_string(*nonce).length() + message.getServerCertificateLength();
                *lengthPlaintext=len;
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                certificate  = message.getServerCertificate();
                pos = writeCompactField(value ,  (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value ,  certificate,message.getServerCertificateLength(),pos, false  );
                pos = writeCompactField(value ,  (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );

                delete[] certificate;
                break;

            case LOGIN_REQ:
                nonce = message.getNonce();
                len = to_string(type).length()+to_string(*nonce).length()+message.getUsername().length();
                *lengthPlaintext=len;
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value ,  (unsigned char*)message.getUsername().c_str(), message.getUsername().length(), pos, false  );
                pos = writeCompactField(value ,  (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );

                break;

            case LOGIN_OK:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length();
                *lengthPlaintext=len;
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );

                break;

            case LOGIN_FAIL:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length();
                *lengthPlaintext=len;
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );

                break;

            case KEY_EXCHANGE:
                nonce = message.getNonce();
                key = message.getDHkey();
                len = to_string(type).length()+to_string(*nonce).length()+message.getDHkeyLength();
                *lengthPlaintext=len;
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , key, message.getDHkeyLength(), pos, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(), pos,false  );

                delete[] key;
                break;

            case USER_LIST_REQ:
                nonce = message.getNonce();
                len = to_string(type).length()+to_string(*nonce).length();
                *lengthPlaintext=len;
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );

                break;

            case USER_LIST:
                nonce = message.getNonce();
                len = to_string(type).length()+to_string(*nonce).length()+message.getUserListLen();
                *lengthPlaintext=len-message.getUserListLen();
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeCompactField(value , (unsigned char*)message.getUserList(),message.getUserListLen(), pos,false  );
                break;

            case RANK_LIST_REQ:
                nonce = message.getNonce();
                len = to_string(type).length()+to_string(*nonce).length();
                *lengthPlaintext=len;
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );

                break;

            case RANK_LIST:
                nonce = message.getNonce();
                len = to_string(type).length()+to_string(*nonce).length()+message.getRankListLen();
                *lengthPlaintext=len-message.getRankListLen();
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(), pos,false  );
                pos = writeCompactField(value , (unsigned char*)message.getRankList(), message.getRankListLen(), pos,false  );
                break;

            case MATCH:
                nonce = message.getNonce();
                len = to_string(type).length()+to_string(*nonce).length()+message.getUsername().length();
                *lengthPlaintext=len;
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)message.getUsername().c_str(), message.getUsername().length(), pos,false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(), pos,false  );

                break;

            case ACCEPT:
                nonce = message.getNonce();
                len = to_string(type).length()+to_string(*nonce).length()+message.getAdversary_1().length()+message.getAdversary_2().length();
                *lengthPlaintext=len;
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)message.getAdversary_1().c_str(), message.getAdversary_1().length(), pos,false  );
                pos = writeCompactField(value , (unsigned char*)message.getAdversary_2().c_str(), message.getAdversary_2().length(), pos,false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(), pos,false  );

                break;

            case REJECT:
                nonce = message.getNonce();
                len = to_string(type).length()+to_string(*nonce).length()+message.getAdversary_1().length()+message.getAdversary_2().length();
                *lengthPlaintext=len;
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)message.getAdversary_1().c_str(), message.getAdversary_1().length(), pos,false  );
                pos = writeCompactField(value , (unsigned char*)message.getAdversary_2().c_str(), message.getAdversary_2().length(), pos,false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(), pos,false  );

                break;

            case WITHDRAW_REQ:
                nonce = message.getNonce();
                len = to_string(type).length()+to_string(*nonce).length()+message.getUsername().length();
                *lengthPlaintext=len;
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)message.getUsername().c_str(), message.getUsername().length(), pos,false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(), pos,false  );

                break;

            case WITHDRAW_OK:
                nonce = message.getNonce();
                len = to_string(type).length()+to_string(*nonce).length();
                *lengthPlaintext=len;
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );

                break;

            case LOGOUT_REQ:
                nonce = message.getNonce();
                len = to_string(type).length()+to_string(*nonce).length();
                *lengthPlaintext=len;
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );

                break;

            case LOGOUT_OK:
                nonce = message.getNonce();
                len = to_string(type).length()+to_string(*nonce).length();
                *lengthPlaintext=len;
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );

                break;

            case GAME_PARAM:
                nonce = message.getNonce();
                len = to_string(type).length()+to_string(*nonce).length()+message.getPubKeyLength()+message.getNetInformationsLength();
                *lengthPlaintext=len-message.getNetInformationsLength();
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                key = message.getPubKey();
                net = message.getNetInformations();
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , key ,message.getPubKeyLength(),pos,false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeCompactField(value , net ,message.getNetInformationsLength(),pos,false  );
                delete[] key;
                delete[] net;
                break;


            case GAME:
                nonce = message.getNonce();
                len = 1+to_string(type).length()+to_string(*nonce).length()+message.getChosenColumnLength()+message.getSignatureLen();
                key = message.getChosenColumn();
                *lengthPlaintext=len-message.getChosenColumnLength();
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos=writeCompactField(value,message.getSignature(),message.getSignatureLen(),pos,false);
                pos = writeCompactField(value , key,message.getChosenColumnLength(),pos,false );

                delete[] key;
                break;


            case MOVE:
                nonce = message.getCurrent_Token();
                int key_size;
                key_size=0;
                if(message.getSignature()==nullptr)
                {
                  len = to_string(type).length()+to_string(*nonce).length()+message.getChosenColumnLength()+message.getMessageLength()+5;
                  key = concTwoField(message.getChosenColumn(),message.getChosenColumnLength(),message.getMessage(),message.getMessageLength(),(unsigned char)'&',(unsigned int)5);
                  *lengthPlaintext=len-message.getChosenColumnLength()-message.getMessageLength()-5;
                  key_size=message.getChosenColumnLength()+message.getMessageLength()+5;
                }
                else
                {
                   verbose<<"--> [Converter][encodeMessage] we are in decrypt mode."<<'\n';
                   len = to_string(type).length()+to_string(*nonce).length()+message.getChosenColumnLength();
                   key = message.getChosenColumn();
                   *lengthPlaintext=len-message.getChosenColumnLength();
                   key_size=message.getChosenColumnLength();
                }
                if(key==nullptr)
                {
                   verbose<<"--> [Converter][encodeMessage] Error, the key is nullptr"<<'\n';
                  return nullptr;
                }
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e)
                {
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeCompactField(value , key,key_size ,pos,false  );

                delete[] key;
                break;
            case CHAT:
                nonce = message.getCurrent_Token();
                len = to_string(type).length()+to_string(*nonce).length()+message.getMessageLength();
                *lengthPlaintext=len-message.getMessageLength();
                try
                {
                  value = new unsigned char[len];
                }
                catch( std::bad_alloc& e )
                {
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                key = message.getMessage();
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeCompactField(value , key, message.getMessageLength(), pos,false  );

                delete[] key;
                break;

            case ACK:
                nonce = message.getCurrent_Token();
                len = to_string(type).length()+to_string(*nonce).length();
                *lengthPlaintext=len;
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );

                break;

            case DISCONNECT:
                nonce = message.getNonce();
                len = to_string(type).length()+to_string(*nonce).length();
                *lengthPlaintext=len;
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );

                break;
            case ERROR:
                nonce = message.getNonce();
                len = to_string(type).length()+to_string(*nonce).length()+message.getMessageLength();
                *lengthPlaintext=len;
                try
                {
                  value = new unsigned char[len];
                }
                catch(std::bad_alloc& e){
                    verbose<<"--> [Converter][encodeMessage] Error, unable to allocate memory"<<'\n';
                    return nullptr;
                }
                key = message.getMessage();
                for( int a = 0; a<len;a++)
                    value[a] = '\0';
                pos = writeCompactField(value , (unsigned char*)to_string(type).c_str(),to_string(type).length(),0, false  );
                pos = writeCompactField(value , (unsigned char*)to_string(*nonce).c_str(),to_string(*nonce).length(),pos,false  );
                pos = writeCompactField(value , key, message.getMessageLength(), pos,false  );

                delete[] key;
                break;
            default:
                verbose<<"--> [Converter][encodeMessage] No option for this type of message"<<'\n';
                return nullptr;
        }
        delete nonce;

        return new NetMessage(value,len);

    }

    int Converter::writeField( unsigned char* value , char fieldTag , unsigned char* field , int len , int pos , bool finish ) {

        value[pos++] = fieldTag;
        value[pos++] = '=';
        value[pos++] = '"';

        for( int a = 0; a<len;a++)
            value[pos+a] = field[a];

        pos += len;
        value[pos++] = '"';

        if (finish)
            value[pos++] = '\0';
        else{
            value[pos++] = '&';
            value[pos++] = '&';
            value[pos++] = '&';
            value[pos++] = '&';
        }

        return pos;
    }

    int Converter::writeCompactField( unsigned char* value, unsigned char* field , int len , int pos , bool finish ) {
        
        for (int a = 0; a < len; a++)
            value[pos + a] = field[a];
        pos += len;

        if (finish)
            value[pos++] = '\0';

        return pos;
    }
/*
---------------------------concatenateTwoField function--------------------------------------
*/
  unsigned char* Converter::concTwoField(unsigned char* firstField,unsigned int firstFieldSize,unsigned char* secondField,unsigned int secondFieldSize,unsigned char separator,unsigned int numberSeparator)
  {
    if(firstField==nullptr||secondField==nullptr)
      return nullptr;
    int j=0;
    unsigned char* app=new unsigned char[firstFieldSize+secondFieldSize+numberSeparator];
    for(int i=0;i<firstFieldSize;++i)
    {
      app[i]=firstField[i];
    }
    for(int i=firstFieldSize;i<(firstFieldSize+numberSeparator);i++)
    {
      app[i]=separator;
    }
    for(int i=(firstFieldSize+numberSeparator);i<(firstFieldSize+numberSeparator+secondFieldSize);++i)
    {
     
      app[i]=secondField [j];
      ++j;
    }
    return app;
  }


}
