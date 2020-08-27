#include"utility/Message.h"
#include<vector>
#include<stdexcept>
#include"Logger.h"
#include"utility/ConnectionManager.h"
#include"utility/NetMessage.h"
#include<stdlib.h>
#include<iostream>
using namespace utility;
int main()
{
  vector<int> vect;
  const char* IP="127.0.0.1";
  int port= 10005;
  bool connectClosed=false;
  int idsock;
  string *s;
  Message m;
  const char *m1=nullptr;
  m.setNonce( 1 );
  m.setMessageType(CERTIFICATE_REQ);
  ConnectionManager connectionman(false,IP,port);
  bool connect=connectionman.createConnectionWithServerTCP("127.0.0.1",10001);
  if(!connect)
  {
    std::cout<<"connection not create"<<endl;
    return 0;
  }
  int sock_serv=connectionman.getserverSocket();
  bool result=connectionman.sendMessage(m,sock_serv,&connectClosed,m1,0);
  std::cout<<"result: "<<result<<endl;
  Message ma;
  const char *c1=nullptr;
  ma.setNonce( 1 );
  ma.setMessageType(CERTIFICATE_REQ);
  if(!connect)
  {
    std::cout<<"connection not create"<<endl;
    return 0;
  }
  sock_serv=connectionman.getserverSocket();
  result=connectionman.sendMessage(ma,sock_serv,&connectClosed,c1,0);
  std::cout<<"result: "<<result<<endl;
 /* while(true)
 /* while(true)
  {
     vect=connectionman.waitForMessage(&idsock,s);
     if(vect.size()!=0)
     {
       for(int i=0;i<vect.size();i++)
       {
         m=connectionman.getMessage(vect.at(i));
         if(m==nullptr)
         {
           cout<<"errore message null";
         }
         std::cout<<m->getNonce()<<endl;
       }
     }
  }*/


}
