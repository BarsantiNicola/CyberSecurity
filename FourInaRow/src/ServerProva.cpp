#include"utility/Message.h"
#include<vector>
#include<exception>
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
  int port= 10001;
  int idsock;
  std::string s="";
  Message *m;
  
  ConnectionManager connectionman(true,IP,port);
  while(true)
  {
     std::cout<<"siamo entrati nel ciclo"<<endl;
     vect=connectionman.waitForMessage(&idsock,&s);
     std::cout<<"fine prima wait"<<endl;
     if(vect.size()!=0)
     {
       for(int i=0;i<vect.size();i++)
       {
         try
         {
           
           m=connectionman.getMessage(vect.at(i));
           if(m==nullptr)
           {
             cout<<"errore message null";
             return 0;
           }
           std::cout<<m->getUsername()<<endl;
         }
         catch(std::runtime_error)
         {
           std::cout<<"socket "<<vect.at(i)<<" closed"<<endl;
         }
       }
     }
  }
  return 0;

}
