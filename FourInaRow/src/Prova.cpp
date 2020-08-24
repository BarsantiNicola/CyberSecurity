#include<iostream>
#include"utility/Register.h"
#include "Logger.h"
#include "server/ClientInformation.h"
#include "utility/Information.h"
using namespace utility;

int main()
{
  
  
  Logger::setThreshold( VERY_VERBOSE );
  server::ClientInformation c1 (1, "64654664",5);
  Information p1=c1;
  Information p2=c1;
  Register<Information>r;
  r.addData(p1);
  r.addData(p2);
   
  Information* p3=r.getData(p1);
  
  
  std::cout<<flush;
  std::cout<<"fino a qui tutto funzionante"<<endl;
  if(p3==NULL)
   std::cout<<"il risultato è un puntatore a NULL"<<endl;
  else
   std::cout<<"ok"<<endl;
  bool var=r.removeData(p1);
  if(var==true)
  {
    std::cout<<"elemento cancellato in modo corretto"<<endl;
  }
  else
  {
    std::cout<<"cancellazione elemeto non riuscita"<<endl;
  }

  p3=r.getData(p2);
  
  
  std::cout<<flush;
  std::cout<<"fino a qui tutto funzionante"<<endl;
  if(p3==NULL)
   std::cout<<"il risultato è un puntatore a NULL"<<endl;
  else
   std::cout<<"ok"<<endl;
  return 0;
}

