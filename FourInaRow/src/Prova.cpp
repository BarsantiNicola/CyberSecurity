#include<iostream>
#include"utility/Register.h"
#include "Logger.h"
using namespace utility;
struct prova
{
  int index;
 
};
int main()
{
  Logger::setThreshold( VERY_VERBOSE );
  int p1=1;
  int p2=2;
  Register<int>r;
  r.addData(p1);
  r.addData(p2);
   
  int* p3=r.getData(0);
  
  
  std::cout<<flush;
  std::cout<<"fino a qui tutto funzionante"<<endl;
  if(p3==NULL)
   std::cout<<"il risultato è un puntatore a NULL"<<endl;
  else
   std::cout<<*p3<<endl;
  bool var=r.removeData(1);
  if(var==true)
  {
    std::cout<<"elemento cancellato in modo corretto"<<endl;
  }
  else
  {
    std::cout<<"cancellazione elemeto non riuscita"<<endl;
  }

  p3=r.getData(0);
  
  
  std::cout<<flush;
  std::cout<<"fino a qui tutto funzionante"<<endl;
  if(p3==NULL)
   std::cout<<"il risultato è un puntatore a NULL"<<endl;
  else
   std::cout<<*p3<<endl;
  return 0;
}

