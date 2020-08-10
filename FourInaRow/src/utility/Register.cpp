#include"Register.h"
#include<limits.h>
//using namespace std;

namespace utility
{ 
 /* template<typename T>
   Register::Register(){
  
   // Tramite logger scrivere che l'oggetto è stato creato correttamente
  }*/

  template<typename T>
  T Register<T>::getData(int pos)
  {
    if(pos>= dataList.size()||pos<0)
    {
      //posizione non presente
      
      return NULL;
    }
    else
      return dataList[pos];
  }
  template<typename T>
  bool Register<T>::removeData(T data)
  {
    for(int i=0;i<dataList.size();i++)
    {
      if(dataList[i]==data)
      {
         //scrivere nel log che il dato è stato eliminato
         dataList.erase(i);
         return true;
      }
    }
    return false;
  }
  template<typename T>
  bool Register<T>::addData(T data)
  {
    try
    {
      dataList.emplace_back(data);
    }
    catch(const bad_alloc& e)
    {
      //scrivere l'errore nel log
      return false;
    }
    // scrivere che il dato è stato inserito correttamente
    return true;
  }
  template<typename T>
  Register<T>::~Register()
  {
    vector<T>().swap(dataList);
  }
  
}
