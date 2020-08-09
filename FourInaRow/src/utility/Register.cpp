#include"Register.h"
#include<limits.h>
using namespace std;
namespace utility
{
  Register::Register(){

   // Tramite logger scrivere che l'oggetto è stato creato correttamente
  }


  T Register::getData(int pos)
  {
    if(pos>= dataList.size())
    {
      //posizione non presente
      return NULL;
    }
    else
      return dataList[pos];
  }

  bool Register::removeData(T data)
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

  bool Register::addData(T data)
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
    // scrivere che il dato è stato 
    return true;
  }

  Register:~Register()
  {
    vector<T>().swap(dataList);
  }
  
}
