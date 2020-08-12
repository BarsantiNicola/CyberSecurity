#include"Register.h"
#include<limits.h>

//using namespace std;

namespace utility
{ 
   template<typename T>
   Register<T>::Register(){
  
   vverbose<<"-->[Register][Costructor] Object created"<<'\n';
  }

  template<typename T>
  T Register<T>::getData(int pos)
  {
    if(pos>= dataList.size()||pos<0)
    {
      verbose<<"-->[Register][getData] Position: "<<pos <<" not valid"<<'\n';
      
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
         vverbose<<"-->[Register][removeData] the data was removed successfully"<<'\n';
         dataList.erase(i);
         return true;
      }
    }
    verbose<<"-->[Register][removeData] data not found"<<'\n';
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
      vverbose<<"-->[Register][addData] Error bad allocation"<<'\n';
      return false;
    }
    vverbose<<"-->[Register][addData] the data was added successfully"<<'\n';
    return true;
  }
  template<typename T>
  Register<T>::~Register()
  {
    vector<T>().swap(dataList);
  }
  
}
