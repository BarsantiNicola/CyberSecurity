#include"Register.h"
#include<limits.h>

//using namespace std;

namespace utility
{ 
   template<typename T>
   Register<T>::Register(){
  /* dataList=vector<T>();
   vector<T>().swap(dataList);*/
   vverbose<<"-->[Register][Costructor] Object created"<<'\n';
   //cout<<"vector size: "<<dataList.size()<<endl;
  }

  template<typename T>
  T* Register<T>::getData(unsigned pos)
  {
    if(pos>= dataList.size()||pos<0)
    {
      verbose<<"-->[Register][getData] Position: "<<(int)pos <<" not valid"<<'\n';
      
      return NULL;
    }
    else
       verbose<<"-->[Register][getData] The data was returned succesfully at the pos "<<(int)pos<<'\n';
      try
      {
        return &dataList.at(pos);
       }
      
      catch(const out_of_range& e)
      {
        verbose<<"-->[Register][getData] error to access on data"<<'\n';
        return NULL;
      }

  }
  template<typename T>
  bool Register<T>::removeData(T data)
  {
    for(int i=0;i<dataList.size();i++)
    {
      if(dataList.at(i)==data)
      {
         vverbose<<"-->[Register][removeData] the data was removed successfully"<<'\n';
         dataList.erase(dataList.begin()+(i));
         return true;
      }
    }
    verbose<<"-->[Register][removeData] data not found"<<'\n';
    return false;
  }


  template<typename T>
  bool Register<T>::addData(T data)
  {
    //cout<<"Previos vector size: "<<dataList.size()<<endl;
    try
    {
      dataList.emplace_back(data);
    }
    catch(const bad_alloc& e)
    {
      verbose<<"-->[Register][addData] Error bad allocation"<<'\n';
      return false;
    }
    vverbose<<"-->[Register][addData] the data was added successfully"<<'\n';
    //cout<<(int)dataList.size()<<endl;
    return true;
  }

  template<typename T>
  Register<T>::~Register()
  {
    vector<T>().swap(dataList);
  }
  template class Register<int>; 

}
