#include<stdexcept>
#include"Logger.h"
#include<vector>
template<typename T>
namespace utility{
 class Register{
  private:
    Verbose threshold = VERBOSE;
  protected:
   vector<T> dataList;
  public:
   Register();
   bool removeData(T);
   ~Register();
  protected:
   bool addData(T);
   T getData(int);
 };
