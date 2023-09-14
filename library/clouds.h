#pragma once
#ifdef NDEBUG

#ifdef _WIN64
#pragma comment(lib, "Clouds64.lib")
#else
#pragma comment(lib, "Clouds32.lib")
#endif

extern "C" int WINAPI Initialization(int 软件编号, int 线路编号, const char* 传输密码, const char* 定义机器码, int 时钟效验时间);	//中文名：初始化
extern "C" int WINAPI InitializationW(int 软件编号, int 线路编号, const WCHAR * 传输密码, const WCHAR * 定义机器码, int 时钟效验时间);
extern "C" int WINAPI Reg(const char* 注册码);										//中文名：注册
extern "C" int WINAPI RegW(const WCHAR * 注册码);
extern "C" int WINAPI SetServer(int 线路编号);	     	                            //中文名：切换服务器线路
extern "C" int WINAPI Trial();								     	                //中文名：试用
extern "C" int WINAPI Discount(const char* 注册码, int 点数);					    //中文名：扣点
extern "C" int WINAPI DiscountW(const WCHAR * 注册码, int 点数);
extern "C" int WINAPI Tie(const char* 注册码);										//中文名：解绑
extern "C" int WINAPI TieW(const WCHAR * 注册码);
extern "C" char* WINAPI JData();									                //中文名：取静态数据
extern "C" WCHAR * WINAPI JDataW();
extern "C" char* WINAPI Tips();									    	            //中文名：取操作提示信息
extern "C" WCHAR * WINAPI TipsW();
extern "C" char* WINAPI QTime();									                //中文名：取到期时间
extern "C" WCHAR * WINAPI QTimeW();
extern "C" int WINAPI ISreg();									                    //中文名：是否注册
extern "C" int WINAPI Areg(int 软件编号, const char* 配置文件名, const char* 传输密码, const char* 定义机器码, int 时钟效验时间);	     	//中文名：自动注册
extern "C" int WINAPI AregW(int 软件编号, const WCHAR * 配置文件名, const WCHAR * 传输密码, const WCHAR * 定义机器码, int 时钟效验时间);
extern "C" int WINAPI Checktime();									                //中文名：时间效验
extern "C" int WINAPI ExitStatus();
extern "C" int WINAPI Timingbox(const char* 提示文本, int 时长);				    //中文名：定时信息框
extern "C" int WINAPI TimingboxW(const WCHAR * 提示文本, int 时长);
extern "C" char* WINAPI GetInfo(int 类型);									        //中文名：取软件信息
extern "C" WCHAR * WINAPI GetInfoW(int 类型);
extern "C" char* WINAPI Inquiry(const char* 注册码, int 类型);						//中文名：云查询
extern "C" WCHAR * WINAPI InquiryW(const WCHAR * 注册码, int 类型);
extern "C" char* WINAPI CodeRecharge(const char* 注册码, const char* 充值卡);       //注册码充值
extern "C" WCHAR * WINAPI CodeRechargeW(const WCHAR * 注册码, const WCHAR * 充值卡);
extern "C" char* WINAPI ApiCall(int 函数编号, const char* 调用密匙, const char* 参数);  //调用动态函数
extern "C" WCHAR * WINAPI ApiCallW(int 函数编号, const WCHAR * 调用密匙, const WCHAR * 参数);
extern "C" int WINAPI IsConnectNet();                                                   //检测是否断网
extern "C" int WINAPI UserLogin(const char* 用户名, const char* 密码);                  //用户模式登录
extern "C" int WINAPI UserLoginW(const WCHAR * 用户名, const WCHAR * 密码);
extern "C" int WINAPI UserTie(const char* 用户名, const char* 密码);                    //用户解绑
extern "C" int WINAPI UserTieW(const WCHAR * 用户名, const WCHAR * 密码);
extern "C" int WINAPI UserDiscount(const char* 用户名, const char* 密码, int 点数);       //用户扣点
extern "C" int WINAPI UserDiscountW(const WCHAR * 用户名, const WCHAR * 密码, int 点数);
extern "C" char* WINAPI UserInquiry(const char* 用户名, const char* 密码, int 类型);    //用户查询
extern "C" WCHAR * WINAPI UserInquiryW(const WCHAR * 用户名, const WCHAR * 密码, int 类型);
extern "C" char* WINAPI UserRegin(const char* 用户名, const char* 密码, const char* 充值卡, const char* 代理商, const char* 联系方式);       //用户注册账号
extern "C" WCHAR * WINAPI UserReginW(const WCHAR * 用户名, const WCHAR * 密码, const WCHAR * 充值卡, const WCHAR * 代理商, const WCHAR * 联系方式);
extern "C" char* WINAPI UserRecharge(const char* 用户名, const char* 充值卡, const char* 推荐人);                                             //用户充值
extern "C" WCHAR * WINAPI UserRechargeW(const WCHAR * 用户名, const WCHAR * 充值卡, const WCHAR * 推荐人);
extern "C" char* WINAPI UserUpdatePwd(const char* 用户名, const char* 密码, const char* 新密码);                                              //用户改密
extern "C" WCHAR * WINAPI UserUpdatePwdW(const WCHAR * 用户名, const WCHAR * 密码, const WCHAR * 新密码);
extern "C" char* WINAPI GetPluginVer();                                                                               //取模块版本号
extern "C" WCHAR * WINAPI GetPluginVerW();
extern "C" char* WINAPI SetData(const char* 注册码, int 类型, const char* 数据);                                      //注册码设置数据
extern "C" WCHAR * WINAPI SetDataW(const WCHAR * 注册码, int 类型, const WCHAR * 数据);
extern "C" char* WINAPI UserSetData(const char* 用户名, const char* 密码, int 类型, const char* 数据);                //用户模式设置数据
extern "C" WCHAR * WINAPI UserSetDataW(const WCHAR * 用户名, const WCHAR * 密码, int 类型, const WCHAR * 数据);
extern "C" int WINAPI MemoryStrFree(char* 内存指针);                                                                  //释放内存

#endif
