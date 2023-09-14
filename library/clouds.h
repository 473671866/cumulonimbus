#pragma once
#ifdef NDEBUG

#ifdef _WIN64
#pragma comment(lib, "Clouds64.lib")
#else
#pragma comment(lib, "Clouds32.lib")
#endif

extern "C" int WINAPI Initialization(int ������, int ��·���, const char* ��������, const char* ���������, int ʱ��Ч��ʱ��);	//����������ʼ��
extern "C" int WINAPI InitializationW(int ������, int ��·���, const WCHAR * ��������, const WCHAR * ���������, int ʱ��Ч��ʱ��);
extern "C" int WINAPI Reg(const char* ע����);										//��������ע��
extern "C" int WINAPI RegW(const WCHAR * ע����);
extern "C" int WINAPI SetServer(int ��·���);	     	                            //���������л���������·
extern "C" int WINAPI Trial();								     	                //������������
extern "C" int WINAPI Discount(const char* ע����, int ����);					    //���������۵�
extern "C" int WINAPI DiscountW(const WCHAR * ע����, int ����);
extern "C" int WINAPI Tie(const char* ע����);										//�����������
extern "C" int WINAPI TieW(const WCHAR * ע����);
extern "C" char* WINAPI JData();									                //��������ȡ��̬����
extern "C" WCHAR * WINAPI JDataW();
extern "C" char* WINAPI Tips();									    	            //��������ȡ������ʾ��Ϣ
extern "C" WCHAR * WINAPI TipsW();
extern "C" char* WINAPI QTime();									                //��������ȡ����ʱ��
extern "C" WCHAR * WINAPI QTimeW();
extern "C" int WINAPI ISreg();									                    //���������Ƿ�ע��
extern "C" int WINAPI Areg(int ������, const char* �����ļ���, const char* ��������, const char* ���������, int ʱ��Ч��ʱ��);	     	//���������Զ�ע��
extern "C" int WINAPI AregW(int ������, const WCHAR * �����ļ���, const WCHAR * ��������, const WCHAR * ���������, int ʱ��Ч��ʱ��);
extern "C" int WINAPI Checktime();									                //��������ʱ��Ч��
extern "C" int WINAPI ExitStatus();
extern "C" int WINAPI Timingbox(const char* ��ʾ�ı�, int ʱ��);				    //����������ʱ��Ϣ��
extern "C" int WINAPI TimingboxW(const WCHAR * ��ʾ�ı�, int ʱ��);
extern "C" char* WINAPI GetInfo(int ����);									        //��������ȡ�����Ϣ
extern "C" WCHAR * WINAPI GetInfoW(int ����);
extern "C" char* WINAPI Inquiry(const char* ע����, int ����);						//���������Ʋ�ѯ
extern "C" WCHAR * WINAPI InquiryW(const WCHAR * ע����, int ����);
extern "C" char* WINAPI CodeRecharge(const char* ע����, const char* ��ֵ��);       //ע�����ֵ
extern "C" WCHAR * WINAPI CodeRechargeW(const WCHAR * ע����, const WCHAR * ��ֵ��);
extern "C" char* WINAPI ApiCall(int �������, const char* �����ܳ�, const char* ����);  //���ö�̬����
extern "C" WCHAR * WINAPI ApiCallW(int �������, const WCHAR * �����ܳ�, const WCHAR * ����);
extern "C" int WINAPI IsConnectNet();                                                   //����Ƿ����
extern "C" int WINAPI UserLogin(const char* �û���, const char* ����);                  //�û�ģʽ��¼
extern "C" int WINAPI UserLoginW(const WCHAR * �û���, const WCHAR * ����);
extern "C" int WINAPI UserTie(const char* �û���, const char* ����);                    //�û����
extern "C" int WINAPI UserTieW(const WCHAR * �û���, const WCHAR * ����);
extern "C" int WINAPI UserDiscount(const char* �û���, const char* ����, int ����);       //�û��۵�
extern "C" int WINAPI UserDiscountW(const WCHAR * �û���, const WCHAR * ����, int ����);
extern "C" char* WINAPI UserInquiry(const char* �û���, const char* ����, int ����);    //�û���ѯ
extern "C" WCHAR * WINAPI UserInquiryW(const WCHAR * �û���, const WCHAR * ����, int ����);
extern "C" char* WINAPI UserRegin(const char* �û���, const char* ����, const char* ��ֵ��, const char* ������, const char* ��ϵ��ʽ);       //�û�ע���˺�
extern "C" WCHAR * WINAPI UserReginW(const WCHAR * �û���, const WCHAR * ����, const WCHAR * ��ֵ��, const WCHAR * ������, const WCHAR * ��ϵ��ʽ);
extern "C" char* WINAPI UserRecharge(const char* �û���, const char* ��ֵ��, const char* �Ƽ���);                                             //�û���ֵ
extern "C" WCHAR * WINAPI UserRechargeW(const WCHAR * �û���, const WCHAR * ��ֵ��, const WCHAR * �Ƽ���);
extern "C" char* WINAPI UserUpdatePwd(const char* �û���, const char* ����, const char* ������);                                              //�û�����
extern "C" WCHAR * WINAPI UserUpdatePwdW(const WCHAR * �û���, const WCHAR * ����, const WCHAR * ������);
extern "C" char* WINAPI GetPluginVer();                                                                               //ȡģ��汾��
extern "C" WCHAR * WINAPI GetPluginVerW();
extern "C" char* WINAPI SetData(const char* ע����, int ����, const char* ����);                                      //ע������������
extern "C" WCHAR * WINAPI SetDataW(const WCHAR * ע����, int ����, const WCHAR * ����);
extern "C" char* WINAPI UserSetData(const char* �û���, const char* ����, int ����, const char* ����);                //�û�ģʽ��������
extern "C" WCHAR * WINAPI UserSetDataW(const WCHAR * �û���, const WCHAR * ����, int ����, const WCHAR * ����);
extern "C" int WINAPI MemoryStrFree(char* �ڴ�ָ��);                                                                  //�ͷ��ڴ�

#endif
