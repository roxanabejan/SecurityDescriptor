// SecurityDescriptor.cpp : Defines the entry point for the console application.
//
#pragma comment(lib, "advapi32.lib")

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <aclapi.h>
#include <tchar.h>
#include <iostream>
using namespace std;

HKEY createKey(SECURITY_ATTRIBUTES sa) {
	HKEY hkey;
	DWORD dwDisposition;
	if (RegCreateKeyEx(HKEY_CURRENT_USER,
		TEXT("Software\\NewKey"),
		0, NULL, 0,
		KEY_READ | KEY_WRITE,
		&sa,
		&hkey, &dwDisposition) == ERROR_SUCCESS) {

		_tprintf(TEXT("S-a creat o noua cheie.\n"));
	}
	else {
		printf("Error creating key.\n");
	}
	return hkey;
}

PSID SpcLookupName(LPCTSTR SystemName, LPCTSTR AccountName) {
	PSID         Sid;
	DWORD        cbReferencedDomainName, cbSid;
	LPTSTR       ReferencedDomainName;
	SID_NAME_USE eUse;
	SecureZeroMemory(&Sid, sizeof(Sid));

	cbReferencedDomainName = cbSid = 0;
	if (LookupAccountName(SystemName, AccountName, 0, &cbSid,
		0, &cbReferencedDomainName, &eUse)) {
		SetLastError(ERROR_NONE_MAPPED);
		return 0;
	}
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return 0;

	if (!(Sid = (PSID)LocalAlloc(LMEM_FIXED, cbSid))) return 0;
	ReferencedDomainName = (LPTSTR)LocalAlloc(LMEM_FIXED, cbReferencedDomainName);
	if (!ReferencedDomainName) {
		LocalFree(Sid);
		return 0;
	}

	if (!LookupAccountName(SystemName, AccountName, Sid, &cbSid,
		ReferencedDomainName, &cbReferencedDomainName, &eUse)) {
		LocalFree(ReferencedDomainName);
		LocalFree(Sid);
		return 0;
	}

	LocalFree(ReferencedDomainName);
	return Sid;
}

int main()
{
	HKEY hKey = NULL;
	SECURITY_ATTRIBUTES sa;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	PSID pEveryoneSID = NULL, pOwnerSid = NULL;
	EXPLICIT_ACCESS ea[2];
	LPCTSTR AccountName = TEXT("roxan"); //roxanabejan15@gmail.com
	PACL pACL = NULL, pACL2 = NULL;
	DWORD dwRes;
	PSECURITY_DESCRIPTOR pSD = NULL;
	//hKey = createKey(sa);

	// Create a well-known SID for the Everyone group.
	if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
		SECURITY_WORLD_RID,
		0, 0, 0, 0, 0, 0, 0,
		&pEveryoneSID))
	{
		_tprintf(_T("AllocateAndInitializeSid Error %u\n"), GetLastError());
		goto Cleanup;
	}

	ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));

	pOwnerSid = SpcLookupName(NULL, AccountName);
	if (pOwnerSid == NULL)
		printf("vsdxf\n");
	// Initialize an EXPLICIT_ACCESS structure for an ACE.
	// The ACE will allow the OWNER full access to
	// the key.
	ea[0].grfAccessPermissions = KEY_ALL_ACCESS;
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
	ea[0].Trustee.ptstrName = (LPTSTR)pOwnerSid;

	// Create a new ACL that contains the new ACEs.
	dwRes = SetEntriesInAcl(1, ea, NULL, &pACL);
	if (ERROR_SUCCESS != dwRes)
	{
		_tprintf(_T("SetEntriesInAcl Error %u\n"), GetLastError());
		goto Cleanup;
	}
	// Initialize a security descriptor.  
	pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR,
		SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (NULL == pSD)
	{
		_tprintf(_T("LocalAlloc Error %u\n"), GetLastError());
		goto Cleanup;
	}

	if (!InitializeSecurityDescriptor(pSD,
		SECURITY_DESCRIPTOR_REVISION))
	{
		_tprintf(_T("InitializeSecurityDescriptor Error %u\n"),
			GetLastError());
		goto Cleanup;
	}

	//set owner to security descriptor
	if (SetSecurityDescriptorOwner(pSD, pOwnerSid, FALSE) == FALSE)
	{
		_tprintf(_T("SetSecurityDescriptorOwner Error %u\n"),
			GetLastError());
		goto Cleanup;
	}

	// Add the ACL to the security descriptor. 
	if (!SetSecurityDescriptorDacl(pSD, TRUE, pACL, FALSE))   // not a default DACL 
	{
		_tprintf(_T("SetSecurityDescriptorDacl Error %u\n"),
			GetLastError());
		goto Cleanup;
	}

	// Initialize a security attributes structure.
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = pSD;
	sa.bInheritHandle = FALSE;

	//create key
	hKey = createKey(sa);

	// Initialize an EXPLICIT_ACCESS structure for an ACE.
	// The ACE will allow Everyone read access to the key.
	ea[1].grfAccessPermissions = KEY_READ;
	ea[1].grfAccessMode = SET_ACCESS;
	ea[1].grfInheritance = NO_INHERITANCE;
	ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea[1].Trustee.ptstrName = (LPTSTR)pEveryoneSID;

	// Create a new ACL that contains the new ACEs.
	dwRes = SetEntriesInAcl(2, ea, pACL, &pACL2);
	if (ERROR_SUCCESS != dwRes)
	{
		_tprintf(_T("SetEntriesInAcl Error %u\n"), GetLastError());
		goto Cleanup;
	}

	// Attach the new ACL as the object's DACL.

	dwRes = SetNamedSecurityInfo(TEXT("CURRENT_USER\\Software\\NewKey"), SE_REGISTRY_KEY,
		DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
		NULL, pEveryoneSID, pACL2, NULL);
	if (ERROR_SUCCESS != dwRes) {
		printf("SetNamedSecurityInfo Error %u\n", dwRes);
		goto Cleanup;
	}

	goto Cleanup;
Cleanup:

	if (pEveryoneSID)
		FreeSid(pEveryoneSID);
	if (pOwnerSid)
		FreeSid(pOwnerSid);
	if (pACL)
		LocalFree(pACL);
	if (pSD)
		LocalFree(pSD);
	if (hKey)
		RegCloseKey(hKey);
	return 0;
}

