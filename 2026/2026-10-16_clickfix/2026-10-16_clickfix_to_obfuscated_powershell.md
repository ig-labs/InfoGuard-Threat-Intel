# Summary
During a recent Akira Ransomware case, we observed initial access via ClickFix. The ClickFix was injected into legitimate sites. 
In our case, the site specialised in manufacturing in Germany. Pivoting on the URL in VirusTotal shows multiple affected legitimate sites serving this ClickFix. Initial triage of other affected companies shows a huge proportion of German sites across different industries. In our case, the initial Payload was no longer available; therefore, we can't reconstruct it completely.
However, a similar payload is shown [here](https://www.joesandbox.com/analysis/1979283/0/executive#deviceScreen)
After execution of the initial payload, an obfuscated PowerShell Script is dropped into `C:\ProgramData\Postparenthoodizenesses\yarovizingful.ps1` which fetches commands from a hardcoded C2.
# Authors
Evgen Blohm @ InfoGuard AG
Andreas Klaus @ InfoGuard AG

# Browser Cache Analysis
As the injection of the external JavaScript Library into the legitimate website is short-lived, a post-mortem analysis of the website might not show the reference to the library anymore. Therefore, we recommend analysing the compromised user's local browser history, where the visited website might be cached and show the state as it was during the visit

![[images/browser_cache.png]]

# yarovizingful.ps1
This PowerShell Script is obfuscated and runs through a scheduled task every 38 minutes.
## Behavior
1. Checks whether `C:\ProgramData\Postparenthoodizenesses` exists. Exits if it does not. The script does not create this directory.
2. Checks for the extensionless file `C:\ProgramData\Postparenthoodizenesses\kuQxBercPadcMjfnjzIScFvXFVLBWb`.
	1. If the file exists, reads its entire contents as UTF-8 text and submits them with an HTTP POST. The request body is a hashtable with the field `5SlU8XXSK4qf4lSS`. If the response matches `kuQxBercPadcMjfnjzIScFvXFVLBWb`, deletes the local file and exits. This branch does not explicitly execute the response.
	2. If the file does not exist, issues an HTTP GET. If the returned object's `Length` exceeds one, passes the response to `Invoke-Expression` for execution. The supplied first stage does not explicitly save this response to a file.
3. Both request branches append a random integer from 24333 through 892805 (`Get-Random` has an exclusive maximum) as the `rnd` query parameter.
## Obfuscation
Both scripts encode strings as arithmetic expressions whose results are cast to `[char[]]` and joined using `-join` or `[string]::Concat`. Randomized variable names, alias chains, and concatenations with undeclared filler variables obscure data flow; `irm` is reconstructed from character indices `[3]`, `[2]`, and `[21]` of `ToString.OverloadDefinitions[1]`. Commands are invoked indirectly through the dot invocation operator, while abbreviated parameters (`-Me 'PO' -B`) and a separately assembled `iex` alias conceal HTTP POST requests and execution of downloaded PowerShell.

# Follow-Up Activity
Roughly 9 hours after execution, we observed multiple files with the format `C:\ProgramData\s<single digit char>.log` being written. They contained output from commands used to conduct reconnaissance against the Active Directory Domain.
# Scheduled Task 

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>qualifiersed nonforming oversupremeary xenomorphstions impressionizations unequivocalizedships cardiologyment hieroglyphizations</Description>
    <URI>\Mailboxfulations\Underviablement\Nondisclosurful</URI>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT38M</Interval>
        <Duration>P3650D</Duration>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2026-10-06T13:17:18</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  ...
  <Settings>
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -WindowStyle Minimized -File "C:\ProgramData\Postparenthoodizenesses\yarovizingful.ps1"</Arguments>
    </Exec>
  </Actions>
</Task>
```
# IOCs

| filename              | SHA256                                                           |
| --------------------- | ---------------------------------------------------------------- |
| abolitionizing.ps1    | 42e262849a2f92d26863017532e3b5c62dee6560451c1f26d58f58719572561d |
| wainscotedization.ps1 | 8f7d846aad75b378fc4675af58ec2716ee8c0ac1a8125fe4713b7974a6837f64 |
| rescare.ps1           | a039098be8bb4e2a31a89c2ad1b20278c28bc16f91773c9fbcd201c99301fb9a |
| unchannelless.ps1     | 748f47ff667199488f1553836a9f245dfd41a7c5dc468dd5e04b829a50be30bc |
| yarovizingful.ps1     | baa87f9d629bd6c1cc2326ad498bcf4eecbfbc3dfba6f9af796b2ab25a57196f |
| vendettistism.ps1     | 92764d0d629140f029b95732177c5e252e0a985330d5c58b1f575480e8c478a4 |
| likelihoodships.ps1   | 557a9c2d05b7ae77110bdc4a955f578254379485ced63b028851c4e0a1ca2f08 |

| URL                                                                                                                                          | Description                                       |
| -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| https://facilitateest.com/app/main.js?v=13                                                                                                   | Injected URL into the legitimate site             |
| https://safeguardses.com/aSqfwIjiwigDUHzfEHDXgBQdfgssUaNS/kuQxBercPadcMjfnjzIScFvXFVLBWb.html?5SlU8XXSK4qf4lSS=<marker>&rnd=<random integer> | Base URL in PowerShell Script `yarovizingful.ps1` |

| IP             | Description                                                         |
| -------------- | ------------------------------------------------------------------- |
| 88.80.150.25   | IP to which the C2 and the injected URL resolve                     |
| 176.53.159.182 | Historic IP until 2026-10-11, to which the injected URL resolved to |

# YARA

```
rule OBFUS_PowerShell_join_concat_Oct26 {
	meta:
		creator = "Evgen Blohm @ InfoGuard AG"
		created = "2026-10-14"
		last_modified = "2026-10-15"
		ref = "Internal Research"
		desc = "Detects obfuscated PowerShell delivered via ClickFix. It fetched a next-stage payload from a hardcoded URL"
        hash = "baa87f9d629bd6c1cc2326ad498bcf4eecbfbc3dfba6f9af796b2ab25a57196f"
        
	strings:
		$join = "-join[char[]]"
        $concat = "[string]::Concat("

        $func_1 = "Get-Random -Minimum"
        $func_2 = "Get-Content -LiteralPath"
        $func_3 = "Length -gt 1"

        $footer = "exit"
        
	condition:
		#join > 5 and 
		#concat > 5 and 
		3 of ( $func_* ) and 
		$footer in (filesize - 50 .. filesize) and
		filesize < 30KB
}
```
# Further Links
https://www.joesandbox.com/analysis/1979283/0/executive#deviceScreen