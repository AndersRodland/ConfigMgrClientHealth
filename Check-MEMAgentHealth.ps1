Function Check-MEMAgentHealth {
  param ([Parameter(Mandatory = $true)]$Computers,
      [Parameter(Mandatory = $false)][Switch]$InvokeActions,
      [Parameter(Mandatory = $false)][Switch]$Updates)

  $x = $Computers.Count
  $i = 0
  foreach ($computer in $Computers) {
      Write-Progress -activity "Health Check" -status "Status: " -PercentComplete (($i / $x) * 100)
      Write-host $computer
      $ConnectionTest = test-connection $computer -Count 1 -Quiet
      $i += 0.25
      Write-Progress -activity "Health Check" -status "Status: " -PercentComplete (($i / $x) * 100)
      If ($ConnectionTest -eq $true) {
          test-connection $computer -Count 1 -ErrorAction Stop -Quiet
          Invoke-Command -ComputerName $computer -ScriptBlock {
              
              if (Get-ScheduledTask | Where-Object { $_.TaskName -eq "Health Checking" }) { schtasks /delete /tn "Health Checking" /f }
          }
          If ($Updates -eq $false) {
              Invoke-Command -ComputerName $computer -ScriptBlock {
                  $schedtask = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo>
  <Date>2021-08-10T12:46:22</Date>
  <Author></Author>
  <URI>\HealthCheckingCheck</URI>
</RegistrationInfo>
<Principals>
  <Principal id="Author">
    <UserId>S-1-5-18</UserId>
    <RunLevel>HighestAvailable</RunLevel>
  </Principal>
</Principals>
<Settings>
  <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
  <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
  <ExecutionTimeLimit>P1D</ExecutionTimeLimit>
  <MultipleInstancesPolicy>StopExisting</MultipleInstancesPolicy>
  <IdleSettings>
    <StopOnIdleEnd>false</StopOnIdleEnd>
    <RestartOnIdle>false</RestartOnIdle>
  </IdleSettings>
  <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
</Settings>
<Triggers />
<Actions Context="Author">
  <Exec>
    <Command>Powershell.exe</Command>
    <Arguments>-WindowStyle Hidden -ExecutionPolicy Bypass -File \\INSERTSHAREHERE\ConfigMgrClientHealth.ps1 -Config \\INSERTSHAREHERE\configUpdateCheck.xml</Arguments>
  </Exec>
</Actions>
</Task>
"@
                  Register-ScheduledTask -xml $schedtask -TaskName "Health Checking"
              }
          }
          If ($Updates -eq $true) {
              Invoke-Command -ComputerName $computer -ScriptBlock {
                  $schedtask = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo>
  <Date>2021-08-10T12:46:22</Date>
  <Author></Author>
  <URI>\HealthCheckingCheck</URI>
</RegistrationInfo>
<Principals>
  <Principal id="Author">
    <UserId>S-1-5-18</UserId>
    <RunLevel>HighestAvailable</RunLevel>
  </Principal>
</Principals>
<Settings>
  <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
  <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
  <ExecutionTimeLimit>P1D</ExecutionTimeLimit>
  <MultipleInstancesPolicy>StopExisting</MultipleInstancesPolicy>
  <IdleSettings>
    <StopOnIdleEnd>false</StopOnIdleEnd>
    <RestartOnIdle>false</RestartOnIdle>
  </IdleSettings>
  <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
</Settings>
<Triggers />
<Actions Context="Author">
  <Exec>
    <Command>Powershell.exe</Command>
    <Arguments>-WindowStyle Hidden -ExecutionPolicy Bypass -File \\INSERTSHAREHERE\ConfigMgrClientHealth.ps1 -Config \\INSERTSHAREHERE\configUpdateFix.xml</Arguments>
  </Exec>
</Actions>
</Task>
"@
                  Register-ScheduledTask -xml $schedtask -TaskName "Health Checking"

              }
          }
          Invoke-Command -ComputerName $computer -ScriptBlock {
              $i += 0.25
              Write-Progress -activity "Health Check" -status "Status: " -PercentComplete (($i / $x) * 100)
              Start-Sleep -Seconds 5
              Get-ScheduledTask -TaskName "Health Checking" | Start-ScheduledTask
              do {
                  Start-Sleep -Seconds 5
                  $schedtask = Get-ScheduledTask -TaskName "Health Checking"
                  $TaskState = $schedtask.State
              }
              until ($TaskState -eq "Ready")
              $i += 0.25
              Write-Progress -activity "Health Check" -status "Status: " -PercentComplete (($i / $x) * 100)
              Start-Sleep -Seconds 5
              schtasks /delete /tn "Health Checking" /f
          } -ErrorAction SilentlyContinue
          If ($InvokeActions -eq $true) {
              Invoke-WMIMethod -ComputerName $computer -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000021}" -ErrorAction SilentlyContinue
              Invoke-WMIMethod -ComputerName $computer -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000022}" -ErrorAction SilentlyContinue
              Invoke-WMIMethod -ComputerName $computer -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000026}" -ErrorAction SilentlyContinue
              Invoke-WMIMethod -ComputerName $computer -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000027}" -ErrorAction SilentlyContinue
              Invoke-WMIMethod -ComputerName $computer -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000121}" -ErrorAction SilentlyContinue
              Invoke-WMIMethod -ComputerName $computer -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000113}" -ErrorAction SilentlyContinue
              Invoke-WMIMethod -ComputerName $computer -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000114}" -ErrorAction SilentlyContinue
              Invoke-WMIMethod -ComputerName $computer -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000001}" -ErrorAction SilentlyContinue 
          }
          $i += 0.25
          Write-Progress -activity "Health Check" -status "Status: " -PercentComplete (($i / $x) * 100)
      }
  }

  <#
.SYNOPSIS
Runs health check on ConfigMGR Client

.DESCRIPTION
Runs health check on ConfigMGR Client and upgrade to current version if less than current version
It will also attempt to repair BITS, DNS, Updates missing, Free Space, WMI, Windows Update Agent, select services.
Also advise of drivers that are an issue and pending reboot

.PARAMETER Computers
Specify single or multiple computers to run agains. This is manadatory

.PARAMETER InvokeActions
This will run on the specified systems the following ConfigMGR Agent actions: Machine Policy Retrieval & Evaluation Cycle, User Policy Retrieval & Evaluation Cycle, Application Deployment Evaluation Cycle, Software Update Scan, Software Update Deployment Evaluation Cycle

.PARAMETER Updates
This will change behaviour from checking if select updates are missing to installing these missing updates.

.INPUTS
None. You cannot pipe objects to Add-Extension.

.OUTPUTS


.EXAMPLE
PS> Check-MEMAgentHealth -Computer Computer1

.EXAMPLE
PS> Check-MEMAgentHealth -Computer "Computer1","Computer2","Computer3"

.EXAMPLE
PS> Check-MEMAgentHealth -Computer Computer1 -InvokeActions

.EXAMPLE
PS> Check-MEMAgentHealth -Computer Computer1 -Updates

.EXAMPLE
PS> Check-MEMAgentHealth -Computer Computer1 -InvokeActions -Updates

.EXAMPLE
PS> Check-MEMAgentHealth -Computer "Computer1","Computer2","Computer3" -InvokeActions -Updates

#>
}
