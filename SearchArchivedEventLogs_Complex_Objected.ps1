#########################################################
#														#
#  Search the archived security event logs for 			#
#  interesting EventIDs from a specifid IPaddress, 		#
#	username or computer								#
#														#################################
#	4624 - successful logon					4625 - Failed Logon							#
#	4634 - Account logoff 					4648 - Explicit Credential					#
#	4778 - Session reconnect				4779 - Session disconnect					#
#	5140 - network share access 			4728 - User Added to security group			#
#	4723 - Admin changed user's password	4729 - User removed from a security group	#
#	4724 - User changed their password		4720 - User Account Created					#
#																						#									
#########################################################################################

"ComputerName,TimeStamp,EventID,CorrelationID,TargetSID,SubjectUsername,TargetUsername,TargetLogonID,LogonType,IPAddress" | out-file -FilePath "c:\temp\Output.csv"  -encoding UTF8

$Controllers="dc1","dc2","dc3"

foreach ($DomainController in $Controllers)
{
(get-childitem \\$DomainController\C$\windows\system32\winevt\logs\archive-security-2019-03-1*).fullname | foreach-object {

	$Logfile=$_
	write-host $LogFile
	$LogFileName="file://"+$LogFile
	
	$query = @"
			<QueryList>
			<Query Id="0" Path="$LogFileName">
			<Select Path="$LogFileName">
			*[System
			 [(EventID=4624 or EventID=4778 or EventID=4625)]
			 and
			 EventData[Data [@Name='TargetUsername'] = '<USERNAME>']
			]
			</Select>
			</Query>
			</QueryList>
"@ 

get-winevent -filterxml $query -erroraction 'SilentlyContinue' -ErrorVariable NoResult | foreach-object {
	$hash=$_
	if ($hash -eq $NULL) 
		{Write-host no results}
		else
		{
			$count=0
			While ($count -ne $hash.count)
			{
				[xml]$Event=$hash[$count].toXML()
				
				$timeCreated=(get-date($Event.Event.System.TimeCreated.systemtime)).addhours(+10) 
				
				$SystemData=$Event.event.system.computer+","+$TimeCreated+","+$event.event.system.EventID+","+$event.event.system.correlation
				
				$selectRecord = $Event.event.eventdata | select -expandproperty childnodes | where {$_.name -match 'SubjectUsername' -or $_.name -match 'TargetUsername' -or $_.name -match 'TargetLogonID' -or $_.name -match 'LogonType' -or $_.name -match 'IpAddress' -or $_.name -match 'TargetUserSid'}	
				
				
				$EventData=$SelectRecord[0].innertext+","+$SelectRecord[1].innertext+","+$SelectRecord[2].innertext+","+$SelectRecord[3].innertext+","+$SelectRecord[4].innertext+","+$SelectRecord[5].innertext+","+$SelectRecord[6].innertext
				
				
				 write-host $SystemData,$EventData
				 "$SystemData,$EventData" | out-file -Append -FilePath "c:\temp\OutPut.csv"  -encoding UTF8
				
			$Count++
			}
		}
	}
}
}
