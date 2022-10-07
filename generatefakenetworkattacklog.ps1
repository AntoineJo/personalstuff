

$file = "C:\Users\ajourn\Downloads\query_data_phishandAzure.csv"

$sourceEvents = (get-content $file) | convertfrom-csv

#This is the start time of the network traffic. You can get it from MDE AH with the following query:
# don't forget to update the information related to the URLs
##      DeviceNetworkEvents
##      | where Timestamp > ago(2d) and DeviceId =="d11af611b0b4bf0fb7de060bed072d537055617a"
##      | where RemoteUrl contains "antoinetest.ovh"
##      | order by Timestamp desc

$startTimePhish =  "10/7/22 01:49:20 PM"
$deltaTimePhish = new-timespan -start (get-date($sourceEvents[0].ReceiptTime)) -end (get-date($startTimePhish))

#This is the start time of the network traffic. You can get it from MDE AH with the following query:
# don't forget to update the information related to the URLs
##      DeviceNetworkEvents
##      | where Timestamp > ago(2d) and DeviceId == @"46db1538cc03d01ed67d06ea12601bfb6d101fe4"
##      | where RemoteUrl contains "contosohotelsassets.blob.core.windows.net"
##      | order by Timestamp desc

$startTimeMalware = "10/7/22 02:14:27 PM"
$deltaTimeMalware = new-timespan -start (get-date($sourceEvents[0].ReceiptTime)) -end (get-date($startTimeMalware))

$ipPhish = "20.127.144.13"
$sourceIPPolly = "192.168.2.20"

$ipScript = "52.239.221.68"
$sourceIPKarla = "192.168.2.6"

foreach ($event in $sourceEvents) {
    #$tempEvent = $event
    if ($event.DestinationIP -eq $ipScript) {
        $event.ReceiptTime = (get-date($event.ReceiptTime)).AddDays($deltaTimeMalware.TotalDays)
        $event.'TimeGenerated [UTC]' = (get-date($event.'TimeGenerated [UTC]')).AddDays($deltaTimeMalware.TotalDays)       
        $event.SourceIP = $sourceIPKarla
    }
    elseif ($event.DestinationIP -eq $ipPhish) {
        $event.ReceiptTime = (get-date($event.ReceiptTime)).AddDays($deltaTimePhish.TotalDays)
        $event.'TimeGenerated [UTC]' = (get-date($event.'TimeGenerated [UTC]')).AddDays($deltaTimePhish.TotalDays)
        $event.SourceIP = $sourceIPPolly
    }

    $event.PSObject.Properties.remove("Type")
    $event.PSObject.Properties.remove("_ResourceId")
    $event.PSObject.Properties.remove("TenantId")
    $event.PSObject.Properties.remove("SourceSystem")
    $event.PSObject.Properties.remove("AdditionalExtensions")
}
ConvertTo-Json -InputObject ($sourceEvents  | Where-Object -Property SourceIP -in ($sourceIPPolly,$sourceIPKarla))  > attack.json