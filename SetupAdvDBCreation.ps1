# Setup how you want the database info:

$DatabaseName = 'ClientHealth'
$ConfigurationTableName = 'Configuration'
$ClientsTableName = 'Clients'

$SqlFileContent = Get-Content -Path .\CreateDatabaseAdv.sql
$UpdatedCommand = $SqlFileContent -replace '{DatabaseName}', $DatabaseName -replace '{Configuration}', $ConfigurationTableName -replace '{Clients}', $ClientsTableName

Out-File -InputObject $UpdatedCommand -FilePath .\CreateDatabaseAdv_Custom.sql -Force