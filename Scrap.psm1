function Get-NetworkAudit {
    param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)][String[]]$ComputerName,
        [parameter(Position=1)][String]$Username = $env:USERNAME,
        [parameter(Mandatory=$true, Position=2)][String]$DefinitionsPath
    )

    begin {
        $rules = (Get-Content -Path $DefinitionsPath | ConvertFrom-Json)
        $commands = ($rules | Select-Object -Unique -Property Command)

        # select JSON_OBJECT('VulnID', VulnID, 'CheckCommand', CheckCommand, 'Pattern', JSON_ARRAYAGG(Pattern)) from audititem join auditpattern using (vulnid) group by VulnID;
        # mysqlsh.exe root@localhost/scrap --sql -e "select JSON_OBJECT('VulnID', VulnID, 'CheckCommand', CheckCommand, 'Pattern', JSON_ARRAYAGG(Pattern)) from audititem join auditpattern using (vulnid) group by VulnID;"
        # mysqlsh.exe root@localhost/scrap --sql -e "select JSON_OBJECT('VulnID', VulnID, 'CheckCommand', CheckCommand, 'Pattern', JSON_ARRAYAGG(Pattern)) from audititem join auditpattern using (vulnid) group by VulnID;" | Select-Object -Skip 1 | ConvertFrom-Json
        # mysqlsh.exe root@localhost/scrap --sql -e "select JSON_OBJECT('VulnID', VulnID, 'CheckCommand', CheckCommand, 'Pattern', JSON_ARRAYAGG(Pattern)) from audititem join auditpattern using (vulnid) group by VulnID;" | Select-Object -Skip 1 | ConvertFrom-Json | ConvertTo-Json | Out-File def2.json
    }

    process {
        $rules;
        $commands;
    }
}