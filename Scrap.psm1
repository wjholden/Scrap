# Query database for 
# mysqlsh.exe root@localhost/scrap --sql -e "select JSON_OBJECT('VulnID', VulnID, 'CheckCommand', CheckCommand, 'Pattern', JSON_ARRAYAGG(Pattern)) from audititem join auditpattern using (vulnid) group by VulnID;" | select -skip 1 | convertfrom-json

# 
# $definitions = (mysqlsh.exe root@localhost/scrap --sql -e "select JSON_OBJECT('VulnID', VulnID, 'CheckCommand', CheckCommand, 'Pattern', JSON_ARRAYAGG(Pattern)) from audititem join auditpattern using (vulnid) group by VulnID;" | select -skip 1 | convertfrom-json)
# $routers = @('192.168.16.1', '192.168.16.2', '192.168.16.3')

# Serialize definitions to a JSON file
# $definitions | ConvertTo-Json | Out-File 'definitions.json'

function Get-NetworkAudit {
    param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)][String[]]$ComputerName,
        [parameter(Position=1)][String]$Username = $env:USERNAME,
        [parameter(Mandatory=$true, Position=2)]$Definitions,
        [parameter(Position=4)][String]$ssh_executable = 'plink'
    )

    begin {
        # TODO: download rules from the web
        $rules = $Definitions;
        
        # Extract the distinct commands from rules
        $commands = ($rules | Select-Object -Unique CheckCommand).CheckCommand;

        # Check if SSH executable is on the path
        Get-Command $ssh_executable -ErrorAction Stop | Write-Verbose
    }

    process {
        $queries = @{};
        foreach ($computer in $ComputerName) {
            foreach ($command in $commands) {
                $key = $computer + ' ' + $command;
                # plink requires -batch now for this use case. See this article:
                # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-auth-prompt-spoofing.html
                $value = (& $ssh_executable -l $username -ssh -P 22 -batch $computer $command);
                $value | Write-Verbose
                $queries[$key] = $value;
            }
        }

        $queries;
    }
}
