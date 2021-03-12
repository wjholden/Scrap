# Query database for 
# mysqlsh.exe root@localhost/scrap --sql -e "select JSON_OBJECT('VulnID', VulnID, 'CheckCommand', CheckCommand, 'Pattern', JSON_ARRAYAGG(Pattern)) from Item join Pattern using (vulnid) group by VulnID;" | select -skip 1 | convertfrom-json

# 
# $definitions = (mysqlsh.exe root@localhost/scrap --sql -e "select JSON_OBJECT('VulnID', VulnID, 'CheckCommand', CheckCommand, 'Pattern', JSON_ARRAYAGG(Pattern)) from Item join Pattern  using (vulnid) group by VulnID;" | select -skip 1 | convertfrom-json)
# $routers = @('192.168.16.1', '192.168.16.2', '192.168.16.3')

# Serialize definitions to a JSON file
# $definitions | ConvertTo-Json | Out-File 'definitions.json'

function Get-NetworkAudit {
    param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)][String[]]$ComputerName,
        [parameter(Position=1)][String]$Username = $env:USERNAME,
        [parameter(Mandatory=$true, Position=2)]$Definitions
    )

    begin {
        # TODO: download rules from the web
        $rules = $Definitions;
        
        # Extract the distinct commands from rules
        $commands = ($rules | Select-Object -Unique CheckCommand).CheckCommand;

        # Check if SSH executable is on the path
        Get-Command plink -ErrorAction Stop | Write-Verbose
    }

    process {
        $queries = @{};
        foreach ($computer in $ComputerName) {
            foreach ($command in $commands) {
                $key = $command + ' on ' + $computer;
                # plink requires -batch now for this use case. See this article:
                # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-auth-prompt-spoofing.html
                $value = (plink -l $username -ssh -P 22 -batch $computer $command);
                $queries[$key] = $value;
            }
        }
        return $queries;
    }
}

function Test-NetworkAudit() {
    $definitions = (mysqlsh.exe root@localhost/scrap --sql -e "select JSON_OBJECT('VulnID', VulnID, 'CheckCommand', CheckCommand, 'Pattern', JSON_ARRAYAGG(Pattern)) from Item join Pattern  using (vulnid) group by VulnID;" | select -skip 1 | convertfrom-json)
    $routers = @('192.168.16.1', '192.168.16.2', '192.168.16.3')
    Get-NetworkAudit -ComputerName $routers -Username 'cisco' -Definitions $definitions
}