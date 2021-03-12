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
        
        # This could have been done in parallel, but we cannot depend on users having PS7.
        foreach ($computer in $ComputerName) {
            # Fetch all of the command output first. Some commands are duplicated.
            foreach ($command in $commands) {
                $key = $command + ' on ' + $computer;
                # plink requires -batch now for this use case. See this article:
                # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-auth-prompt-spoofing.html
                $value = (plink -l $username -ssh -P 22 -batch $computer $command);
                # PowerShell constructed an array of strings, but it will be easier to parse if they are all
                # joined into a single large string.
                $queries[$key] = [string]::Join("`n", $value);
            }
            # Now that we have the command output we can match rules.
            foreach ($rule in $rules) {
                foreach ($pattern in $rule.Pattern) {
                    $key = $rule.CheckCommand + ' on ' + $computer;
                    $commandOutput = $queries[$key];
                    $id = $rule.VulnID;
                    # rules begin with '+' to indicate that it must match or '-' to indicate that it must not match.
                    $matchablePattern = $pattern.Substring(1);
                    if ($pattern[0] -eq '+') {
                        $compliant = $commandOutput -match $matchablePattern;
                    } else {
                        $compliant = $commandOutput -notmatch $matchablePattern;
                    }
                    [pscustomobject]@{ComputerName = $computer; VulnID = $id; Compliant = $compliant};
                }
            }
        }
    }
}

function Test-NetworkAudit() {
    $definitions = (mysqlsh.exe root@localhost/scrap --sql -e "select JSON_OBJECT('VulnID', VulnID, 'CheckCommand', CheckCommand, 'Pattern', JSON_ARRAYAGG(Pattern)) from Item join Pattern using (vulnid) group by VulnID;" | select -skip 1 | convertfrom-json)
    $routers = @('192.168.16.1', '192.168.16.2', '192.168.16.3')
    Get-NetworkAudit -ComputerName $routers -Username 'cisco' -Definitions $definitions
}