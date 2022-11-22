Write-Host "trustbutverify.ps1 <rules file> <1-4>"
Write-Host "Rules file must be Snort/Suricata formatted"
Write-Host "1 through 4 displays up to matching severity level (1=low, 2=med, 3=high, 4=critical)"


if ($args.Count -eq 0)
{    
    Write-Host "No input file" -BackgroundColor Red
    return
}

if ($args.Count -eq 1){ $filter = 4 }
else { $filter= $args[1] }
    
$rules = Get-Content $args[0]

$linenum=1
$low=0
$med=0
$high=0
$crit=0

'sep=~' > trust-but-verify.csv
"line~match~level~full rule" >> trust-but-verify.csv

Write-Host "Filter set to $filter" -BackgroundColor DarkGray -ForegroundColor White

foreach ($line in $rules)
{

    #Skip commented out rules and blank lines
    if ($line.contains('#alert') -or $line.length -eq 0)
    {
        $linenum++
        continue
    }


    # Any -> any rules
    if ($line.contains('any any -> any any'))
    { 
        if ($filter -ge '2' -and $line.contains('content'))
        {
            $match = "any -> any rule. Consider scoping to appropriate endpoints"
            Write-Host "Line [$linenum] : MEDIUM : $match" -BackgroundColor DarkYellow
            Write-Host $line
            "$linenum~$match~MEDIUM~$line" >> trust-but-verify.csv
            $med++
        }

        if ($filter -ge '3' -and $line -notlike "*content*")
        {
            $match = "any -> any rule without content: fast pattern matching"
            Write-Host "Line [$linenum] : HIGH : $match" -BackgroundColor Red
            Write-Host $line
            "$linenum~$match~HIGH~$line" >> trust-but-verify.csv
            $high++
        }
        if ($filter -ge '4' -and $line.contains('pcre'))
        {
            $match = "any -> any rule with a regex (pcre) rule"
            Write-Host "Line [$linenum] : CRITICAL : $match" -BackgroundColor DarkRed -ForegroundColor Yellow 
            Write-Host $line
            "$linenum~$match~CRITICAL~$line" >> trust-but-verify.csv
            $crit++
        }

    }

    # Regular Expressions and Content
    if ($line.contains('pcre'))
    { 
        if ($filter -ge '4' -and $line -notlike "*content*")
        {
            $match = "Regex (pcre) rule without 'content:' fast pattern matching"
            Write-Host "Line [$linenum] : CRITICAL : $match" -BackgroundColor DarkRed -ForegroundColor Yellow
            Write-Host $line
            "$linenum~$match~CRITICAL~$line" >> trust-but-verify.csv
            $crit++
        }
        
        if($filter -ge '4' -and $line.IndexOf('pcre') -lt $line.IndexOf('content')) 
        {
            $match = "Regex (pcre) before 'content:' in rule, swap their locations (order matters)"
            Write-Host "Line [$linenum] : CRITICAL : $match" -BackgroundColor DarkRed -ForegroundColor Yellow
            Write-Host $line
            "$linenum~$match~CRITICAL~$line" >> trust-but-verify.csv
            $crit++
        }

    }

    #Flow direction
    if ($line.contains('tcp') -or $line.contains('http'))
    { 
        if ($filter -ge '2' -and $line -notlike "*flow*" -and $line -notlike "*flag*")
        { 
            $match = "TCP based rule without session awareness. Consider adding appropriate flow: direction"
            Write-Host "Line [$linenum] : MEDIUM : $match" -BackgroundColor DarkYellow
            Write-Host $line
            "$linenum~$match~MEDIUM~$line" >> trust-but-verify.csv
            $med++
                      
        }
    }

    #Content missing fast_pattern
    if ($filter -ge '1' -and (Select-String "content" -InputObject $line -AllMatches).Matches.Count -gt 1 -and $line -notlike "*fast_pattern*")
    { 
        $match = "no fast_pattern declared with multiple 'content:' matches. Consider picking the least likely to match first"
        Write-Host "Line [$linenum] : LOW : $match " -BackgroundColor Cyan -ForegroundColor DarkGray
        Write-Host $line
        "$linenum~$match~LOW~$line" >> trust-but-verify.csv
        $low++
    }

    $linenum++

}

Write-Host "Final Stats:" -BackgroundColor Gray -ForegroundColor White
Write-Host "Low: $low" -BackgroundColor Cyan -ForegroundColor DarkGray
Write-Host "Medium: $med" -BackgroundColor DarkYellow
Write-Host "High: $high" -BackgroundColor Red
Write-Host "Critical: $crit" -BackgroundColor DarkRed -ForegroundColor Yellow
