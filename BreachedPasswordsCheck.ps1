########
# BreachedPasswordsCheck
#Copyright:     Free to use, but please leave this header intact
#Author:        Brandon Hansen
#Email:         brandon@v6networks.com.au
#Company:       V6 Networks (https://v6networks.com.au)
#Purpose:       
########

##### MANUAL CONFIGURATION
$pwnedPasswordsList                 = ""                # Location of your downloaded NTLM PwnedPasswords List (https://haveibeenpwned.com/passwords)
$domain                             = ""                # Domain
$domainController                   = ""                # Domain Controller Hostname
$credentials                        = Get-Credential    # Specify Credentials
$days                               = 1                 # Amount of days to check against PasswordLastSet in Active Directory
$outputData                         = $false            # If you would like to export the data for further review set to $true
$outputLocation                     = ""                # Set the output location of your data export
$emailUsers                         = $true             # Set to $false if you do not wish to email your end users
$smtpServer                         = ""                # SMTP Server
$smtpPort                           = ""                # SMTP Port
$smtpFrom                           = ""                # SMTP From Address

##### PROCESS

# Import PSSQlite Module
if (!(Get-Module -ListAvailable -Name PSSQLite)) {
    Install-Module -Name PSSQLite -Force
    Import-Module -Name PSSqlite
}
else {
    Import-Module -Name PSSQLite
}

# Import DSInternals
if (!(Get-Module -ListAvailable -Name DSInternals)) {
    Install-Module -Name DSInternals -Force
    Import-Module -Name DSInternals
}
else {
    Import-Module -Name DSInternals
}

# Import Get-ADUser cmdlet from DomainController
$Session = New-PSSession -ComputerName $domainController -Credential $credentials -ErrorAction Stop
Invoke-Command -Session $Session -ScriptBlock {Import-Module ActiveDirectory -Cmdlet Get-ADUser, Set-ADUser}
Import-PSSession -Session $Session -Module ActiveDirectory -AllowClobber | Out-Null

# Filter out users who have recently changed their password within the last $days
$users = Get-ADUser -Filter * -Properties PasswordLastSet, EmailAddress | Where-Object {$_.PasswordLastSet -gt (Get-Date).AddDays(-$days)}

# Create User Hash Object to store user and NTLM hash
$userArray = @()

# Go through each user found and grab their latest NTLM hash before adding to the $userArray 
foreach ($user in $users) {
    $adReplAccount = Get-ADReplAccount -SamAccountName $user.SamAccountName -Domain $domain -Server $domainController -Credential $credentials -Protocol TCP | Select-Object -Property SamAccountName, @{Name = 'Hash'; Expression = {[string]::Concat(($_.NTHash | ConvertTo-Hex))}}
    $userObject = [PSCustomObject]@{
        User  = $adReplAccount.SamAccountName
        Hash  = $adReplAccount.Hash.toUpper()
        Email = $user.EmailAddress
    }
    $userArray += $userObject 
}

# Create Matched Results Object
$matchedResults = @()

# Cycle through each user from the previous userArray object and see if their NTLM hash is found in the SQLite DB
foreach ($user in $userArray) {
    if ($freq = Invoke-SqliteQuery -DataSource $pwnedPasswordsList -Query "SELECT frequency FROM [pwned-passwords] WHERE hash='$($user.hash)'") {
        $match = [PSCustomObject]@{
            User      = $user.User
            Email     = $user.Email
            Frequency = $freq.frequency
            Hash      = $user.Hash
        }
        $matchedResults += $match
    }
}

# Iterate through matched results
foreach ($user in $matchedResults) {
    # If outputData is set to true in configuration then export as CSV to the set output location
    if ($outputData) {
        $matchedResults | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $outputLocation -Append
    }
    # If email users variable is set to true then we will process and email the user a notification about their password.
    if ($emailUsers) {
        # HTML Template
        $htmlTemplate = @"
        <html>
        <head>
            <style>
                body { background-color: #313b42; font-family: 'Helvetica', 'Tahoma', 'Arial', sans-serif; position: relative; }
                div.container { width: 50%; margin: 0 25%; text-align: center; }
                h1 {color:white; text-align: center; margin: 20px 0 40px 0; }
                h2 {color:white; text-align: left; }
                p {color: white; text-align: left; }
                img { width: 25%; height: auto; margin: 20px 0; }
                footer {color: white; margin: 40px 0; }
                a { text-decoration: underline; color: #fff; }
            </style>
        </head>
        <body>
        
            <div class="container">
              
                <a href="https://v6networks.com.au" title="Official Website of V6 Networks">
                    <img src="https://v6networks.com.au/img/v6networks-logo.svg">
                </a>
                
                <h1>Security Warning - Commonly Used Password</h1>
                
                <h2>What? Has my account been compromised?</h2>
                
                <p>Probably not, but this increases the risk of your account being compormised, because your current password appears at least once on a list of known, commonly-used passwords. $($user.Frequency) Times to be exact.</p>
                
                <h2>What should I do?</h2> 
                <p>To keep your account secure we highly recommend that you go and change your password. We also recommened you familiarise yourself with modern password practices to reduce the risk of this happening again.</p>
                
                <h2>Wait, so you know my password?</h2>
                <p><strong>No!</strong> We utilise publicly available services that allow us to match a partial hashed section of your password against commonly used password lists.</p>
                
                <footer>Copyright &copy; 2019 <a href="https://v6networks.com.au" title="Official Website of V6 Networks">V6 Networks</a> - ABN 23 710 959 527</footer>
               
           </div>
           
        </body>
    </html>
"@
        # Send Email Notification to user.
        Send-MailMessage -BodyAsHtml -Body $htmlTemplate -From $smtpFrom -SmtpServer $smtpServer -To $user.Email -Subject "Password Notification" -Port $smtpPort

    }
}

