# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

function Remove-EmptyValuesFromHashtable {
    param(
        [parameter(Mandatory = $true)][Hashtable]$Hashtable
    )

    $newHashtable = @{}
    foreach ($Key in $Hashtable.Keys) {
        if (-not[String]::IsNullOrEmpty($Hashtable.$Key)) {
            $null = $newHashtable.Add($Key, $Hashtable.$Key)
        }
    }
    
    return $newHashtable
}

# Generate Password
#Not the best implementation method, but it does work. Useful generating a random password with the Cloud Agent since [System.Web] is not available.
function New-RandomPassword($PasswordLength)
{
    # Length of the password to be generated
    #$PasswordLength = 20

    if($PasswordLength -lt 4) {$PasswordLength = 4}
        
    # Used to store an array of characters that can be used for the password
    $CharPool = New-Object System.Collections.ArrayList

    # Add characters a-z to the arraylist
    for ($index = 97; $index -le 122; $index++) { [Void]$CharPool.Add([char]$index) }

    # Add characters A-Z to the arraylist
    for ($index = 65; $index -le 90; $index++) { [Void]$CharPool.Add([Char]$index) }

    # Add digits 0-9 to the arraylist
    $CharPool.AddRange(@("0","1","2","3","4","5","6","7","8","9"))
        
    # Add a range of special characters to the arraylist
    $CharPool.AddRange(@("!","""","#","$","%","&","'","(",")","*","+","-",".","/",":",";","<","=",">","?","@","[","\","]","^","_","{","|","}","~","!"))
        
    $password=""
    $rand=New-Object System.Random
        
    # Generate password by appending a random value from the array list until desired length of password is reached
    1..$PasswordLength | foreach { $password = $password + $CharPool[$rand.Next(0,$CharPool.Count)] }  

    # Replace characters to avoid confusion
    $password = $password.replace("o", "p")
    $password = $password.replace("O", "P")
    $password = $password.replace("i", "k")
    $password = $password.replace("I", "K")
    $password = $password.replace("0", "9")
    $password = $password.replace("l", "m")
    $password = $password.replace("L", "M")
    $password = $password.replace("|", "_")
    $password = $password.replace("``", "_")
    $password = $password.replace("`"", "R")
    $password = $password.replace("<", "F")
    $password = $password.replace(">", "v")  

    #print password
    $password
}


#Change mapping here
$account = @{
    userType = $form.employeeType.Type
    displayName = $form.naming.displayname
    userPrincipalName = $form.naming.userPrincipalName
    mailNickname = $form.naming.userPrincipalName.split("@")[0];
    mail = $form.naming.userPrincipalName
    showInAddressList = $true;

    accountEnabled = $true;
    passwordProfile = @{
        password = New-RandomPassword(16)
        forceChangePasswordNextSignIn = $false
    }

    givenName = $form.givenname
    surname = $form.naming.surname

    jobTitle = $form.title
    department = $form.department
    # officeLocation = "Baarn"
    # companyName = "Tools4ever"

    # mobilePhone = "0612345678"
    # businessPhones = @("0229 123456")
    # faxNumber = ""

    # employeeId = "12345678"

    UsageLocation       =   "NL"
    PreferredLanguage   =   "NL"

    #Country             =   "Netherlands"
    #State               =   "Utrecht"
    #City                =   "Baarn"
    #StreetAddress       =   "Amalialaan 126C"
    #PostalCode          =   "3743 KJ"
    
    # onPremisesExtensionAttributes =  @{
    #     extensionAttribute1 = "";
    #     extensionAttribute2 = "";
    #     extensionAttribute3 = "";
    #     extensionAttribute4 = "";
    #     extensionAttribute5 = "";
    #     extensionAttribute6 = "";
    #     extensionAttribute7 = "";
    #     extensionAttribute8 = "";
    #     extensionAttribute9 = "";
    #     extensionAttribute10 = "";
    #     extensionAttribute11 = "";
    #     extensionAttribute12 = "";
    #     extensionAttribute13 = "";
    #     extensionAttribute14 = "";
    #     extensionAttribute15 = "";
    # }
}

# Filter out empty properties
$account = Remove-EmptyValuesFromHashtable $account
$account = [PSCustomObject]$account

try{
    Write-Verbose "Generating Microsoft Graph API Access Token.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }
    
    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType "application/x-www-form-urlencoded"
    $accessToken = $Response.access_token;

    Write-Verbose "Creating AzureAD user [$($account.userPrincipalName)].."
    
    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        "Content-Type" = "application/json";
        Accept = "application/json";
    }
    
    $baseCreateUri = "https://graph.microsoft.com/"
    $createUri = $baseCreateUri + "v1.0/users"
    $body = $account | ConvertTo-Json -Depth 10
    
    $response = Invoke-RestMethod -Uri $createUri -Method POST -Headers $authorization -Body $body -Verbose:$false

    Write-Information "AzureAD user [$($account.userPrincipalName)] created successfully"
}catch{
    Write-Error "Error creating AzureAD user [$($account.userPrincipalName)]. Error: $_"
}
