# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Generate Password
$minLength = 9 ## characters
$maxLength = 12 ## characters

$length = Get-Random -Minimum $minLength -Maximum $maxLength
$nonAlphaChars = 2
$password = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)

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

#Change mapping here
$account = [PSCustomObject]@{
    userType = $employeeType;
    displayName = $displayName;
    userPrincipalName = $userPrincipalName;
    mailNickname = $userPrincipalName.split("@")[0];
    mail = $userPrincipalName
    showInAddressList = $true;

    accountEnabled = $true;
    passwordProfile = @{
        password = $password
        forceChangePasswordNextSignIn = $false
    }

    givenName = $firstname
    surname = $lastname

    jobTitle = $title
    department = $department
    officeLocation = $office
    companyName = $company

    mobilePhone = $mobileNumber
    businessPhones = @($telephoneNumber)
    faxNumber = $faxNumber

    employeeId = $employeeId

    UsageLocation       =   "NL"
    PreferredLanguage   =   "NL"

    #Country             =   "Netherlands"
    #State               =   "Utrecht"
    #City                =   "Baarn"
    #StreetAddress       =   "Amalialaan 126C"
    #PostalCode          =   "3743 KJ"
    
    onPremisesExtensionAttributes =  @{
        extensionAttribute1 = "";
        extensionAttribute2 = "";
        extensionAttribute3 = "";
        extensionAttribute4 = "";
        extensionAttribute5 = "";
        extensionAttribute6 = "";
        extensionAttribute7 = "";
        extensionAttribute8 = "";
        extensionAttribute9 = "";
        extensionAttribute10 = "";
        extensionAttribute11 = "";
        extensionAttribute12 = "";
        extensionAttribute13 = "";
        extensionAttribute14 = "";
        extensionAttribute15 = "";
    }
}

# Filter out empty properties
$accountTemp = $account

$account = @{}
foreach($property in $accountTemp.PSObject.Properties){
    if(![string]::IsNullOrEmpty($property.Value)){
        $null = $account.Add($property.Name, $property.Value)
    }
}

$account = [PSCustomObject]$account

try{
    Hid-Write-Status -Message "Generating Microsoft Graph API Access Token.." -Event Information

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

    Hid-Write-Status -Message "Creating AzureAD user [$($account.userPrincipalName)].." -Event Information
    
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

    Hid-Write-Status -Message "AzureAD user [$($account.userPrincipalName)] created successfully" -Event Success
    HID-Write-Summary -Message "AzureAD user [$($account.userPrincipalName)] created successfully" -Event Success
}catch{
    HID-Write-Status -Message "Error creating AzureAD user [$($account.userPrincipalName)]. Error: $_" -Event Error
    HID-Write-Summary -Message "Error creating AzureAD user [$($account.userPrincipalName)]" -Event Failed
}
