# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
    $iterationMax = 10
    $iterationStart = 0;
    $givenName = $datasource.givenName
    $middleName = $datasource.middleName
    $lastName = $datasource.lastName
    
    $UPNsuffix = $datasource.employeeType.UPNsuffix
    
    Write-Information ("Generating names for " + (("$givenName" + " " + "$middleName" + " " + "$lastName").replace("  "," ")))
        
    function Remove-StringLatinCharacters
    {
        PARAM ([string]$String)
        [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
    }
        
    for($i = $iterationStart; $i -lt $iterationMax; $i++) {
        # Surname - "middleName" + "lastName"
        # B	    Van den Boele
        # BP	Boele - De Vries, van den
        # P	    De Vries
        # PB	Vries - van den Boele, de
        $surName = if(![string]::IsNullOrEmpty($middleName)){$middleName + " " + $lastName}else{$lastName}

        # Displayname - "middleName" + "lastName" + ", " "givenName"
        # B	    Boele, Janine van den
        # BP	Boele - de Vries, Janine van den
        # P	    Vries, Janine de
        # PB	Vries - van den Boele, Janine de
        $displayName = if(![string]::IsNullOrEmpty($middleName)){$middleName + " " + $lastName + ", " + $givenName}else{$lastName + ", " + $givenName}
        $displayName = $displayName.trim() -replace "\s+", " "

        # UserPrincipalName - "givenName" + "." + "middleName" + "." + "lastName"
        # B	    Janine.van.den.boele@enyoi.local
        # BP	Janine.van.den.boele@enyoi.local
        # P	    Janine.van.den.boele@enyoi.local
        # PB	Janine.van.den.boele@enyoi.local

        $UPNprefix = if(![string]::IsNullOrEmpty($middleName)){$givenName + "." + "$middleName" + "." + $lastName}else{$givenName + "." + $lastName}
        $UPNprefix = $UPNprefix.trim() -replace "\s+", " "
        $UPNprefix = $UPNprefix.replace(" ",".")
        $UPNprefix = $UPNprefix.replace("..",".")
        if($i -eq $iterationStart) {
            $UPNprefix = $UPNprefix
        } else {
            $UPNprefix = $UPNprefix + "$i"
        }
        $UPNprefix = $UPNprefix.ToLower()
        $UPNprefix = Remove-StringLatinCharacters $UPNprefix
        $UPNprefix = $UPNprefix.trim() -replace "\s+", ""

        $upn = $UPNprefix + "@" + $UPNsuffix

        # Mail
        $mail = $upn

        Write-Information "Generating Microsoft Graph API Access Token.."

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
        
        Write-Information "Searching for AzureAD user userPrincipalName=$upn"

        #Add the authorization header to the request
        $authorization = @{
            Authorization = "Bearer $accesstoken";
            "Content-Type" = "application/json";
            Accept = "application/json";
        }

        $baseSearchUri = "https://graph.microsoft.com/"
        $searchUri = $baseSearchUri + "v1.0/users/$upn"

        try{
            $response = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
            
            Write-Warning "AzureAD user userPrincipalName=$upn found"
        }catch{
            Write-Information "AzureAD user userPrincipalName=$upn not found"

            $returnObject = @{
                surname=$surName;
                displayname=$displayName;
                userPrincipalName=$upn;
                mail=$mail
            }
            Write-Output $returnObject
            
            break;
        }
    }
} catch {
    Write-Error "Error generating names. Error: $_"
}
