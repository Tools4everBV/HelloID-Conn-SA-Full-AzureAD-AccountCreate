#HelloID variables
$PortalBaseUrl = "https://ramons.helloid.com"
$apiKey = "EMUFTEVQMYUERBJVWUSAXUWKSUDBRTWB"
$apiSecret = "nBszZMACJkmzKLHaGrxaJJtLrjpzbtZT"
$delegatedFormAccessGroupNames = @("Users", "HID_administrators")
 
# Create authorization headers with HelloID API key
$pair = "$apiKey" + ":" + "$apiSecret"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [System.Convert]::ToBase64String($bytes)
$key = "Basic $base64"
$headers = @{"authorization" = $Key}
# Define specific endpoint URI
if($PortalBaseUrl.EndsWith("/") -eq $false){
    $PortalBaseUrl = $PortalBaseUrl + "/"
}
 

function Write-ColorOutput($ForegroundColor) {
  $fc = $host.UI.RawUI.ForegroundColor
  $host.UI.RawUI.ForegroundColor = $ForegroundColor
  
  if ($args) {
      Write-Output $args
  }
  else {
      $input | Write-Output
  }

  $host.UI.RawUI.ForegroundColor = $fc
}

$variableName = "AADtenantID"
$variableGuid = ""
  
try {
    $uri = ($PortalBaseUrl +"api/v1/automation/variables/named/$variableName")
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
  
    if([string]::IsNullOrEmpty($response.automationVariableGuid)) {
        #Create Variable
        $body = @{
            name = "$variableName";
            value = '<Provide your Tenant ID here>';
            secret = "false";
            ItemType = 0;
        }
  
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/automation/variable")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
        $variableGuid = $response.automationVariableGuid

        Write-ColorOutput Green "Variable '$variableName' created: $variableGuid"
    } else {
        $variableGuid = $response.automationVariableGuid
        Write-ColorOutput Yellow "Variable '$variableName' already exists: $variableGuid"
    }
} catch {
    Write-ColorOutput Red "Variable '$variableName'"
    $_
}

$variableName = "AADAppId"
$variableGuid = ""
  
try {
    $uri = ($PortalBaseUrl +"api/v1/automation/variables/named/$variableName")
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
  
    if([string]::IsNullOrEmpty($response.automationVariableGuid)) {
        #Create Variable
        $body = @{
            name = "$variableName";
            value = '<Provide your Client ID here>';
            secret = "false";
            ItemType = 0;
        }
  
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/automation/variable")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
        $variableGuid = $response.automationVariableGuid

        Write-ColorOutput Green "Variable '$variableName' created: $variableGuid"
    } else {
        $variableGuid = $response.automationVariableGuid
        Write-ColorOutput Yellow "Variable '$variableName' already exists: $variableGuid"
    }
} catch {
    Write-ColorOutput Red "Variable '$variableName'"
    $_
}

$variableName = "AADAppSecret"
$variableGuid = ""
  
try {
    $uri = ($PortalBaseUrl +"api/v1/automation/variables/named/$variableName")
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
  
    if([string]::IsNullOrEmpty($response.automationVariableGuid)) {
        #Create Variable
        $body = @{
            name = "$variableName";
            value = '<Provide your Client Secret here>';
            secret = "true";
            ItemType = 0;
        }
  
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/automation/variable")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
        $variableGuid = $response.automationVariableGuid

        Write-ColorOutput Green "Variable '$variableName' created: $variableGuid"
    } else {
        $variableGuid = $response.automationVariableGuid
        Write-ColorOutput Yellow "Variable '$variableName' already exists: $variableGuid"
    }
} catch {
    Write-ColorOutput Red "Variable '$variableName'"
    $_
}

$dataSourceName = "AzureAD-employeeType-generate-table-create"
$dataSourceSelectemployeeTypeGuid = ""
 
try {
    $uri = ($PortalBaseUrl +"api/v1/datasource/named/$dataSourceName")
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
 
    if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
        #Create DataSource
        $body = @{
            name = "$dataSourceName";
            type = "2";
            model = @(@{key = "Groups"; type = 0}, @{key = "Name"; type = 0}, @{key = "Organization"; type = 0}, @{key = "Type"; type = 0}, @{key = "UPNsuffix"; type = 0});
            value = @(@{Name = "Employee"; Organization = "Enyoi"; Type = "Member"; UPNsuffix = "enyoi.nl"; Groups = '[{"Name": "TestGroup1"},{"Name": "TestGroup2"}]'},
            @{Name = "External"; Organization = "Enyoi"; Type = "Guest"; UPNsuffix = "enyoi.nl"; Groups = '[{"Name": "TestGroup1"}]'});
        }
        $body = $body | ConvertTo-Json
 
        $uri = ($PortalBaseUrl +"api/v1/datasource")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
         
        $dataSourceSelectemployeeTypeGuid = $response.dataSourceGUID
        Write-ColorOutput Green "Task data source '$dataSourceName' created: $dataSourceSelectemployeeTypeGuid"
    } else {
        #Get DatasourceGUID
        $dataSourceSelectemployeeTypeGuid = $response.dataSourceGUID
        Write-ColorOutput Yellow "Task data source '$dataSourceName' already exists: $dataSourceSelectemployeeTypeGuid"
    }
} catch {
    Write-ColorOutput Red "Task data source '$dataSourceName'"
    $_
} 
 

$taskName = "AzureAD-user-create-check-names"
$taskCheckNamesGuid = ""
  
try {
    $uri = ($PortalBaseUrl +"api/v1/automationtasks?search=$taskName&container=1")
    $response = (Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false) | Where-Object -filter {$_.name -eq $taskName}
  
    if([string]::IsNullOrEmpty($response.automationTaskGuid)) {
        #Create Task
  
        $body = @{
            name = "$taskName";
            useTemplate = "false";
            powerShellScript = @'
            # Set TLS to accept TLS, TLS 1.1 and TLS 1.2
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
            
            try {
                $iterationMax = 10
                $iterationStart = 0;
                $givenName = $formInput.givenName
                $middleName = $formInput.middleName
                $lastName = $formInput.lastName
                
                $UPNsuffix = $formInput.employeeType.UPNsuffix
                
                HID-Write-Status -Message ("Generating names for " + (("$givenName" + " " + "$middleName" + " " + "$lastName").replace("  "," "))) -Event Information       
                    
                function Remove-StringLatinCharacters
                {
                    PARAM ([string]$String)
                    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
                }
                    
                for($i = $iterationStart; $i -lt $iterationMax; $i++) {
                    # Surname - "middleName" + "lastName"
                    # B	    Van den Boele
                    # BP	Boele – De Vries, van den
                    # P	    De Vries
                    # PB	Vries – van den Boele, de
                    $surName = if(![string]::IsNullOrEmpty($middleName)){$middleName + " " + $lastName}else{$lastName}
            
                    # Displayname - "middleName" + "lastName" + ", " "givenName"
                    # B	    Boele, Janine van den
                    # BP	Boele – de Vries, Janine van den
                    # P	    Vries, Janine de
                    # PB	Vries – van den Boele, Janine de
                    $displayName = if(![string]::IsNullOrEmpty($middleName)){$middleName + " " + $lastName + ", " + $givenName}else{$lastName + ", " + $givenName}
                    $displayName = $displayName.trim() -replace "\s+", " "
            
                    # UserPrincipalName - "givenName" + "." + "middleName" + "." + "lastName"
                    # B	    Janine.van.den.boele@vecozo.nl
                    # BP	Janine.van.den.boele@vecozo.nl
                    # P	    Janine.van.den.boele@vecozo.nl
                    # PB	Janine.van.den.boele@vecozo.nl
            
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
            
                    Hid-Write-Status -Message "Generating Microsoft Graph API Access Token user.." -Event Information
            
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
                    
                    Hid-Write-Status -Message "Searching for AzureAD user userPrincipalName=$upn" -Event Information
            
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
                        Hid-Write-Status -Message "AzureAD user userPrincipalName=$upn found" -Event Information
                    }catch{
                        $returnObject = @{surName=$surName;displayname=$displayName;userPrincipalName=$upn;mail=$mail}
                        Hid-Write-Status -Message "AzureAD user userPrincipalName=$upn not found" -Event Information
                        break;
                    }
                }
            } catch {
                HID-Write-Status -Message "Error generating names. Error: $($_.Exception.Message)" -Event Error
                HID-Write-Summary -Message "Error generating names" -Event Failed
            }
                
            if([string]::IsNullOrEmpty($returnObject)) {
                Hid-Add-TaskResult -ResultValue []
            } else {
                Hid-Add-TaskResult -ResultValue $returnObject
            }
'@;
            automationContainer = "1";
            variables = @()
        }
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/automationtasks/powershell")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
        $taskCheckNamesGuid = $response.automationTaskGuid

        Write-ColorOutput Green "Powershell task '$taskName' created: $taskCheckNamesGuid"    
    } else {
        #Get TaskGUID
        $taskCheckNamesGuid = $response.automationTaskGuid
        Write-ColorOutput Yellow "Powershell task '$taskName' already exists: $taskCheckNamesGuid"
    }
} catch {
    Write-ColorOutput Red "Powershell task '$taskName'"
    $_
}  

$dataSourceName = "AzureAD-user-create-check-names"
$dataSourceCheckNamesGuid = ""
  
try {
    $uri = ($PortalBaseUrl +"api/v1/datasource/named/$dataSourceName")
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
  
    if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
        #Create DataSource
        $body = @{
            name = "$dataSourceName";
            type = "3";
            model = @(@{key = "displayname"; type = 0}, @{key = "surName"; type = 0}, @{key = "userPrincipalName"; type = 0});
            automationTaskGUID = "$taskCheckNamesGuid";
            input = @(
                @{description = ""; translateDescription = "False"; inputFieldType = "1"; key = "employeeType"; type = "0"; options = "1"},
                @{description = ""; translateDescription = "False"; inputFieldType = "1"; key = "givenName"; type = "0"; options = "1"},
                @{description = ""; translateDescription = "False"; inputFieldType = "1"; key = "lastName"; type = "0"; options = "1"},
                @{description = ""; translateDescription = "False"; inputFieldType = "1"; key = "middleName"; type = "0"; options = "0"}
            )
        }
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/datasource")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
          
        $dataSourceCheckNamesGuid = $response.dataSourceGUID
        Write-ColorOutput Green "Task data source '$dataSourceName' created: $dataSourceCheckNamesGuid"
    } else {
        #Get DatasourceGUID
        $dataSourceCheckNamesGuid = $response.dataSourceGUID
        Write-ColorOutput Yellow "Task data source '$dataSourceName' already exists: $dataSourceCheckNamesGuid"
    }
} catch {
  Write-ColorOutput Red "Task data source '$dataSourceName'"
  $_
}

$formName = "AzureAD Account - Create"
$formGuid = ""
  
try
{
    try {
        $uri = ($PortalBaseUrl +"api/v1/forms/$formName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
    } catch {
        $response = $null
    }
  
    if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true))
    {
        #Create Dynamic form
        $form = @"
        [
            {
              "label": "Details",
              "fields": [
                {
                  "key": "employeeType",
                  "templateOptions": {
                    "label": "Account type",
                    "required": true,
                    "useObjects": false,
                    "useDataSource": true,
                    "useFilter": false,
                    "options": [
                      "1111",
                      "2222",
                      "33333"
                    ],
                    "valueField": "Type",
                    "textField": "Name",
                    "dataSourceConfig": {
                      "dataSourceGuid": "$dataSourceSelectemployeeTypeGuid",
                      "input": {
                        "propertyInputs": []
                      }
                    },
                    "defaultSelectorProperty": "Name"
                  },
                  "type": "dropdown",
                  "summaryVisibility": "Show",
                  "textOrLabel": "text",
                  "requiresTemplateOptions": true
                },
                {
                  "key": "givenname",
                  "templateOptions": {
                    "label": "Givenname",
                    "placeholder": "John",
                    "required": true,
                    "minLength": 2
                  },
                  "type": "input",
                  "summaryVisibility": "Show",
                  "requiresTemplateOptions": true
                },
                {
                  "key": "middlename",
                  "templateOptions": {
                    "label": "Middle name",
                    "placeholder": "van der"
                  },
                  "type": "input",
                  "summaryVisibility": "Show",
                  "requiresTemplateOptions": true
                },
                {
                  "key": "lastname",
                  "templateOptions": {
                    "label": "Last name",
                    "placeholder": "Poel",
                    "required": true,
                    "minLength": 2
                  },
                  "type": "input",
                  "summaryVisibility": "Show",
                  "requiresTemplateOptions": true
                },
                {
                  "key": "title",
                  "templateOptions": {
                    "label": "Job title",
                    "placeholder": "Application owner"
                  },
                  "type": "input",
                  "summaryVisibility": "Show",
                  "requiresTemplateOptions": true
                },
                {
                  "key": "department",
                  "templateOptions": {
                    "label": "Department",
                    "placeholder": "ICT"
                  },
                  "type": "input",
                  "summaryVisibility": "Show",
                  "requiresTemplateOptions": true
                }
              ]
            },
            {
              "label": "Naming",
              "fields": [
                {
                  "key": "naming",
                  "templateOptions": {
                    "label": "Naming convention",
                    "required": true,
                    "grid": {
                      "columns": [
                        {
                          "headerName": "Displayname",
                          "field": "displayname"
                        },
                        {
                          "headerName": "Sur Name",
                          "field": "surName"
                        },
                        {
                          "headerName": "User Principal Name",
                          "field": "userPrincipalName"
                        }
                      ],
                      "height": 300,
                      "rowSelection": "single"
                    },
                    "dataSourceConfig": {
                      "dataSourceGuid": "$dataSourceCheckNamesGuid",
                      "input": {
                        "propertyInputs": [
                          {
                            "propertyName": "employeeType",
                            "otherFieldValue": {
                              "otherFieldKey": "employeeType"
                            }
                          },
                          {
                            "propertyName": "givenName",
                            "otherFieldValue": {
                              "otherFieldKey": "givenname"
                            }
                          },
                          {
                            "propertyName": "lastName",
                            "otherFieldValue": {
                              "otherFieldKey": "lastname"
                            }
                          },
                          {
                            "propertyName": "middleName",
                            "otherFieldValue": {
                              "otherFieldKey": "middlename"
                            }
                          }
                        ]
                      }
                    },
                    "useFilter": false,
                    "defaultSelectorProperty": "userPrincipalName",
                    "useDefault": true
                  },
                  "type": "grid",
                  "summaryVisibility": "Show",
                  "requiresTemplateOptions": true
                }
              ]
            }
          ]
"@
  
        $body = @{
            Name = "$formName";
            FormSchema = $form
        }
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/forms")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
  
        $formGuid = $response.dynamicFormGUID
        Write-ColorOutput Green "Dynamic form '$formName' created: $formGuid"
    } else {
        $formGuid = $response.dynamicFormGUID
        Write-ColorOutput Yellow "Dynamic form '$formName' already exists: $formGuid"
    }
} catch {
    Write-ColorOutput Red "Dynamic form '$formName'"
    $_
}

$delegatedFormAccessGroupGuids = @()

foreach($group in $delegatedFormAccessGroupNames) {
    try {
        $uri = ($PortalBaseUrl +"api/v1/groups/$group")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
        $delegatedFormAccessGroupGuid = $response.groupGuid
        $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
        
        Write-ColorOutput Green "HelloID (access)group '$group' successfully found: $delegatedFormAccessGroupGuid"
    } catch {
        Write-ColorOutput Red "HelloID (access)group '$group'"
        $_
    }
}

$delegatedFormName = "AzureAD Account - Create"
$delegatedFormGuid = ""
$delegatedFormCreated = $false

try {
    try {
        $uri = ($PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
    } catch {
        $response = $null
    }
  
    if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
        #Create DelegatedForm
        $body = @{
            name = "$delegatedFormName";
            dynamicFormGUID = "$formGuid";
            isEnabled = "True";
            accessGroups = $delegatedFormAccessGroupGuids;
            useFaIcon = "True";
            faIcon = "fa fa-user-plus";
        }  
  
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/delegatedforms")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
  
        $delegatedFormGuid = $response.delegatedFormGUID
        Write-ColorOutput Green "Delegated form '$delegatedFormName' created: $delegatedFormGuid"
        $delegatedFormCreated = $true
    } else {
        #Get delegatedFormGUID
        $delegatedFormGuid = $response.delegatedFormGUID
        Write-ColorOutput Yellow "Delegated form '$delegatedFormName' already exists: $delegatedFormGuid"
    }
} catch {
    Write-ColorOutput Red "Delegated form '$delegatedFormName'"
    $_
}

$taskActionName = "AzureAD-user-create"
$taskActionGuid = ""
  
try {
    if($delegatedFormCreated -eq $true) {
        #Create Task
  
        $body = @{
            name = "$taskActionName";
            useTemplate = "false";
            powerShellScript = @'
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
            
            
            # Set TLS to accept TLS, TLS 1.1 and TLS 1.2
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
            
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
                Hid-Write-Status -Message "Generating Microsoft Graph API Access Token user.." -Event Information
            
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
                if(-Not($_.Exception.Response -eq $null)){
                    $result = $_.Exception.Response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($result)
                    $reader.BaseStream.Position = 0
                    $reader.DiscardBufferedData()
                    $errResponse = $reader.ReadToEnd();
            
                    HID-Write-Status -Message "Error creating AzureAD user [$($account.userPrincipalName)]. Error: $errResponse" -Event Error
                    HID-Write-Summary -Message "Error creating AzureAD user [$($account.userPrincipalName)]" -Event Failed
                }else{
                    HID-Write-Status -Message "Error creating AzureAD user [$($account.userPrincipalName)]. Error: $($_.Exception.Message)" -Event Error
                    HID-Write-Summary -Message "Error creating AzureAD user [$($account.userPrincipalName)]" -Event Failed
                }
            }
'@;
            automationContainer = "8";
            objectGuid = "$delegatedFormGuid";
            variables = @(
                @{name = "company"; value = "{{company.name}}"; typeConstraint = "string"; secret = "False"},
                @{name = "defaultGroups"; value = "{{form.employeeType.Groups}}"; typeConstraint = "string"; secret = "False"},
                @{name = "department"; value = "{{form.department}}"; typeConstraint = "string"; secret = "False"},
                @{name = "displayname"; value = "{{form.naming.displayname}}"; typeConstraint = "string"; secret = "False"},
                @{name = "employeeType"; value = "{{form.employeeType.Type}}"; typeConstraint = "string"; secret = "False"},
                @{name = "firstname"; value = "{{form.givenname}}"; typeConstraint = "string"; secret = "False"},
                @{name = "lastname"; value = "{{form.naming.surName}}"; typeConstraint = "string"; secret = "False"},
                @{name = "middlename"; value = "{{form.middlename}}"; typeConstraint = "string"; secret = "False"},
                @{name = "password"; value = "{{form.password}}"; typeConstraint = "string"; secret = "False"},
                @{name = "title"; value = "{{form.title}}"; typeConstraint = "string"; secret = "False"},
                @{name = "userprincipalname";value = "{{form.naming.userPrincipalName}}"; typeConstraint = "string"; secret = "False"}
            );
        }
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/automationtasks/powershell")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
        $taskActionGuid = $response.automationTaskGuid

        Write-ColorOutput Green "Delegated form task '$taskActionName' created: $taskActionGuid"  
    } else {
        Write-ColorOutput Yellow "Delegated form '$delegatedFormName' already exists. Nothing to do with the Delegated Form task..."
    }
} catch {
    Write-ColorOutput Red "Delegated form task '$taskActionName'"
    $_
}