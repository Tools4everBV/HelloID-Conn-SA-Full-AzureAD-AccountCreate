# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("Users","HID_administrators") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("Azure Active Directory","User Management") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> AADtenantID
$tmpName = @'
AADtenantID
'@ 
$tmpValue = @'
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #2 >> AADAppId
$tmpName = @'
AADAppId
'@ 
$tmpValue = @'
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});


#make sure write-information logging is visual
$InformationPreference = "continue"
# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}
# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}
# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  
 
function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )
    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid
            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
    }
}
function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task
            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = [Object[]]($Variables | ConvertFrom-Json);
            }
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid
            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
    }
    $returnObject.Value = $taskGuid
}
function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = [Object[]]($DatasourceModel | ConvertFrom-Json);
                automationTaskGUID = $AutomationTaskGuid;
                value              = [Object[]]($DatasourceStaticValue | ConvertFrom-Json);
                script             = $DatasourcePsScript;
                input              = [Object[]]($DatasourceInput | ConvertFrom-Json);
            }
            $body = ConvertTo-Json -InputObject $body
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
      Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }
    $returnObject.Value = $datasourceGuid
}
function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = [Object[]]($FormSchema | ConvertFrom-Json)
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
    }
    $returnObject.Value = $formGuid
}
function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][String][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                accessGroups    = [Object[]]($AccessGroups | ConvertFrom-Json);
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
            }    
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true
            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }
    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "Azure-AD-User-Create-check-names" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"surname","type":0},{"key":"userPrincipalName","type":0},{"key":"mail","type":0},{"key":"displayname","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"employeeType","type":0,"options":1},{"description":"","translateDescription":false,"inputFieldType":1,"key":"givenName","type":0,"options":1},{"description":"","translateDescription":false,"inputFieldType":1,"key":"lastName","type":0,"options":1},{"description":"","translateDescription":false,"inputFieldType":1,"key":"middleName","type":0,"options":0}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
Azure-AD-User-Create-check-names
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "Azure-AD-User-Create-check-names" #>

<# Begin: DataSource "Azure-AD-User-Create-generate-table-employeeType" #>
$tmpStaticValue = @'
[{"Name":"Employee","UPNsuffix":"enyoi.local","Type":"Member","Organization":"Enyoi"},{"Name":"External","UPNsuffix":"enyoi.local","Type":"Guest","Organization":"Enyoi"}]
'@ 
$tmpModel = @'
[{"key":"Name","type":0},{"key":"Organization","type":0},{"key":"Type","type":0},{"key":"UPNsuffix","type":0}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
Azure-AD-User-Create-generate-table-employeeType
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "2" -DatasourceStaticValue $tmpStaticValue -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "Azure-AD-User-Create-generate-table-employeeType" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "AzureAD Account - Create" #>
$tmpSchema = @"
[{"label":"Details","fields":[{"key":"employeeType","templateOptions":{"label":"Account type","required":true,"useObjects":false,"useDataSource":true,"useFilter":false,"options":["1111","2222","33333"],"valueField":"Type","textField":"Name","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[]}},"defaultSelectorProperty":"Name"},"type":"dropdown","summaryVisibility":"Show","textOrLabel":"text","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"givenname","templateOptions":{"label":"Givenname","placeholder":"John","required":true,"minLength":2},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"middlename","templateOptions":{"label":"Middle name","placeholder":"van der"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"lastname","templateOptions":{"label":"Last name","placeholder":"Poel","required":true,"minLength":2},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"title","templateOptions":{"label":"Job title","placeholder":"Application owner"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"department","templateOptions":{"label":"Department","placeholder":"ICT"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]},{"label":"Naming","fields":[{"key":"naming","templateOptions":{"label":"Naming convention","required":true,"grid":{"columns":[{"headerName":"Displayname","field":"displayname"},{"headerName":"Surname","field":"surname"},{"headerName":"User Principal Name","field":"userPrincipalName"},{"headerName":"Mail","field":"mail"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"employeeType","otherFieldValue":{"otherFieldKey":"employeeType"}},{"propertyName":"givenName","otherFieldValue":{"otherFieldKey":"givenname"}},{"propertyName":"lastName","otherFieldValue":{"otherFieldKey":"lastname"}},{"propertyName":"middleName","otherFieldValue":{"otherFieldKey":"middlename"}}]}},"useFilter":false,"defaultSelectorProperty":"userPrincipalName","useDefault":true},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
AzureAD Account - Create
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
foreach($group in $delegatedFormAccessGroupNames) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $delegatedFormAccessGroupGuid = $response.groupGuid
        $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
        
        Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
    } catch {
        Write-Error "HelloID (access)group '$group', message: $_"
    }
}
$delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Compress)
$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
Azure AD Account - Create
'@
Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-user-plus" -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

<# Begin: Delegated Form Task #>
if($delegatedFormRef.created -eq $true) { 
	$tmpScript = @'
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
'@; 

	$tmpVariables = @'
[{"name":"company","value":"{{company.name}}","secret":false,"typeConstraint":"string"},{"name":"defaultGroups","value":"{{form.employeeType.Groups}}","secret":false,"typeConstraint":"string"},{"name":"department","value":"{{form.department}}","secret":false,"typeConstraint":"string"},{"name":"displayname","value":"{{form.naming.displayname}}","secret":false,"typeConstraint":"string"},{"name":"employeeType","value":"{{form.employeeType.Type}}","secret":false,"typeConstraint":"string"},{"name":"firstname","value":"{{form.givenname}}","secret":false,"typeConstraint":"string"},{"name":"lastname","value":"{{form.naming.surname}}","secret":false,"typeConstraint":"string"},{"name":"middlename","value":"{{form.middlename}}","secret":false,"typeConstraint":"string"},{"name":"password","value":"{{form.password}}","secret":false,"typeConstraint":"string"},{"name":"title","value":"{{form.title}}","secret":false,"typeConstraint":"string"},{"name":"userprincipalname","value":"{{form.naming.userPrincipalName}}","secret":false,"typeConstraint":"string"}]
'@ 

	$delegatedFormTaskGuid = [PSCustomObject]@{} 
$delegatedFormTaskName = @'
Azure-AD-user-create
'@
	Invoke-HelloIDAutomationTask -TaskName $delegatedFormTaskName -UseTemplate "False" -AutomationContainer "8" -Variables $tmpVariables -PowershellScript $tmpScript -ObjectGuid $delegatedFormRef.guid -ForceCreateTask $true -returnObject ([Ref]$delegatedFormTaskGuid) 
} else {
	Write-Warning "Delegated form '$delegatedFormName' already exists. Nothing to do with the Delegated Form task..." 
}
<# End: Delegated Form Task #>
