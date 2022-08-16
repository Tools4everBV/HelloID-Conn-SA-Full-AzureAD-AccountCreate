# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("Users") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("Azure Active Directory","User Management") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> AADAppId
$tmpName = @'
AADAppId
'@ 
$tmpValue = ""
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #2 >> AADAppSecret
$tmpName = @'
AADAppSecret
'@ 
$tmpValue = ""
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #3 >> companyName
$tmpName = @'
companyName
'@ 
$tmpValue = @'
{{company.name}}
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #4 >> AADtenantID
$tmpName = @'
AADtenantID
'@ 
$tmpValue = "" 
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

# Make sure to reveive an empty array using PowerShell Core
function ConvertFrom-Json-WithEmptyArray([string]$jsonString) {
    # Running in PowerShell Core?
    if($IsCoreCLR -eq $true){
        $r = [Object[]]($jsonString | ConvertFrom-Json -NoEnumerate)
        return ,$r  # Force return value to be an array using a comma
    } else {
        $r = [Object[]]($jsonString | ConvertFrom-Json)
        return ,$r  # Force return value to be an array using a comma
    }
}

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
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
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
                variables           = (ConvertFrom-Json-WithEmptyArray($Variables));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
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
                model              = (ConvertFrom-Json-WithEmptyArray($DatasourceModel));
                automationTaskGUID = $AutomationTaskGuid;
                value              = (ConvertFrom-Json-WithEmptyArray($DatasourceStaticValue));
                script             = $DatasourcePsScript;
                input              = (ConvertFrom-Json-WithEmptyArray($DatasourceInput));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
      
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
                FormSchema = (ConvertFrom-Json-WithEmptyArray($FormSchema));
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
        [parameter()][Array][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter()][String][AllowEmptyString()]$task,
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
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
                task            = ConvertFrom-Json -inputObject $task;
            }
            if(-not[String]::IsNullOrEmpty($AccessGroups)) { 
                $body += @{
                    accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                }
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
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
}


<# Begin: HelloID Global Variables #>
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
[{"key":"userPrincipalName","type":0},{"key":"surname","type":0},{"key":"mail","type":0},{"key":"displayname","type":0}]
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
[{"Name":"Employee","UPNsuffix":"devbreekie18.onmicrosoft.com","Type":"Member","Organization":"T4EJB"},{"Name":"External","UPNsuffix":"devbreekie18.onmicrosoft.com","Type":"Guest","Organization":"T4EJB"}]
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
if(-not[String]::IsNullOrEmpty($delegatedFormAccessGroupNames)){
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
    if($null -ne $delegatedFormAccessGroupGuids){
        $delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Depth 100 -Compress)
    }
}

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
        $body = ConvertTo-Json -InputObject $body -Depth 100

        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid

        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Depth 100 -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
Azure AD Account - Create
'@
$tmpTask = @'
{"name":"Azure AD Account - Create","script":"# Set TLS to accept TLS, TLS 1.1 and TLS 1.2\r\n[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12\r\n\r\n$VerbosePreference = \"SilentlyContinue\"\r\n$InformationPreference = \"Continue\"\r\n$WarningPreference = \"Continue\"\r\n\r\nfunction Remove-EmptyValuesFromHashtable {\r\n    param(\r\n        [parameter(Mandatory = $true)][Hashtable]$Hashtable\r\n    )\r\n\r\n    $newHashtable = @{}\r\n    foreach ($Key in $Hashtable.Keys) {\r\n        if (-not[String]::IsNullOrEmpty($Hashtable.$Key)) {\r\n            $null = $newHashtable.Add($Key, $Hashtable.$Key)\r\n        }\r\n    }\r\n    \r\n    return $newHashtable\r\n}\r\n\r\n# Generate Password\r\n#Not the best implementation method, but it does work. Useful generating a random password with the Cloud Agent since [System.Web] is not available.\r\nfunction New-RandomPassword($PasswordLength)\r\n{\r\n    # Length of the password to be generated\r\n    #$PasswordLength = 20\r\n\r\n    if($PasswordLength -lt 4) {$PasswordLength = 4}\r\n        \r\n    # Used to store an array of characters that can be used for the password\r\n    $CharPool = New-Object System.Collections.ArrayList\r\n\r\n    # Add characters a-z to the arraylist\r\n    for ($index = 97; $index -le 122; $index++) { [Void]$CharPool.Add([char]$index) }\r\n\r\n    # Add characters A-Z to the arraylist\r\n    for ($index = 65; $index -le 90; $index++) { [Void]$CharPool.Add([Char]$index) }\r\n\r\n    # Add digits 0-9 to the arraylist\r\n    $CharPool.AddRange(@(\"0\",\"1\",\"2\",\"3\",\"4\",\"5\",\"6\",\"7\",\"8\",\"9\"))\r\n        \r\n    # Add a range of special characters to the arraylist\r\n    $CharPool.AddRange(@(\"!\",\"\"\"\",\"#\",\"$\",\"%\",\"\u0026\",\"\u0027\",\"(\",\")\",\"*\",\"+\",\"-\",\".\",\"/\",\":\",\";\",\"\u003c\",\"=\",\"\u003e\",\"?\",\"@\",\"[\",\"\\\",\"]\",\"^\",\"_\",\"{\",\"|\",\"}\",\"~\",\"!\"))\r\n        \r\n    $password=\"\"\r\n    $rand=New-Object System.Random\r\n        \r\n    # Generate password by appending a random value from the array list until desired length of password is reached\r\n    1..$PasswordLength | foreach { $password = $password + $CharPool[$rand.Next(0,$CharPool.Count)] }  \r\n\r\n    # Replace characters to avoid confusion\r\n    $password = $password.replace(\"o\", \"p\")\r\n    $password = $password.replace(\"O\", \"P\")\r\n    $password = $password.replace(\"i\", \"k\")\r\n    $password = $password.replace(\"I\", \"K\")\r\n    $password = $password.replace(\"0\", \"9\")\r\n    $password = $password.replace(\"l\", \"m\")\r\n    $password = $password.replace(\"L\", \"M\")\r\n    $password = $password.replace(\"|\", \"_\")\r\n    $password = $password.replace(\"``\", \"_\")\r\n    $password = $password.replace(\"`\"\", \"R\")\r\n    $password = $password.replace(\"\u003c\", \"F\")\r\n    $password = $password.replace(\"\u003e\", \"v\")  \r\n\r\n    #print password\r\n    $password\r\n}\r\n\r\n\r\n#Change mapping here\r\n$account = @{\r\n    userType = $form.employeeType.Type\r\n    displayName = $form.naming.displayname\r\n    userPrincipalName = $form.naming.userPrincipalName\r\n    mailNickname = $form.naming.userPrincipalName.split(\"@\")[0];\r\n    mail = $form.naming.userPrincipalName\r\n    showInAddressList = $true;\r\n\r\n    accountEnabled = $true;\r\n    passwordProfile = @{\r\n        password = New-RandomPassword(16)\r\n        forceChangePasswordNextSignIn = $false\r\n    }\r\n\r\n    givenName = $form.givenname\r\n    surname = $form.naming.surname\r\n\r\n    jobTitle = $form.title\r\n    department = $form.department\r\n    # officeLocation = \"Baarn\"\r\n    # companyName = \"Tools4ever\"\r\n\r\n    # mobilePhone = \"0612345678\"\r\n    # businessPhones = @(\"0229 123456\")\r\n    # faxNumber = \"\"\r\n\r\n    # employeeId = \"12345678\"\r\n\r\n    UsageLocation       =   \"NL\"\r\n    PreferredLanguage   =   \"NL\"\r\n\r\n    #Country             =   \"Netherlands\"\r\n    #State               =   \"Utrecht\"\r\n    #City                =   \"Baarn\"\r\n    #StreetAddress       =   \"Amalialaan 126C\"\r\n    #PostalCode          =   \"3743 KJ\"\r\n    \r\n    # onPremisesExtensionAttributes =  @{\r\n    #     extensionAttribute1 = \"\";\r\n    #     extensionAttribute2 = \"\";\r\n    #     extensionAttribute3 = \"\";\r\n    #     extensionAttribute4 = \"\";\r\n    #     extensionAttribute5 = \"\";\r\n    #     extensionAttribute6 = \"\";\r\n    #     extensionAttribute7 = \"\";\r\n    #     extensionAttribute8 = \"\";\r\n    #     extensionAttribute9 = \"\";\r\n    #     extensionAttribute10 = \"\";\r\n    #     extensionAttribute11 = \"\";\r\n    #     extensionAttribute12 = \"\";\r\n    #     extensionAttribute13 = \"\";\r\n    #     extensionAttribute14 = \"\";\r\n    #     extensionAttribute15 = \"\";\r\n    # }\r\n}\r\n\r\n# Filter out empty properties\r\n$account = Remove-EmptyValuesFromHashtable $account\r\n$account = [PSCustomObject]$account\r\n\r\ntry{\r\n    Write-Verbose \"Generating Microsoft Graph API Access Token..\"\r\n\r\n    $baseUri = \"https://login.microsoftonline.com/\"\r\n    $authUri = $baseUri + \"$AADTenantID/oauth2/token\"\r\n\r\n    $body = @{\r\n        grant_type      = \"client_credentials\"\r\n        client_id       = \"$AADAppId\"\r\n        client_secret   = \"$AADAppSecret\"\r\n        resource        = \"https://graph.microsoft.com\"\r\n    }\r\n    \r\n    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType \"application/x-www-form-urlencoded\"\r\n    $accessToken = $Response.access_token;\r\n\r\n    Write-Verbose \"Creating AzureAD user [$($account.userPrincipalName)]..\"\r\n    \r\n    #Add the authorization header to the request\r\n    $authorization = @{\r\n        Authorization = \"Bearer $accesstoken\";\r\n        \"Content-Type\" = \"application/json\";\r\n        Accept = \"application/json\";\r\n    }\r\n    \r\n    $baseCreateUri = \"https://graph.microsoft.com/\"\r\n    $createUri = $baseCreateUri + \"v1.0/users\"\r\n    $body = $account | ConvertTo-Json -Depth 10\r\n    \r\n    $response = Invoke-RestMethod -Uri $createUri -Method POST -Headers $authorization -Body $body -Verbose:$false\r\n\r\n    Write-Information \"AzureAD user [$($account.userPrincipalName)] created successfully\"\r\n    $Log = @{\r\n        Action            = \"CreateAccount\" # optional. ENUM (undefined = default) \r\n        System            = \"AzureActiveDirectory\" # optional (free format text) \r\n        Message           = \"AzureAD user [$($account.userPrincipalName)] created successfully\" # required (free format text) \r\n        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = $($account.displayName) # optional (free format text) \r\n        TargetIdentifier  = $([string]$response.id) # optional (free format text) \r\n    }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log\r\n}catch{\r\n    Write-Error \"Error creating AzureAD user [$($account.userPrincipalName)]. Error: $_\"\r\n    $Log = @{\r\n        Action            = \"CreateAccount\" # optional. ENUM (undefined = default) \r\n        System            = \"AzureActiveDirectory\" # optional (free format text) \r\n        Message           = \"Error creating AzureAD user [$($account.userPrincipalName)].\" # required (free format text) \r\n        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = $($account.displayName) # optional (free format text) \r\n        TargetIdentifier  = $([string]$response.id) # optional (free format text) \r\n    }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log\r\n}","runInCloud":true}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-user-plus" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

