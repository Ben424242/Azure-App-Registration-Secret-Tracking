# Get all apps with secrets
# Flag if it doesn't have an email tag
# Flag all its secrets that have a > 2 year expiration

param (
  [Parameter(Mandatory = $true)]
  [string] $subscriptionName,
  [String] $emailTenantId,
  [String] $emailClientId,
  [String] $emailUPN, #email address that the email will come from
  [String] $keyVaultName
)

try {
  "Logging in to Azure..."
  Connect-AzAccount -Identity
  Set-AzContext -SubscriptionName $subscriptionName
}
catch {
  Write-Error -Message $_.Exception
  throw $_.Exception
}

$companyEmailSuffix = "contoso.com" #for checking the vailidity of the email addresses
$toAddress = "somebody@contoso.com"
$ccAddress = "sombodyelse@contoso.com"

$emailClientSecret = Get-AzKeyVaultSecret -VaultName keyVaultName -Name "AzAutomation-EmailNotifications" -AsPlainText



class appWithSecrets {
  [string]$name
  [string]$pwdExpiration
  [string]$certExpiration
  [string]$emailAddresses
}

class badEmailApp {
  [string]$name
  [string]$emailAddress
}

$badApps = @()
$appsWithSecNoEmail = @()


$applications = Get-AzADApplication -First 10000

#find the ones with too long secrets and add them to the list of app objects
foreach ($application in $applications) {
  $emailString = $null
  $isProxy = $false
  $secrets = $application | Get-AzADAppCredential

  if ($secrets) {
    $tags = $application.tag
    foreach ($tag in $tags) {
      $tagParts = $tag.Split(':')
      switch ($tagParts[0]) {
        "notificationEmail" { 
          $emailString = $tagParts[1]
        }
        "applicationType" {
          if ($tagParts[1] -eq 'proxy') {
            #we also tag for app proxy app registrations because we don't need to check those
            $isProxy = $true
          }
        }
      }
    }

    if (-not $isProxy) {
      #check if it has an email tag
      if (-not $emailString -or (-not $emailString.ToLower().EndsWith($companyEmailSuffix))) {
        $appObject = [badEmailApp]::new()
        $appObject.name = $application.DisplayName
        $appObject.emailAddress = $emailString
        $appsWithSecNoEmail += $appObject
      }

      $certs = $secrets | Where-Object { $_.type -eq "AsymmetricX509Cert" }
      $pwds = $secrets  | Where-Object { $_.type -eq $null }
      
      if ($certs) {
        foreach ($cert in $certs) {
          if (($cert.EndDateTime) -gt ($cert.StartDateTime).AddYears(2)) {
            $appObject = [appWithSecrets]::new()
            $appObject.name = $application.DisplayName
            $appObject.emailAddresses = $emailString
            $appObject.certExpiration = $cert.EndDateTime.ToString()
            $badApps += $appObject
          }
        }
      }

      if ($pwds) {
        foreach ($pwd in $pwds) {
          if (($pwd.EndDateTime) -gt ($pwd.StartDateTime).AddYears(2)) {
            $appObject = [appWithSecrets]::new()
            $appObject.name = $application.DisplayName
            $appObject.emailAddresses = $emailString
            $appObject.pwdExpiration = $pwd.EndDateTime.ToString()
            $badApps += $appObject
          }
        }
      }
    }
  }
}

# set up for emailing the report

$emailBody = "<h3>Apps with non-compliant secret expiration dates</h3><br>"
$emailBody += "<table>"
$emailBody += "<tr>"
$emailBody += "<th>Name</th>"
$emailBody += "<th>Client Secret</th>"
$emailBody += "<th>Cert</th>"
$emailBody += "<th>Contact Email</th>"
$emailBody += "</tr>"
foreach ($badApp in $badApps) {
  $emailBody += "<tr>"
  $emailBody += "<td>$($badApp.name)</td>"
  $emailBody += "<td>$($badApp.pwdExpiration)</td>"
  $emailBody += "<td>$($badApp.certExpiration)</td>"
  $emailBody += "<td>$($badApp.emailAddresses)</td>"
  $emailBody += "</tr>"
}
$emailBody += "</table>"
$emailBody += "<h4>Apps with missing or bad contact email</h4>"
$emailBody += "<table>"
$emailBody += "<tr>"
$emailBody += "<th>Name</th>"
$emailBody += "<th>Contact Email</th>"
$emailBody += "</tr>"
foreach ($appWithSecNoEmail in $appsWithSecNoEmail) {
  $emailBody += "<tr>"
  $emailBody += "<td>$($appWithSecNoEmail.name)</td>"
  $emailBody += "<td>$($appWithSecNoEmail.emailAddress)</td>"
  $emailBody += "</tr>"
}
$emailBody += "</table>"



$config = @{ 
  ClientID         = $emailClientId
  TenantID         = $emailTenantId
  ClientSecret     = $emailClientSecret
  ImpersonationUpn = $emailUPN
  To               = $toAddress
  cc               = $ccAddress
  Subject          = 'App Registration Non-Compliance Report' 
  Body             = $emailBody
}



# We need to request an OAuth token so we craft an OAuth token request  
$tokenRequestBody = @{
  Grant_Type    = 'client_credentials'
  Scope         = 'https://graph.microsoft.com/.default'
  client_Id     = $config.ClientID
  Client_Secret = $config.ClientSecret
}   

# Call the REST API to obtain a token so we can authenticate and send the message

$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$($config.TenantID)/oauth2/v2.0/token" -Method POST -Body $tokenRequestBody -ContentType 'application/x-www-form-urlencoded'
# Each user has a URI based on their UPN that we can send the REST API call to send the message
$sendMailUri = "https://graph.microsoft.com/v1.0/users/$($config.ImpersonationUpn)/sendMail"

# The message is defined using a JSON based request. Note that we can define a JSON request using
# nested PowerShell hashtables and then converting it into a JSON string.
# See https://docs.microsoft.com/en-us/graph/api/user-sendmail?view=graph-rest-1.0&tabs=http for

# examples on crafting a SendMail JSON request.  

$sendMailRequest = @{  
  message         = @{
    subject      = $config.Subject
    body         = @{
      contentType = 'HTML'
      content     = $config.Body
    }  
  
    toRecipients = @(
      @{
        emailAddress = @{
          address = $config.To
        }
      }
    )

    ccRecipients = @(
      @{
        emailAddress = @{
          address = $config.cc
        }
      }
    )
  }
  saveToSentItems = 'false' 
}

$emailHeaders = @{
  Authorization = "Bearer $($TokenResponse.access_token)"
}

# Convert the hashtable to a JSON string so we can send it to the API properly
$sendMailRequestJson = ConvertTo-Json $sendMailRequest -Depth 4

# Make the REST API call so we can send the message
Invoke-RestMethod -Headers $emailHeaders -Uri $sendMailUri -Body $sendMailRequestJson -Method Post -ContentType 'application/json'