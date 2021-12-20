# Examine all apps with secrets
# Check to see when the client secret or certificate is going to expire
# Send a notification at 30, 15, 7, 1, 0, and every 7 days after expiration.


param (
  [Parameter(Mandatory = $true)]
  [string] $subscriptionName,
  [String] $emailTenantId,
  [String] $emailClientId,
  [String] $emailUPN, #UPN email address that the email will come from
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

$defaultToAddress = "somebody@contoso.com"
$ccAddress = "sombodyelse@contoso.com"

$emailClientSecret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name "AzAutomation-EmailNotifications" -AsPlainText



# set up for email Rest Calls
$config = @{ 
  ClientID         = $emailClientId
  TenantID         = $emailTenantId
  ClientSecret     = $emailClientSecret
  ImpersonationUpn = $emailUPN
  cc               = $ccAddress
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

class appSecret {
  [string]$Id
  [string]$ExpDate
}

###################################################
## Start Function Code
###################################################
function Send-Notification {
  param (
    $PwdList,
    $CertList
  )
  
  $isProxy = $false
  $tags = $application.tag

  foreach ($tag in $tags) {
    $tagParts = $tag.Split(':')
    switch ($tagParts[0]) {
      "notificationEmail" { 
        $emailString = $tagParts[1]
      }
      "applicationType" {
        if ($tagParts[1] -eq 'proxy') {
          $isProxy = $true
        }
      }
    }
  }

  if (-not $isProxy) {
    #don't notify if the secret is on a app proxy app

    # if no tag found, send the notice to a default mailbox
    if (-not $emailString) {
      $emailString = $defaultToAddress
    }

    $toStruct = @()
    $toList = $emailString.Split(';')
    foreach ($toAddress in $toList) {
      $toStruct += @{emailAddress = @{address = $toAddress } }
    }

    $ccStruct = @()
    $ccList = $config.cc.Split(';')
    foreach ($ccAddress in $ccList) {
      $ccStruct += @{emailAddress = @{address = $ccAddress } }
    }

    $subject = "QA App Registration Secret Expiration Notice!"

    $emailBody = "<h3>Your Azure Application Registration Secret in $TenantID tenant has expired or will expire soon!</h3>"
    $emailBody += "<h4>App Name: $($application.DisplayName)</h4>"
    $emailBody += "Application Id: $AppId<br>"
    $emailBody += "<h4>Client Secrets</h4>"
    foreach ($pwd in $pwdList) {
      $emailBody += "Client Secret Id: $($pwd.Id)<br>"
      $emailBody += "Expiration Date: $($pwd.ExpDate)<br><br>"  
    }
    $emailBody += "<h4>App Certificates</h4>"
    foreach ($cert in $CertList) {
      $emailBody += "Certificate Id: $($cert.Id)<br>"
      $emailBody += "Expiration Date: $($cert.ExpDate)<br><br>"  
    }
    
    $emailBody += "<h4>Please contact the appropriate administrator to renew the secret.</h4>"
    
    
    $sendMailRequest = @{  
      message         = @{
        subject      = $subject
        body         = @{
          contentType = 'HTML'
          content     = $emailBody
        }  
      
        toRecipients = $toStruct

        ccRecipients = $ccStruct
      }
      saveToSentItems = 'false' 
    }
    
    $emailHeaders = @{
      Authorization = "Bearer $($TokenResponse.access_token)"
    }
    
    # Convert the hashtable to a JSON string so we can send it to the API properly
    $sendMailRequestJson = ConvertTo-Json $sendMailRequest -Depth 4
    
    # Make the REST API call so we can send the message
    "Sending the message to $emailString"
    Invoke-RestMethod -Headers $emailHeaders -Uri $sendMailUri -Body $sendMailRequestJson -Method Post -ContentType 'application/json'
  }
}
###################################################
###  End Function
###################################################




###################################################
## Start Main Code
###################################################

$applications = Get-AzADApplication -First 10000
$today = (Get-Date).Date

foreach ($application in $applications) {
  $secrets = $application | Get-AzADAppCredential
  
  

  if ($secrets) {
    $appId = $application.AppId
    $pwdSecretList = @()
    $certSecretList = @() 
    $sendNotice = $false 
    $certs = $secrets | Where-Object { $_.type -eq "AsymmetricX509Cert" }
    $pwds = $secrets  | Where-Object { $_.type -eq $null }
    
    if ($certs) {
      foreach ($cert in $certs) {
        $appObject = [appSecret]::new()
        $appObject.Id = $cert.KeyId
        $appObject.ExpDate = $cert.EndDateTime.ToString()
        $certSecretList += $appObject

        $daysToExpire = ($cert.EndDateTime - $today).Days
      
        if ($daysToExpire -eq 30 -or $daysToExpire -eq 15 -or $daysToExpire -eq 7 -or $daysToExpire -eq 1 -or ($daysToExpire -le 0 -and $daysToExpire % 7 -eq 0)) {
          $sendNotice = $true
        }
      }
    }

    if ($pwds) {
      foreach ($pwd in $pwds) {
        $appObject = [appSecret]::new()
        $appObject.Id = $pwd.KeyId
        $appObject.ExpDate = $pwd.EndDateTime.ToString()
        $pwdSecretList += $appObject

        $daysToExpire = ($pwd.EndDateTime - $today).Days
      
        if ($daysToExpire -eq 30 -or $daysToExpire -eq 15 -or $daysToExpire -eq 7 -or $daysToExpire -eq 1 -or ($daysToExpire -le 0 -and $daysToExpire % 7 -eq 0)) {
          $sendNotice = $true
        }
      }
    }
    
    if ($sendNotice) {
      Send-Notification -PwdList $pwdSecretList -CertList $certSecretList
    }
  }
  
}