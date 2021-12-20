# Azure-App-Registration-Secret-Tracking
Code for tracking secrets and certs in Azure AD App registrations for expirations

Since Azure AD App Registrations can now be tagged, we are using that feature to implement a system where users can be notified
when their client secrets or certificates are expired, or about to expire.

You can manually add a tag by editing the manifest of the App Reg in the Azure portal. Or you can use the 
Update-AzADApplication PowerShell commandlet with the -Tag to add/change the tags of the registration.

There are two scripts are PoweShell runbooks that run in an Azure Automation account.

The FindExpiringAADSecrets.ps1 script runs daily. It find secrets that are about to expire, or that have expired
and sends a notice to an address of someone responsible for the app reg. It finds the email address in the Tag field 
of the app registration.

It expects the format of the tag to be "notificationEmail:address@example.com"

The AppRegistrationNonComplianceReport.ps1 script runs weekly. It looks at all the App Registrations to find any that
don't have a tag with a notification email or have a badly formed email (e.g. no domain suffix).

If also finds secrets that have validity periods greater than 2 years.
