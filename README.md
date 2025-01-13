This sample code is intended to be read in conjunction with a blog about digitally signing PDFs using a certificate that is based on Azure.
It assumes the folder layout used by https://docs.apryse.com/core/samples#digitalsignatures, and can be used as a drop in replacement.
You will need to create an app.config file that contains values that you can find in your Azure key vault.

Required values are 
* TenantId
* ClientID
* KeyVault Secret
* URI of Key vault
* URI of key for certificate
* Name of certificate to be used for signing
