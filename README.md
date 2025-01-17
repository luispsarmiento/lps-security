# LPS.Security.API

## Follow this minimum steps to configure the LPS Security App in Debug mode
1. Ensure that an Azure Key Vault resource is available, as it is required for this configuration.
2. Install the [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-linux?pivots=apt "Azure CLI") if it is not already installed.
3. Log in to Azure using your Azure credential by running the following command: `az login`
4. Navigate to `LPS.Security.API > Properties > launchSettings.json` and replace `"your_key_vault_uri"` with the actual URI of your Azure Key Vault. 

## Ceate a Azure CosmosDB resource

1. Create a resource group first:
`az group create --location <myLocation> --name az204-cosmos-rg --subscription <ID_Sub>`
2. Create the Azure CosmosDB Account:
`az cosmosdb create --name <myCosmosDBacct> --resource-group az204-cosmos-rg`
3. Retrieve the principal key:
`az cosmosdb keys list --name <myCosmosDBacct> --resource-group az204-cosmos-rg`

> Check [here](https://learn.microsoft.com/en-us/azure/azure-resource-manager/troubleshooting/error-register-resource-provider?tabs=azure-cli "here") just the provider Microsoft.DocumentDB is not registered.

## Config the Application using CosmosDB
1. Install the Microsoft.Azure.Cosmos package:
`dotnet add package Microsoft.Azure.Cosmos`
2. Config a cosmos cliente with the values to EndpointUri and the Principal Key.