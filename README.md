# LPS.Security.API

## Ceate a Azure CosmosDB resource

1. Create a resource group first:
`az group create --location <myLocation> --name az204-cosmos-rg --subscription <ID_Sub>`
2. Create the Azure CosmosDB Account:
`az cosmosdb create --name <myCosmosDBacct> --resource-group az204-cosmos-rg`
3. Retrieve the principal key:
`az cosmosdb keys list --name <myCosmosDBacct> --resource-group az204-cosmos-rg`

> Check [here](https://learn.microsoft.com/en-us/azure/azure-resource-manager/troubleshooting/error-register-resource-provider?tabs=azure-cli "here") just the provider Microsoft.DocumentDB is not registered.

## Config the Application
1. Install the Microsoft.Azure.Cosmos package:
`dotnet add package Microsoft.Azure.Cosmos`
2. Config a cosmos cliente with the values to EndpointUri and the Principal Key.