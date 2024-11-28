FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine AS build-env
WORKDIR /src

COPY ["DataAccess/DataAccess.csproj", "DataAccess/"]
COPY ["Domain/Domain.csproj", "Domain/"]
COPY ["IoCConfig/IoCConfig.csproj", "IoCConfig/"]
COPY ["Service/Service.csproj", "Service/"]
COPY ["LPS.Security.API/LPS.Security.API.csproj", "LPS.Security.API/"]

RUN dotnet restore "LPS.Security.API/LPS.Security.API.csproj"

COPY . .

WORKDIR "/src/LPS.Security.API"

RUN dotnet build "LPS.Security.API.csproj" -c Release -o /app

RUN dotnet publish "LPS.Security.API.csproj" -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine

WORKDIR "/app"

COPY --from=build-env /app .

EXPOSE 80

CMD ["./LPS.Security.API"]
#ENTRYPOINT ["dotnet", "LPS.Security.API.dll"]