# usage: 
# docker build -t macaroonapp
# docker run -it --rm -p 5000:80 --name macaroon_sample macaroonapp 

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /source

# copy csproj's and restore as distinct layers
COPY *.sln .
COPY Macaroon/*.csproj ./Macaroon/
COPY MacaroonCore/*.csproj ./MacaroonCore/
COPY MacaroonCoreTests/*.csproj ./MacaroonCoreTests/
RUN dotnet restore 

# copy everything else and build app
COPY Macaroon/. ./Macaroon/
WORKDIR /source/Macaroon
RUN dotnet publish -c release -o /app --no-restore

# final stage/image 
FROM mcr.microsoft.com/dotnet/aspnet:3.1
WORKDIR /app
COPY --from=build /app ./
ENTRYPOINT ["dotnet", "Macaroon.dll"]