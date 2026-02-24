FROM mcr.microsoft.com/dotnet/aspnet:5.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:5.0 AS build
WORKDIR /src
COPY ["MoodleHack.API/MoodleHack.API.csproj", "MoodleHack.API/"]
COPY ["MoodleHack.Domain/MoodleHack.Domain.csproj", "MoodleHack.Domain/"]
COPY ["MoodleHack.Infrastructure.Data/MoodleHack.Infrastructure.Data.csproj", "MoodleHack.Infrastructure.Data/"]

RUN dotnet restore "MoodleHack.API/MoodleHack.API.csproj"
COPY . .
WORKDIR "/src/MoodleHack.API"
RUN dotnet build "MoodleHack.API.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "MoodleHack.API.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "MoodleHack.API.dll"]
