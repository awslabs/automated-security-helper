# dotnet-vulnerable captured output

Real output of the scanner's argv from the .NET SDK 10.0.404 (linux-x64 archive
`dotnet-sdk-10.0.404-linux-x64.tar.gz`, SHA512
`577d0eb17fec33d029104c5c63a1ab0accc3e28776274abef2218dbac5af18d2109b5406d26b31d76f5c245215e3ba0926a94c20246c672c41847c9e1eb1dc50`
as Microsoft's 10.0 release metadata publishes it; `dotnet --version` printed `10.0.404`), run on
2026-11-26 from `/tmp/dotnet_vulnerable-capture`, the directory that held `pos/` and `neg/`:

```
dotnet restore pos/App.csproj
dotnet list pos/App.csproj package --vulnerable --include-transitive --format json --output-version 1
dotnet restore neg/App.csproj
dotnet list neg/App.csproj package --vulnerable --include-transitive --format json --output-version 1
```

Both `list` runs exited 0 and wrote nothing to stderr; stdout was the JSON report alone. The
advisory data came from `https://api.nuget.org/v3/index.json`, so a later run can report more as
advisories are published.

| File | What it is |
|---|---|
| `positive.json` | The report for `pos/App.csproj` below: two vulnerable top-level packages and two vulnerable transitive ones (`Npgsql` and `Microsoft.Extensions.Caching.Memory`, both pulled in by `Npgsql.EntityFrameworkCore.PostgreSQL`), each listed under both target frameworks. Re-serialized by the repository's JSON formatter (two-space indent, sorted keys); no value changed. |
| `negative.json` | The report for `neg/App.csproj` below: nothing vulnerable, so the project carries its `path` and no `frameworks` key. Re-serialized the same way. |
| `positive.sarif` | What the scanner writes for `positive.json` (`convert_report` with the project uri `pos/App.csproj`, in the scanner's own report). Regenerate it with the test `test_the_committed_sarif_is_what_the_scanner_writes`. |

The two inputs, which are not committed as project files:

`pos/App.csproj`

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFrameworks>net8.0;net10.0</TargetFrameworks>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
    <PackageReference Include="System.Text.Encodings.Web" Version="4.5.0" />
    <PackageReference Include="Npgsql.EntityFrameworkCore.PostgreSQL" Version="8.0.0" />
  </ItemGroup>
</Project>
```

`neg/App.csproj`

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>
```

The restore of `pos/App.csproj` also printed NuGet audit warnings (NU1903 for the three High
advisories, NU1904 for the Critical one) and NU1510 for the explicit `System.Text.Encodings.Web`
reference. They are restore output, not part of the report.

The same `list` command on an unrestored copy of `pos/App.csproj` restored the project itself
(it wrote `obj/` beside the project file) and printed the same report, again with nothing ahead of
the JSON on stdout.

The SARIF file is the corpus the facets register's consistency gate reads. The hand-built reports
in `../reports/` stay for the severity rows a real run cannot be made to produce (Moderate, Low,
an unrated advisory, a severity name the scanner does not know).
