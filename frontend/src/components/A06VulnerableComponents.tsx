import React, { useState } from "react";
import axios from "axios";
import "./VulnerabilityPage.css";

const A06VulnerableComponents: React.FC = () => {
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [showCSharpExamples, setShowCSharpExamples] = useState(false);

  const fetchDependencies = async () => {
    setLoading(true);
    try {
      const res = await axios.get(
        "http://localhost:3001/api/a06/dependencies"
      );
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const handleUnpatchedInfo = async () => {
    setLoading(true);
    try {
      const res = await axios.get(
        "http://localhost:3001/api/a06/unpatched-info"
      );
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  return (
    <div className="vulnerability-page">
      <div className="vuln-header">
        <h1>A06 - Vulnerable and Outdated Components</h1>
        <div className="vulnerability-badge">OWASP #6</div>
      </div>
      <div className="vuln-description">
        <p>
          Using components with known vulnerabilities is a widespread issue.
          This demo shows how an application can be at risk due to outdated
          dependencies, deprecated functions, and unpatched vulnerabilities.
        </p>
      </div>

      <div className="demo-section">
        <h2>📦 Demo 1: Outdated Dependencies</h2>
        <p>
          This demo simulates a scan that finds outdated and vulnerable
          dependencies in the project. An attacker can exploit these known
          vulnerabilities to compromise the application.
        </p>
        <div className="demo-controls">
          <button onClick={fetchDependencies} disabled={loading}>
            Scan for Outdated Dependencies
          </button>
        </div>
      </div>

      <div className="demo-section">
        <h2>🚨 Demo 2: Unpatched CVEs</h2>
        <p>
          This demo simulates a security scanner finding critical, unpatched
          vulnerabilities (CVEs - Common Vulnerabilities and Exposures) in the application's components. Each CVE
          represents a known exploit that attackers can use.
        </p>
        <div className="demo-controls">
          <button onClick={handleUnpatchedInfo} disabled={loading}>
            Scan for Unpatched CVEs
          </button>
        </div>
      </div>

      {response && (
        <div className="response-section">
          <h3>Response:</h3>
          <pre className="response-box">
            {JSON.stringify(response, null, 2)}
          </pre>
        </div>
      )}

      <div className="remediation-section">
        <h2>🛡️ How to Fix This</h2>

        <div className="code-examples">
          <div className="code-example">
            <h3>JavaScript/Node.js - Dependency Management</h3>
            <pre className="code-block">
              {`// package.json - Lock down dependencies
{
  "dependencies": {
    "express": "^4.18.2",
    "helmet": "^7.0.0",
    "jsonwebtoken": "^9.0.0"
  },
  "scripts": {
    "audit": "npm audit",
    "audit-fix": "npm audit fix",
    "outdated": "npm outdated",
    "update-check": "npm-check-updates -u"
  },
  "engines": {
    "node": ">=18.0.0",
    "npm": ">=8.0.0"
  }
}

// Automated security scanning in CI/CD
// .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - run: npm ci
      - run: npm audit --audit-level=high
      - run: npx snyk test

// Regular dependency updates with Renovate
// renovate.json
{
  "extends": ["config:base"],
  "schedule": ["before 9am on monday"],
  "packageRules": [
    {
      "matchUpdateTypes": ["minor", "patch"],
      "automerge": true
    },
    {
      "matchUpdateTypes": ["major"],
      "assignees": ["security-team"]
    }
  ]
}

// Runtime dependency validation
const semver = require('semver');
const packageJson = require('./package.json');

const validateDependencies = () => {
  const criticalDeps = ['express', 'helmet', 'jsonwebtoken'];

  for (const dep of criticalDeps) {
    const installedVersion = require(\`\${dep}/package.json\`).version;
    const requiredVersion = packageJson.dependencies[dep];

    if (!semver.satisfies(installedVersion, requiredVersion)) {
      throw new Error(\`Dependency \${dep} version mismatch\`);
    }
  }
};

// Subresource Integrity for CDN resources
const generateSRIHash = (algorithm, content) => {
  const crypto = require('crypto');
  const hash = crypto.createHash(algorithm).update(content).digest('base64');
  return \`\${algorithm}-\${hash}\`;
};

// Example usage in HTML template
const sriHash = generateSRIHash('sha384', cssContent);
// <link rel="stylesheet" href="..." integrity="sha384-..." crossorigin="anonymous">`}
            </pre>
          </div>

          <div className="code-example">
            <div
              className="code-example-header"
              onClick={() => setShowCSharpExamples(!showCSharpExamples)}
              style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', marginBottom: '10px' }}
            >
              <h3 style={{ margin: 0 }}>C#/.NET - Dependency Management</h3>
              <span style={{ marginLeft: '10px', fontSize: '14px' }}>
                {showCSharpExamples ? '▼ Hide' : '▶ Show'}
              </span>
            </div>
            {showCSharpExamples && (
              <pre className="code-block">
                {`// .csproj - Package vulnerability scanning
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net7.0</TargetFramework>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <EnableNETAnalyzers>true</EnableNETAnalyzers>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="7.0.9" />
    <PackageReference Include="BCrypt.Net-Next" Version="4.0.3" />
    <PackageReference Include="Serilog.AspNetCore" Version="7.0.0" />
  </ItemGroup>

  <!-- Security analyzers -->
  <ItemGroup>
    <PackageReference Include="Microsoft.CodeAnalysis.NetAnalyzers" Version="7.0.3">
      <PrivateAssets>all</PrivateAssets>
      <IncludeAssets>runtime; build; native; contentfiles; analyzers</IncludeAssets>
    </PackageReference>
    <PackageReference Include="SecurityCodeScan.VS2019" Version="5.6.7">
      <PrivateAssets>all</PrivateAssets>
      <IncludeAssets>runtime; build; native; contentfiles; analyzers</IncludeAssets>
    </PackageReference>
  </ItemGroup>
</Project>

// Startup.cs - Runtime dependency validation
public class DependencyValidator
{
    public static void ValidateSecurityPackages(IServiceProvider services)
    {
        var requiredServices = new[]
        {
            typeof(IAuthenticationService),
            typeof(IAuthorizationService),
            typeof(ILogger<>)
        };

        foreach (var serviceType in requiredServices)
        {
            var service = services.GetService(serviceType);
            if (service == null)
            {
                throw new InvalidOperationException($"Required security service {serviceType.Name} not registered");
            }
        }
    }
}

// NuGet package update automation
// .github/workflows/dependency-update.yml
name: Dependency Update
on:
  schedule:
    - cron: '0 9 * * MON'
jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-dotnet@v3
        with:
          dotnet-version: '7.0.x'
      - run: dotnet list package --outdated
      - run: dotnet list package --vulnerable
      - run: dotnet restore --force-evaluate

// Custom vulnerability scanner
public class VulnerabilityScanner
{
    public async Task<List<VulnerabilityReport>> ScanDependenciesAsync()
    {
        var vulnerabilities = new List<VulnerabilityReport>();

        // Check against known vulnerability databases
        var packages = GetInstalledPackages();

        foreach (var package in packages)
        {
            var vulns = await CheckVulnerabilityDatabase(package.Name, package.Version);
            vulnerabilities.AddRange(vulns);
        }

        return vulnerabilities;
    }

    private List<PackageInfo> GetInstalledPackages()
    {
        // Parse project files to get package references
        // Implementation would read .csproj files
        return new List<PackageInfo>();
    }
}`}
              </pre>
            )}
          </div>
        </div>

        <div className="remediation-grid">
          <div className="fix-item">
            <h4>1. Automated Scanning</h4>
            <p>Implement automated dependency vulnerability scanning</p>
            <code>npm audit, Snyk, OWASP Dependency-Check</code>
          </div>
          <div className="fix-item">
            <h4>2. Regular Updates</h4>
            <p>Keep all dependencies updated with latest patches</p>
            <code>Renovate, Dependabot, automated PRs</code>
          </div>
          <div className="fix-item">
            <h4>3. Version Pinning</h4>
            <p>Use exact versions for critical dependencies</p>
            <code>package-lock.json, yarn.lock</code>
          </div>
          <div className="fix-item">
            <h4>4. Source Verification</h4>
            <p>Verify packages come from trusted sources</p>
            <code>Package signatures, checksums</code>
          </div>
        </div>

        <div className="best-practices">
          <h3>🏆 Best Practices</h3>
          <ul>
            <li>
              <strong>Inventory Management:</strong> Maintain complete inventory
              of all components and versions
            </li>
            <li>
              <strong>Automated Monitoring:</strong> Use tools to continuously
              monitor for vulnerabilities
            </li>
            <li>
              <strong>Patch Management:</strong> Establish process for rapid
              security patch deployment
            </li>
            <li>
              <strong>Least Privilege:</strong> Run components with minimum
              necessary privileges
            </li>
            <li>
              <strong>Source Verification:</strong> Only use components from
              trusted, official sources
            </li>
            <li>
              <strong>Security Testing:</strong> Test updates in staging before
              production deployment
            </li>
          </ul>
        </div>
      </div>

      <div className="navigation-section">
        <a href="/web/a07" className="next-button">
          Next: A07 - Authentication Failures →
        </a>
      </div>
    </div>
  );
};

export default A06VulnerableComponents;
