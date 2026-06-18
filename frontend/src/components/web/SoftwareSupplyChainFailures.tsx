import React, { useState } from "react";
import { Link } from "react-router-dom";
import axios from "axios";
import "../VulnerabilityPage.css";
import { WebVulnProps } from "./types";

const SoftwareSupplyChainFailures: React.FC<WebVulnProps> = ({ meta, next }) => {
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [artifactUrl, setArtifactUrl] = useState(
    "http://cdn.build-cache.internal/app-release-2.4.1.tar.gz"
  );
  const [showCSharpExamples, setShowCSharpExamples] = useState(false);

  const fetchDependencies = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${meta.apiBase}/dependencies`);
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const handleUnpatchedInfo = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${meta.apiBase}/unpatched-info`);
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const handleDependencyConfusion = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${meta.apiBase}/dependency-confusion`);
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const handleVerifyArtifact = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${meta.apiBase}/verify-artifact`, {
        url: artifactUrl,
      });
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const handlePostinstall = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${meta.apiBase}/postinstall-script`);
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  return (
    <div className="vulnerability-page">
      <div className="vuln-header">
        <h1>{meta.code} - {meta.title}</h1>
        <div className="vulnerability-badge">OWASP #{meta.rank}</div>
      </div>
      <div className="vuln-description">
        <p>
          New in OWASP 2025, this category broadens the old "Vulnerable and
          Outdated Components" to cover the <strong>entire software supply
          chain</strong> — the dependencies you pull in, the build systems that
          assemble your software, and the channels that distribute it. A
          compromise anywhere along that chain ends up running inside your
          application or your CI.
        </p>
      </div>

      <div className="demo-section">
        <h2>📦 Demo 1: Outdated &amp; Vulnerable Dependencies</h2>
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

      <div className="demo-section">
        <h2>🎭 Demo 3: Dependency Confusion</h2>
        <p>
          An internal package name (<code>@acme/auth-utils</code>) also exists on
          the public registry — at a higher version. With no scoped-registry
          pinning, the resolver pulls the attacker's <em>public</em> package into
          the build, and its install scripts then run inside CI.
        </p>
        <div className="demo-controls">
          <button onClick={handleDependencyConfusion} disabled={loading}>
            Resolve Package
          </button>
        </div>
        <div className="vulnerability-explanation">
          <h4>🚨 Why this is dangerous:</h4>
          <ul>
            <li>Attacker code executes inside your build pipeline</li>
            <li>CI secrets and source code are exposed</li>
            <li>No exploit of your app needed — the build trusts the registry</li>
          </ul>
        </div>
      </div>

      <div className="demo-section">
        <h2>📥 Demo 4: Unsigned / Unverified Build Artifact</h2>
        <p>
          The deploy pipeline downloads a release artifact and ships it with no
          checksum or signature check. A tampered tarball — from a compromised
          CDN or a man-in-the-middle over plain HTTP — is trusted and deployed
          straight to production.
        </p>
        <div className="demo-controls">
          <label>
            Artifact URL:
            <input
              type="text"
              value={artifactUrl}
              onChange={(e) => setArtifactUrl(e.target.value)}
              style={{ width: "400px" }}
            />
          </label>
          <button onClick={handleVerifyArtifact} disabled={loading}>
            "Verify" &amp; Deploy
          </button>
        </div>
      </div>

      <div className="demo-section">
        <h2>🪝 Demo 5: Malicious postinstall Script</h2>
        <p>
          Package lifecycle scripts run arbitrary code on every{" "}
          <code>npm install</code>. This demo shows what a malicious dependency's
          <code>postinstall</code> hook would harvest from the build environment
          (secrets are redacted here — nothing is actually exfiltrated).
        </p>
        <div className="demo-controls">
          <button onClick={handlePostinstall} disabled={loading}>
            Run postinstall (simulated)
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
    "node": ">=18.0.0",   // a SUPPORT floor only — npm does NOT install Node from this
    "npm": ">=8.0.0"
  }
}

// "engines" just declares what you support. Pin the ACTUAL runtime with exact versions:
//   .nvmrc      ->  20.11.1   (exact Node — used locally and by CI actions/setup-node)
//   Dockerfile  ->  FROM node:20.11.1-bookworm@sha256:<digest>   (pin the tag AND digest)
// Dependencies above use ^ ranges, but the committed package-lock.json + "npm ci"
// pin the exact resolved tree (with integrity hashes) — that lockfile is the real control.

// .npmrc - defeat dependency confusion + enforce the pins
// @acme:registry=https://npm.internal.acme.corp   // internal scope -> private registry
// engine-strict=true    // fail the install if Node/npm fall outside "engines"
// save-exact=true       // write exact versions (no ^ ranges) into package.json
// ignore-scripts=true   // don't run arbitrary lifecycle scripts on install

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
      - run: npm ci --ignore-scripts        // reproducible install, no lifecycle scripts
      - run: npm audit --audit-level=high
      - run: npx snyk test

// Verify a build artifact before trusting it (checksum + signature)
const crypto = require('crypto');
const verifyArtifact = (bytes, expectedSha256) => {
  const actual = crypto.createHash('sha256').update(bytes).digest('hex');
  if (actual !== expectedSha256) {
    throw new Error('Artifact checksum mismatch - refusing to deploy');
  }
  // Also verify a cosign/sigstore or GPG signature and SLSA provenance here.
};

// Subresource Integrity for CDN resources
const generateSRIHash = (algorithm, content) => {
  const hash = crypto.createHash(algorithm).update(content).digest('base64');
  return \`\${algorithm}-\${hash}\`;
};
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

// nuget.config - pin internal packages to the private feed (dependency confusion)
<configuration>
  <packageSources>
    <add key="acme-internal" value="https://nuget.internal.acme.corp/v3/index.json" />
  </packageSources>
  <packageSourceMapping>
    <packageSource key="acme-internal">
      <package pattern="Acme.*" />
    </packageSource>
  </packageSourceMapping>
</configuration>

// NuGet package update + vulnerability automation
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

// Verify a downloaded artifact's signature before trusting it
public class ArtifactVerifier
{
    public void EnsureTrusted(byte[] artifact, string expectedSha256)
    {
        using var sha = System.Security.Cryptography.SHA256.Create();
        var actual = Convert.ToHexString(sha.ComputeHash(artifact)).ToLowerInvariant();
        if (actual != expectedSha256)
            throw new SecurityException("Artifact checksum mismatch - refusing to deploy");
        // Also verify an Authenticode / cosign signature and SLSA provenance.
    }
}`}
              </pre>
            )}
          </div>
        </div>

        <div className="remediation-grid">
          <div className="fix-item">
            <h4>1. Automated Scanning &amp; SBOM</h4>
            <p>Scan dependencies and ship a software bill of materials</p>
            <code>npm audit, Snyk, OWASP Dependency-Check, CycloneDX</code>
          </div>
          <div className="fix-item">
            <h4>2. Pinned, Integrity-Checked Installs</h4>
            <p>Lockfiles with hashes; never run untrusted lifecycle scripts</p>
            <code>npm ci --ignore-scripts, package-lock integrity</code>
          </div>
          <div className="fix-item">
            <h4>3. Scoped / Private Registries</h4>
            <p>Map internal names to the private feed to stop confusion</p>
            <code>@acme:registry=..., packageSourceMapping</code>
          </div>
          <div className="fix-item">
            <h4>4. Signed Artifacts &amp; Provenance</h4>
            <p>Verify signatures and build provenance before deploy</p>
            <code>cosign/sigstore, SLSA, pinned SHA-256</code>
          </div>
        </div>

        <div className="best-practices">
          <h3>🏆 Best Practices</h3>
          <ul>
            <li>
              <strong>Inventory Management:</strong> Maintain a complete SBOM of
              all components and versions
            </li>
            <li>
              <strong>Automated Monitoring:</strong> Continuously monitor
              dependencies and feeds for vulnerabilities
            </li>
            <li>
              <strong>Secure the Build:</strong> Treat CI/CD as production —
              least-privilege tokens, isolated runners, signed commits
            </li>
            <li>
              <strong>Verify Provenance:</strong> Only deploy artifacts with a
              verified signature and SLSA provenance
            </li>
            <li>
              <strong>Defeat Confusion:</strong> Reserve internal names publicly
              and pin scopes to private registries
            </li>
            <li>
              <strong>Disable Lifecycle Scripts:</strong> Install with
              <code>--ignore-scripts</code> and review dependencies before adding
            </li>
          </ul>
        </div>
      </div>

      <div className="navigation-section">
        {next && (
          <Link to={next.path} className="next-button">
            Next: {next.code} - {next.title} &rarr;
          </Link>
        )}
      </div>
    </div>
  );
};

export default SoftwareSupplyChainFailures;
