import React, { useState } from "react";
import axios from "axios";
import "./VulnerabilityPage.css";

const A08IntegrityFailures: React.FC = () => {
  const [serializedData, setSerializedData] = useState(
    '{"username":"guest","role":"user"}'
  );
  const [file, setFile] = useState<File | null>(null);
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [showCSharpExamples, setShowCSharpExamples] = useState(false);

  const handleDeserialization = async () => {
    setLoading(true);
    try {
      const res = await axios.post(
        "http://localhost:3001/api/a08/deserialize",
        {
          serialized_data: serializedData,
        }
      );
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const handleUpdateCheck = async () => {
    setLoading(true);
    try {
      const res = await axios.get(
        "http://localhost:3001/api/a08/update-info"
      );
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const handleFileUpload = async () => {
    if (!file) {
      setResponse({ error: "Please select a file to upload." });
      return;
    }
    setLoading(true);
    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await axios.post(
        "http://localhost:3001/api/a08/upload",
        formData,
        {
          headers: {
            "Content-Type": "multipart/form-data",
          },
        }
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
        <h1>A08 - Software and Data Integrity Failures</h1>
        <div className="vulnerability-badge">OWASP #8</div>
      </div>
      <div className="vuln-description">
        <p>
          These failures occur when software updates, critical data, or CI/CD
          pipelines are not verified for their integrity. This can lead to the
          deployment of malicious code, unauthorized access, or system compromise.
        </p>
      </div>

      <div className="demo-section">
        <h2>💻 Demo 1: Insecure Deserialization</h2>
        <p>
          Insecure deserialization occurs when an application deserializes
          untrusted data without sufficient validation. An attacker can
          manipulate the serialized object to control the application's logic or
          even execute code.
        </p>
        <div className="demo-controls">
          <label>
            Serialized Data:
            <textarea
              value={serializedData}
              onChange={(e) => setSerializedData(e.target.value)}
              rows={4}
            />
          </label>
          <button onClick={handleDeserialization} disabled={loading}>
            Deserialize Data
          </button>
        </div>
        <div className="attack-examples">
          <h4>🚨 Try this malicious payload:</h4>
          <code>
            {'{"username":"attacker","role":"admin","isAdmin":true}'}
          </code>
          <p style={{ margin: '0.5rem 0 0 0', color: '#721c24' }}>
            This payload attempts to elevate privileges by setting the 'role' to
            'admin'.
          </p>
        </div>
      </div>

      <div className="demo-section">
        <h2>💿 Demo 2: Unsigned Software Update</h2>
        <p>
          This demo simulates checking for a software update. The server
          responds with a download URL but provides no checksum or digital
          signature. This means an attacker could tamper with the update file,
          and the client would have no way to verify its integrity.
        </p>
        <div className="demo-controls">
          <button onClick={handleUpdateCheck} disabled={loading}>
            Check for Updates
          </button>
        </div>
      </div>

      <div className="demo-section">
        <h2>📂 Demo 3: Insecure File Upload</h2>
        <p>
          This demo showcases an insecure file upload feature. The server does
          not validate the file type, content, or name, allowing an attacker to
          upload malicious files (like a web shell) to the server.
        </p>
        <div className="demo-controls">
          <label>
            File to Upload:
            <input
              type="file"
              onChange={(e) => setFile(e.target.files ? e.target.files[0] : null)}
            />
          </label>
          <button onClick={handleFileUpload} disabled={loading || !file}>
            Upload File
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
            <div
              className="code-example-header"
              onClick={() => setShowCSharpExamples(!showCSharpExamples)}
              style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', marginBottom: '10px' }}
            >
              <h3 style={{ margin: 0 }}>C#/.NET - Data Integrity Protection</h3>
              <span style={{ marginLeft: '10px', fontSize: '14px' }}>
                {showCSharpExamples ? '▼ Hide' : '▶ Show'}
              </span>
            </div>
            {showCSharpExamples && (
            <pre className="code-block">
              {`// Digital signatures and HMAC implementation
public class DataIntegrityService
{
    private readonly string _hmacSecret;
    private readonly RSA _rsa;

    public DataIntegrityService(IConfiguration config)
    {
        _hmacSecret = config["Security:HmacSecret"];
        _rsa = RSA.Create();
        _rsa.ImportRSAPrivateKey(Convert.FromBase64String(config["Security:PrivateKey"]), out _);
    }

    // Create HMAC for data integrity
    public string CreateHmac(string data)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(_hmacSecret));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        return Convert.ToBase64String(hash);
    }

    // Verify HMAC
    public bool VerifyHmac(string data, string signature)
    {
        var expectedSignature = CreateHmac(data);
        return CryptographicOperations.FixedTimeEquals(
            Convert.FromBase64String(signature),
            Convert.FromBase64String(expectedSignature)
        );
    }

    // Digital signature for critical data
    public string SignData(string data)
    {
        var dataBytes = Encoding.UTF8.GetBytes(data);
        var signature = _rsa.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(signature);
    }

    // Verify digital signature
    public bool VerifySignature(string data, string signature)
    {
        var dataBytes = Encoding.UTF8.GetBytes(data);
        var signatureBytes = Convert.FromBase64String(signature);
        return _rsa.VerifyData(dataBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}

// Secure file upload with integrity checks
[ApiController]
public class FileUploadController : ControllerBase
{
    private readonly IFileIntegrityService _integrityService;
    private readonly string[] _allowedExtensions = { ".jpg", ".jpeg", ".png", ".gif" };
    private readonly string[] _allowedMimeTypes = { "image/jpeg", "image/png", "image/gif" };

    [HttpPost("upload")]
    public async Task<IActionResult> UploadFile(IFormFile file)
    {
        if (file == null || file.Length == 0)
            return BadRequest("No file uploaded");

        // Validate file size
        if (file.Length > 10 * 1024 * 1024) // 10MB
            return BadRequest("File too large");

        // Validate file extension
        var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
        if (!_allowedExtensions.Contains(extension))
            return BadRequest("Invalid file type");

        // Validate MIME type
        if (!_allowedMimeTypes.Contains(file.ContentType))
            return BadRequest("Invalid content type");

        // Read file content for integrity check
        using var stream = new MemoryStream();
        await file.CopyToAsync(stream);
        var fileBytes = stream.ToArray();

        // Verify file signature (magic bytes)
        if (!IsValidImageFile(fileBytes))
            return BadRequest("File content doesn't match extension");

        // Calculate file hash
        var fileHash = SHA256.HashData(fileBytes);
        var hashString = Convert.ToBase64String(fileHash);

        // Store file with integrity information
        var result = await _integrityService.StoreFileWithIntegrityAsync(
            file.FileName, fileBytes, hashString);

        return Ok(new { FileId = result.FileId, Hash = hashString });
    }

    private bool IsValidImageFile(byte[] fileBytes)
    {
        if (fileBytes.Length < 4) return false;

        // Check for JPEG signature
        if (fileBytes[0] == 0xFF && fileBytes[1] == 0xD8)
            return true;

        // Check for PNG signature
        if (fileBytes[0] == 0x89 && fileBytes[1] == 0x50 &&
            fileBytes[2] == 0x4E && fileBytes[3] == 0x47)
            return true;

        // Check for GIF signature
        if (fileBytes[0] == 0x47 && fileBytes[1] == 0x49 && fileBytes[2] == 0x46)
            return true;

        return false;
    }
}

// CI/CD deployment integrity verification
public class DeploymentIntegrityChecker
{
    public async Task<bool> VerifyDeploymentPackageAsync(string packagePath)
    {
        try
        {
            // Verify package signature
            var packageBytes = await File.ReadAllBytesAsync(packagePath);
            var signature = await GetPackageSignatureAsync(packagePath + ".sig");

            using var rsa = RSA.Create();
            rsa.ImportRSAPublicKey(GetPublicKey(), out _);

            var isValidSignature = rsa.VerifyData(packageBytes, signature,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            if (!isValidSignature)
            {
                throw new SecurityException("Package signature verification failed");
            }

            // Verify dependencies integrity
            await VerifyDependenciesIntegrityAsync();

            return true;
        }
        catch (Exception ex)
        {
            // Log integrity failure
            Console.WriteLine($"Deployment integrity check failed: {ex.Message}");
            return false;
        }
    }

    private async Task VerifyDependenciesIntegrityAsync()
    {
        var projectFiles = Directory.GetFiles(".", "*.csproj", SearchOption.AllDirectories);

        foreach (var projectFile in projectFiles)
        {
            var projectContent = await File.ReadAllTextAsync(projectFile);
            var doc = XDocument.Parse(projectContent);

            var packageReferences = doc.Descendants("PackageReference");

            foreach (var packageRef in packageReferences)
            {
                var packageName = packageRef.Attribute("Include")?.Value;
                var version = packageRef.Attribute("Version")?.Value;

                if (!string.IsNullOrEmpty(packageName) && !string.IsNullOrEmpty(version))
                {
                    await VerifyPackageIntegrityAsync(packageName, version);
                }
            }
        }
    }
}`}
            </pre>
            )}
          </div>
        </div>

        <div className="remediation-grid">
          <div className="fix-item">
            <h4>1. Digital Signatures</h4>
            <p>Use digital signatures for critical data and deployments</p>
            <code>RSA, ECDSA signatures</code>
          </div>
          <div className="fix-item">
            <h4>2. File Integrity Checks</h4>
            <p>Validate file types and content integrity</p>
            <code>Magic bytes, checksums, hashes</code>
          </div>
          <div className="fix-item">
            <h4>3. Secure CI/CD Pipeline</h4>
            <p>Implement integrity checks in deployment pipeline</p>
            <code>Signed packages, dependency verification</code>
          </div>
          <div className="fix-item">
            <h4>4. Data Validation</h4>
            <p>Validate all data inputs and transformations</p>
            <code>Schema validation, type checking</code>
          </div>
        </div>

        <div className="best-practices">
          <h3>🏆 Best Practices</h3>
          <ul>
            <li>
              <strong>Digital Signatures:</strong> Sign all critical data and
              software packages
            </li>
            <li>
              <strong>Integrity Monitoring:</strong> Continuously monitor data
              and file integrity
            </li>
            <li>
              <strong>Secure Updates:</strong> Use signed updates and verify
              integrity before installation
            </li>
            <li>
              <strong>File Type Validation:</strong> Validate files by content,
              not just extension
            </li>
            <li>
              <strong>Dependency Management:</strong> Use package managers with
              integrity verification
            </li>
            <li>
              <strong>Audit Trails:</strong> Maintain detailed logs of all data
              modifications
            </li>
          </ul>
        </div>
      </div>

      <div className="navigation-section">
        <a href="/web/a09" className="next-button">
          Next: A09 - Logging Failures →
        </a>
      </div>
    </div>
  );
};

export default A08IntegrityFailures;
