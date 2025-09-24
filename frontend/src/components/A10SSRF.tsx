import React, { useState } from "react";
import axios from "axios";
import "./VulnerabilityPage.css";

const A10SSRF: React.FC = () => {
  const [url, setUrl] = useState("http://httpbin.org/json");
  const [scanHost, setScanHost] = useState("localhost");
  const [scanPort, setScanPort] = useState("22");
  const [webhookUrl, setWebhookUrl] = useState("http://localhost:3001/api/a09/logs");
  const [webhookData, setWebhookData] = useState('{"event":"test"}');
  const [imageUrl, setImageUrl] = useState('https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png');
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [showCSharpExamples, setShowCSharpExamples] = useState(false);

  const testSSRF = async () => {
    setLoading(true);
    try {
      const res = await axios.post("http://localhost:3001/api/a10/fetch-url", {
        url: url,
      });
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const handlePortScan = async () => {
    setLoading(true);
    try {
      const res = await axios.get(
        `http://localhost:3001/api/a10/check-service?host=${scanHost}&port=${scanPort}`
      );
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const handleProcessImage = async () => {
    setLoading(true);
    try {
      const res = await axios.post("http://localhost:3001/api/a10/process-image", {
        image_url: imageUrl,
      });
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const handleWebhook = async () => {
    setLoading(true);
    try {
      const res = await axios.post("http://localhost:3001/api/a10/webhook", {
        callback_url: webhookUrl,
        data: JSON.parse(webhookData),
      });
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  return (
    <div className="vulnerability-page">
      <div className="vuln-header">
        <h1>A10 - Server-Side Request Forgery (SSRF)</h1>
        <div className="vulnerability-badge">OWASP #10</div>
      </div>

      <div className="vuln-description">
        <p>
          SSRF flaws occur whenever a web application fetches a remote resource
          without validating the user-supplied URL. This allows attackers to
          access internal resources or external systems.
        </p>
      </div>

      <div className="demo-section">
        <h2>🌐 Demo 1: Unvalidated URL Fetching</h2>
        <p>
          This demo shows a feature where the server fetches content from a
          user-provided URL. Because the server doesn't validate the URL, an
          attacker can force it to make requests to internal services or local
          files.
        </p>
        <div className="demo-controls">
          <label>
            URL to fetch:
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="http://httpbin.org/json"
              style={{ width: "400px" }}
            />
          </label>
          <button onClick={testSSRF} disabled={loading}>
            Fetch URL
          </button>
        </div>

        <div className="attack-examples">
          <h4>🚨 Try these SSRF attacks:</h4>
          <code>http://localhost:22</code>
          <code>http://127.0.0.1:3000</code>
          <code>http://169.254.169.254/latest/meta-data/</code>
          <code>file:///etc/passwd</code>
        </div>

        <div className="vulnerability-explanation">
          <h4>🚨 Why this is dangerous:</h4>
          <ul>
            <li>Access to internal services and APIs</li>
            <li>Port scanning of internal networks</li>
            <li>Cloud metadata service access</li>
            <li>File system access via file:// protocol</li>
            <li>Bypass of firewalls and network restrictions</li>
          </ul>
        </div>
      </div>

      <div className="demo-section">
        <h2>📡 Demo 2: Internal Port Scanning</h2>
        <p>
          SSRF can be used to scan the internal network from the perspective of
          the server. An attacker can use this to discover running services on
          localhost or other internal servers.
        </p>
        <div className="demo-controls">
          <label>
            Host to Scan:
            <input
              type="text"
              value={scanHost}
              onChange={(e) => setScanHost(e.target.value)}
            />
          </label>
          <label>
            Port to Scan:
            <input
              type="text"
              value={scanPort}
              onChange={(e) => setScanPort(e.target.value)}
            />
          </label>
          <button onClick={handlePortScan} disabled={loading}>
            Scan Port
          </button>
        </div>
      </div>

      <div className="demo-section">
        <h2>🎣 Demo 3: Blind SSRF via Webhook</h2>
        <p>
          This demo simulates a blind SSRF vulnerability in a webhook feature.
          The server sends a POST request to the URL you provide, but you don't
          see the response. This can be used to trigger actions on internal
          systems.
        </p>
        <div className="attack-examples">
          <h4>🚨 Try this blind SSRF attack:</h4>
          <p style={{ margin: '0.5rem 0 0 0', color: '#721c24' }}>
            Set the Callback URL to an internal endpoint like <code>http://localhost:3001/api/a01/update-role</code> and the data to <code>{'{"userId": 1, "role": "admin"}'}</code>. Even though you won't see a response here, the action might have succeeded silently in the background.
          </p>
        </div>
        <div className="demo-controls">
          <label>
            Callback URL:
            <input
              type="text"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              style={{ width: "400px" }}
            />
          </label>
          <label>
            JSON Data to Send:
            <textarea
              value={webhookData}
              onChange={(e) => setWebhookData(e.target.value)}
              rows={3}
            />
          </label>
          <button onClick={handleWebhook} disabled={loading}>
            Trigger Webhook
          </button>
        </div>
      </div>

      <div className="demo-section">
        <h2>🖼️ Demo 4: SSRF via Image Processing</h2>
        <p>
          This demo simulates a feature that fetches an image from a URL for processing. An attacker can abuse this to make the server request resources from internal services, exposing information about the internal network.
        </p>
        <div className="demo-controls">
          <label>
            Image URL to Process:
            <input
              type="text"
              value={imageUrl}
              onChange={(e) => setImageUrl(e.target.value)}
              style={{ width: "400px" }}
            />
          </label>
          <button onClick={handleProcessImage} disabled={loading}>
            Process Image
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
              <h3 style={{ margin: 0 }}>C#/.NET - Secure HTTP Client</h3>
              <span style={{ marginLeft: '10px', fontSize: '14px' }}>
                {showCSharpExamples ? '▼ Hide' : '▶ Show'}
              </span>
            </div>
            {showCSharpExamples && (
              <pre className="code-block">
                {`// Secure URL validation and HTTP client
using System.Net;
using System.Text.RegularExpressions;

public class SecureHttpService
{
    private static readonly HashSet<string> AllowedDomains = new()
    {
        "api.example.com",
        "safe-service.com",
        "trusted-partner.org"
    };

    private static readonly HashSet<string> BlockedHosts = new()
    {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "169.254.169.254",
        "::1",
        "metadata.google.internal"
    };

    private readonly HttpClient _httpClient;

    public SecureHttpService(HttpClient httpClient)
    {
        _httpClient = httpClient;
        _httpClient.Timeout = TimeSpan.FromSeconds(5);
    }

    public async Task<SecureFetchResult> FetchUrlAsync(string urlString)
    {
        var validatedUri = ValidateUrl(urlString);

        try
        {
            var response = await _httpClient.GetAsync(validatedUri);
            var content = await response.Content.ReadAsStringAsync();

            return new SecureFetchResult
            {
                StatusCode = response.StatusCode,
                Content = content,
                Headers = response.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value))
            };
        }
        catch (HttpRequestException ex)
        {
            throw new SecurityException($"Request failed: {ex.Message}");
        }
    }

    private Uri ValidateUrl(string urlString)
    {
        if (!Uri.TryCreate(urlString, UriKind.Absolute, out var uri))
        {
            throw new ArgumentException("Invalid URL format");
        }

        // Only allow HTTP/HTTPS
        if (uri.Scheme != "http" && uri.Scheme != "https")
        {
            throw new SecurityException("Only HTTP/HTTPS protocols allowed");
        }

        // Check allowlist
        if (!AllowedDomains.Contains(uri.Host))
        {
            throw new SecurityException("Domain not in allowlist");
        }

        // Check blocklist
        if (BlockedHosts.Contains(uri.Host))
        {
            throw new SecurityException("Access to internal resources blocked");
        }

        // Check for private IPs
        if (IsPrivateIP(uri.Host))
        {
            throw new SecurityException("Access to private IPs blocked");
        }

        return uri;
    }

    private bool IsPrivateIP(string hostname)
    {
        if (!IPAddress.TryParse(hostname, out var ipAddress))
            return false;

        var bytes = ipAddress.GetAddressBytes();

        // Check for private IP ranges
        return bytes[0] == 10 ||
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
               (bytes[0] == 192 && bytes[1] == 168);
    }
}

public class SecureFetchResult
{
    public HttpStatusCode StatusCode { get; set; }
    public string Content { get; set; }
    public Dictionary<string, string> Headers { get; set; }
}

// Controller with validation
[ApiController]
[Route("api/[controller]")]
public class SecureFetchController : ControllerBase
{
    private readonly SecureHttpService _httpService;

    public SecureFetchController(SecureHttpService httpService)
    {
        _httpService = httpService;
    }

    [HttpPost("fetch-url")]
    public async Task<IActionResult> FetchUrl([FromBody] FetchUrlRequest request)
    {
        try
        {
            var result = await _httpService.FetchUrlAsync(request.Url);
            return Ok(result);
        }
        catch (SecurityException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }
}

public class FetchUrlRequest
{
    public string Url { get; set; }
}`}
              </pre>
            )}
          </div>
        </div>

        <div className="remediation-grid">
          <div className="fix-item">
            <h4>1. URL Validation</h4>
            <p>Validate and sanitize all URLs before making requests</p>
            <code>validateURL(userInput)</code>
          </div>
          <div className="fix-item">
            <h4>2. Domain Allowlisting</h4>
            <p>Maintain a strict allowlist of permitted domains</p>
            <code>ALLOWED_DOMAINS.includes(hostname)</code>
          </div>
          <div className="fix-item">
            <h4>3. Block Private Networks</h4>
            <p>Prevent access to internal IPs and localhost</p>
            <code>isPrivateIP(hostname)</code>
          </div>
          <div className="fix-item">
            <h4>4. Network Segmentation</h4>
            <p>Isolate application servers from internal networks</p>
            <code>Use dedicated network zones</code>
          </div>
        </div>

        <div className="best-practices">
          <h3>🏆 Best Practices</h3>
          <ul>
            <li>
              <strong>Default Deny:</strong> Block all URLs by default, only
              allow explicitly approved domains
            </li>
            <li>
              <strong>Protocol Restrictions:</strong> Only allow HTTP/HTTPS,
              block file://, ftp://, etc.
            </li>
            <li>
              <strong>IP Blocking:</strong> Block all private IP ranges and
              localhost variations
            </li>
            <li>
              <strong>Network Segmentation:</strong> Isolate application servers
              from internal networks
            </li>
            <li>
              <strong>Response Validation:</strong> Validate and sanitize
              responses from external services
            </li>
            <li>
              <strong>Timeout Controls:</strong> Set appropriate timeouts to
              prevent resource exhaustion
            </li>
          </ul>
        </div>
      </div>

      <div className="navigation-section">
        <a href="/" className="next-button">
          Presentation Complete - Return Home →
        </a>
      </div>
    </div>
  );
};

export default A10SSRF;
