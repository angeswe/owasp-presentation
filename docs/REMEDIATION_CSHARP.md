# OWASP Top 10 Remediation Examples - C#/.NET

This document provides secure coding examples in C# to fix the vulnerabilities demonstrated in the application.

## A01 - Broken Access Control

### ❌ Vulnerable Code
```csharp
// Direct object reference without authorization
[HttpGet("{id}")]
public async Task<ActionResult<User>> GetUser(int id)
{
    var user = await _context.Users.FindAsync(id);
    return Ok(user);
}

// Admin endpoint without authentication
[HttpGet("admin/users")]
public async Task<ActionResult<List<User>>> GetAllUsers()
{
    var users = await _context.Users.ToListAsync();
    return Ok(users);
}
```

### ✅ Secure Implementation
```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Security.Claims;

// Custom authorization policies
public class AuthorizationPolicies
{
    public const string AdminOnly = "AdminOnly";
    public const string UserOrAdmin = "UserOrAdmin";
}

// Startup.cs - Configure authorization
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthorization(options =>
    {
        options.AddPolicy(AuthorizationPolicies.AdminOnly, policy =>
            policy.RequireRole("Admin"));

        options.AddPolicy(AuthorizationPolicies.UserOrAdmin, policy =>
            policy.RequireAssertion(context =>
                context.User.IsInRole("Admin") ||
                context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ==
                context.Resource?.ToString()));
    });

    services.AddScoped<IAuthorizationHandler, ResourceOwnerAuthorizationHandler>();
}

// Resource-based authorization handler
public class ResourceOwnerAuthorizationHandler : AuthorizationHandler<ResourceOwnerRequirement, UserResource>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ResourceOwnerRequirement requirement,
        UserResource resource)
    {
        var currentUserId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var isAdmin = context.User.IsInRole("Admin");

        if (isAdmin || resource.OwnerId.ToString() == currentUserId)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

// Secure controller with proper authorization
[ApiController]
[Route("api/[controller]")]
[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
public class UsersController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly IAuthorizationService _authorizationService;
    private readonly ILogger<UsersController> _logger;

    public UsersController(
        ApplicationDbContext context,
        IAuthorizationService authorizationService,
        ILogger<UsersController> logger)
    {
        _context = context;
        _authorizationService = authorizationService;
        _logger = logger;
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<UserDto>> GetUser(int id)
    {
        var user = await _context.Users
            .Where(u => u.Id == id)
            .Select(u => new UserDto
            {
                Id = u.Id,
                Username = u.Username,
                Email = u.Email,
                Role = u.Role
                // Exclude sensitive fields like Password, ApiKey
            })
            .FirstOrDefaultAsync();

        if (user == null)
        {
            return NotFound();
        }

        // Check authorization
        var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var isAdmin = User.IsInRole("Admin");

        if (!isAdmin && currentUserId != id.ToString())
        {
            _logger.LogWarning("Unauthorized access attempt to user {UserId} by user {CurrentUserId}",
                id, currentUserId);
            return Forbid();
        }

        return Ok(user);
    }

    [HttpGet("admin/users")]
    [Authorize(Policy = AuthorizationPolicies.AdminOnly)]
    public async Task<ActionResult<List<UserDto>>> GetAllUsers(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20)
    {
        // Validate pagination parameters
        if (page < 1 || pageSize < 1 || pageSize > 100)
        {
            return BadRequest("Invalid pagination parameters");
        }

        var users = await _context.Users
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(u => new UserDto
            {
                Id = u.Id,
                Username = u.Username,
                Email = u.Email,
                Role = u.Role,
                CreatedAt = u.CreatedAt,
                LastLoginAt = u.LastLoginAt
            })
            .ToListAsync();

        var totalCount = await _context.Users.CountAsync();

        var response = new PaginatedResponse<UserDto>
        {
            Data = users,
            Page = page,
            PageSize = pageSize,
            TotalCount = totalCount,
            TotalPages = (int)Math.Ceiling((double)totalCount / pageSize)
        };

        return Ok(response);
    }

    [HttpPut("{id}/role")]
    [Authorize(Policy = AuthorizationPolicies.AdminOnly)]
    public async Task<ActionResult> UpdateUserRole(int id, [FromBody] UpdateRoleRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = await _context.Users.FindAsync(id);
        if (user == null)
        {
            return NotFound();
        }

        // Prevent admin from removing their own admin role
        var currentUserId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value!);
        if (currentUserId == id && request.Role != "Admin")
        {
            return BadRequest("Cannot remove your own admin privileges");
        }

        user.Role = request.Role;
        user.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        _logger.LogInformation("User role updated: User {UserId} role changed to {Role} by {AdminId}",
            id, request.Role, currentUserId);

        return NoContent();
    }
}

// Data Transfer Objects (DTOs) to control data exposure
public class UserDto
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime? LastLoginAt { get; set; }
}

public class UpdateRoleRequest
{
    [Required]
    [AllowedValues("Admin", "User", "Moderator")]
    public string Role { get; set; } = string.Empty;
}
```

## A02 - Cryptographic Failures

### ❌ Vulnerable Code
```csharp
// Plain text password storage
public class User
{
    public string Password { get; set; } // Plain text
}

// Weak encryption
public string EncryptData(string data)
{
    var key = "weakkey123";
    // Using weak encryption
}
```

### ✅ Secure Implementation
```csharp
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.DataProtection;

// Secure password handling service
public interface IPasswordService
{
    string HashPassword(string password);
    bool VerifyPassword(string password, string hash);
    PasswordStrengthResult CheckPasswordStrength(string password);
}

public class PasswordService : IPasswordService
{
    private const int SaltSize = 32;
    private const int HashSize = 32;
    private const int Iterations = 100000; // PBKDF2 iterations

    public string HashPassword(string password)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be null or empty", nameof(password));

        // Generate salt
        using var rng = RandomNumberGenerator.Create();
        var salt = new byte[SaltSize];
        rng.GetBytes(salt);

        // Hash password
        var hash = KeyDerivation.Pbkdf2(
            password: password,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: Iterations,
            numBytesRequested: HashSize);

        // Combine salt and hash
        var result = new byte[SaltSize + HashSize];
        Array.Copy(salt, 0, result, 0, SaltSize);
        Array.Copy(hash, 0, result, SaltSize, HashSize);

        return Convert.ToBase64String(result);
    }

    public bool VerifyPassword(string password, string hash)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hash))
            return false;

        try
        {
            var hashBytes = Convert.FromBase64String(hash);

            if (hashBytes.Length != SaltSize + HashSize)
                return false;

            // Extract salt
            var salt = new byte[SaltSize];
            Array.Copy(hashBytes, 0, salt, 0, SaltSize);

            // Hash provided password
            var computedHash = KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: Iterations,
                numBytesRequested: HashSize);

            // Compare hashes
            var storedHash = new byte[HashSize];
            Array.Copy(hashBytes, SaltSize, storedHash, 0, HashSize);

            return CryptographicOperations.FixedTimeEquals(computedHash, storedHash);
        }
        catch
        {
            return false;
        }
    }

    public PasswordStrengthResult CheckPasswordStrength(string password)
    {
        var result = new PasswordStrengthResult();

        if (string.IsNullOrEmpty(password))
        {
            result.Errors.Add("Password is required");
            return result;
        }

        if (password.Length < 12)
            result.Errors.Add("Password must be at least 12 characters long");

        if (!password.Any(char.IsUpper))
            result.Errors.Add("Password must contain uppercase letters");

        if (!password.Any(char.IsLower))
            result.Errors.Add("Password must contain lowercase letters");

        if (!password.Any(char.IsDigit))
            result.Errors.Add("Password must contain numbers");

        if (!password.Any(c => "!@#$%^&*(),.?\":{}|<>".Contains(c)))
            result.Errors.Add("Password must contain special characters");

        // Check for common patterns
        if (HasRepeatingCharacters(password, 3))
            result.Errors.Add("Password cannot have more than 2 consecutive identical characters");

        if (IsCommonPassword(password))
            result.Errors.Add("Password is too common");

        result.IsValid = !result.Errors.Any();
        return result;
    }

    private static bool HasRepeatingCharacters(string password, int maxRepeats)
    {
        for (int i = 0; i <= password.Length - maxRepeats; i++)
        {
            if (password.Skip(i).Take(maxRepeats).All(c => c == password[i]))
                return true;
        }
        return false;
    }

    private static bool IsCommonPassword(string password)
    {
        var commonPasswords = new HashSet<string>
        {
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "dragon", "123456789"
        };

        return commonPasswords.Contains(password.ToLower());
    }
}

// Secure encryption service using Data Protection API
public interface IEncryptionService
{
    string Encrypt(string plainText);
    string Decrypt(string cipherText);
    byte[] EncryptBytes(byte[] plainData);
    byte[] DecryptBytes(byte[] cipherData);
}

public class EncryptionService : IEncryptionService
{
    private readonly IDataProtector _protector;

    public EncryptionService(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("MyApp.Encryption.v1");
    }

    public string Encrypt(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
            throw new ArgumentException("Plain text cannot be null or empty", nameof(plainText));

        return _protector.Protect(plainText);
    }

    public string Decrypt(string cipherText)
    {
        if (string.IsNullOrEmpty(cipherText))
            throw new ArgumentException("Cipher text cannot be null or empty", nameof(cipherText));

        try
        {
            return _protector.Unprotect(cipherText);
        }
        catch (CryptographicException)
        {
            throw new InvalidOperationException("Failed to decrypt data");
        }
    }

    public byte[] EncryptBytes(byte[] plainData)
    {
        if (plainData == null || plainData.Length == 0)
            throw new ArgumentException("Plain data cannot be null or empty", nameof(plainData));

        return _protector.Protect(plainData);
    }

    public byte[] DecryptBytes(byte[] cipherData)
    {
        if (cipherData == null || cipherData.Length == 0)
            throw new ArgumentException("Cipher data cannot be null or empty", nameof(cipherData));

        try
        {
            return _protector.Unprotect(cipherData);
        }
        catch (CryptographicException)
        {
            throw new InvalidOperationException("Failed to decrypt data");
        }
    }
}

// Secure token generation
public interface ITokenService
{
    string GenerateSecureToken(int length = 32);
    string GenerateJwtToken(ClaimsIdentity identity, TimeSpan? expiry = null);
    ClaimsPrincipal ValidateJwtToken(string token);
}

public class TokenService : ITokenService
{
    private readonly IConfiguration _configuration;
    private readonly byte[] _jwtKey;

    public TokenService(IConfiguration configuration)
    {
        _configuration = configuration;
        var keyString = _configuration["Jwt:SecretKey"] ??
            throw new InvalidOperationException("JWT secret key not configured");

        if (keyString.Length < 32)
            throw new InvalidOperationException("JWT secret key must be at least 32 characters");

        _jwtKey = Encoding.UTF8.GetBytes(keyString);
    }

    public string GenerateSecureToken(int length = 32)
    {
        using var rng = RandomNumberGenerator.Create();
        var tokenBytes = new byte[length];
        rng.GetBytes(tokenBytes);
        return Convert.ToBase64String(tokenBytes);
    }

    public string GenerateJwtToken(ClaimsIdentity identity, TimeSpan? expiry = null)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var expiration = DateTime.UtcNow.Add(expiry ?? TimeSpan.FromHours(1));

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = identity,
            Expires = expiration,
            Issuer = _configuration["Jwt:Issuer"],
            Audience = _configuration["Jwt:Audience"],
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(_jwtKey),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    public ClaimsPrincipal ValidateJwtToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(_jwtKey),
            ValidateIssuer = true,
            ValidIssuer = _configuration["Jwt:Issuer"],
            ValidateAudience = true,
            ValidAudience = _configuration["Jwt:Audience"],
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };

        try
        {
            var principal = tokenHandler.ValidateToken(token, validationParameters, out _);
            return principal;
        }
        catch (SecurityTokenException)
        {
            throw new UnauthorizedAccessException("Invalid token");
        }
    }
}

// Startup.cs configuration
public void ConfigureServices(IServiceCollection services)
{
    // Data Protection
    services.AddDataProtection()
        .PersistKeysToFileSystem(new DirectoryInfo("/app/keys"))
        .SetDefaultKeyLifetime(TimeSpan.FromDays(90))
        .SetApplicationName("MySecureApp");

    // Register services
    services.AddScoped<IPasswordService, PasswordService>();
    services.AddScoped<IEncryptionService, EncryptionService>();
    services.AddScoped<ITokenService, TokenService>();
}
```

## A03 - Injection

### ❌ Vulnerable Code
```csharp
// SQL Injection
public async Task<User> GetUserByUsername(string username)
{
    var sql = $"SELECT * FROM Users WHERE Username = '{username}'";
    return await _context.Users.FromSqlRaw(sql).FirstOrDefaultAsync();
}

// Command Injection
public string ExecuteCommand(string command)
{
    var process = Process.Start("cmd.exe", $"/c {command}");
    // Vulnerable to command injection
}
```

### ✅ Secure Implementation
```csharp
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

// Secure data access with parameterized queries
public class UserRepository : IUserRepository
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<UserRepository> _logger;

    public UserRepository(ApplicationDbContext context, ILogger<UserRepository> logger)
    {
        _context = context;
        _logger = logger;
    }

    // Parameterized query using LINQ
    public async Task<User?> GetUserByUsernameAsync(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return null;

        // Input validation
        if (!IsValidUsername(username))
            throw new ArgumentException("Invalid username format", nameof(username));

        return await _context.Users
            .Where(u => u.Username == username)
            .FirstOrDefaultAsync();
    }

    // Parameterized raw SQL (when needed)
    public async Task<List<User>> SearchUsersAsync(string searchTerm)
    {
        if (string.IsNullOrWhiteSpace(searchTerm))
            return new List<User>();

        // Sanitize input
        searchTerm = SanitizeSearchTerm(searchTerm);

        return await _context.Users
            .FromSqlRaw("SELECT * FROM Users WHERE Username LIKE {0} OR Email LIKE {0}",
                $"%{searchTerm}%")
            .ToListAsync();
    }

    // Secure dynamic queries using Expression Trees
    public async Task<List<User>> GetUsersWithFiltersAsync(UserFilterDto filters)
    {
        var query = _context.Users.AsQueryable();

        if (!string.IsNullOrEmpty(filters.Role))
        {
            if (!IsValidRole(filters.Role))
                throw new ArgumentException("Invalid role", nameof(filters.Role));

            query = query.Where(u => u.Role == filters.Role);
        }

        if (!string.IsNullOrEmpty(filters.SearchTerm))
        {
            var sanitizedTerm = SanitizeSearchTerm(filters.SearchTerm);
            query = query.Where(u => u.Username.Contains(sanitizedTerm) ||
                                   u.Email.Contains(sanitizedTerm));
        }

        if (filters.CreatedAfter.HasValue)
        {
            query = query.Where(u => u.CreatedAt >= filters.CreatedAfter.Value);
        }

        return await query
            .OrderBy(u => u.Username)
            .Take(100) // Limit results
            .ToListAsync();
    }

    private static bool IsValidUsername(string username)
    {
        // Only allow alphanumeric characters, underscores, and hyphens
        return Regex.IsMatch(username, @"^[a-zA-Z0-9_-]{3,30}$");
    }

    private static bool IsValidRole(string role)
    {
        var validRoles = new[] { "Admin", "User", "Moderator" };
        return validRoles.Contains(role);
    }

    private static string SanitizeSearchTerm(string searchTerm)
    {
        // Remove potential SQL injection characters
        return Regex.Replace(searchTerm, @"[';\""%]", "");
    }
}

// Input validation with Data Annotations
public class UserFilterDto
{
    [StringLength(50)]
    [RegularExpression(@"^[a-zA-Z0-9\s]*$", ErrorMessage = "Invalid characters in search term")]
    public string? SearchTerm { get; set; }

    [AllowedValues("Admin", "User", "Moderator")]
    public string? Role { get; set; }

    public DateTime? CreatedAfter { get; set; }
}

// Secure command execution (when absolutely necessary)
public interface ISecureCommandService
{
    Task<string> ExecuteAllowedCommandAsync(string command, string[] arguments);
}

public class SecureCommandService : ISecureCommandService
{
    private readonly ILogger<SecureCommandService> _logger;
    private readonly HashSet<string> _allowedCommands;

    public SecureCommandService(ILogger<SecureCommandService> logger)
    {
        _logger = logger;

        // Whitelist of allowed commands
        _allowedCommands = new HashSet<string>
        {
            "ping",
            "nslookup",
            "ipconfig"
        };
    }

    public async Task<string> ExecuteAllowedCommandAsync(string command, string[] arguments)
    {
        // Validate command is in whitelist
        if (!_allowedCommands.Contains(command.ToLower()))
        {
            throw new UnauthorizedAccessException($"Command '{command}' is not allowed");
        }

        // Validate arguments
        foreach (var arg in arguments)
        {
            if (!IsValidArgument(arg))
            {
                throw new ArgumentException($"Invalid argument: {arg}");
            }
        }

        try
        {
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = command,
                Arguments = string.Join(" ", arguments.Select(EscapeArgument)),
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            // Set timeout
            var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            process.Start();

            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();

            await process.WaitForExitAsync(cts.Token);

            var output = await outputTask;
            var error = await errorTask;

            if (process.ExitCode != 0)
            {
                _logger.LogWarning("Command failed with exit code {ExitCode}: {Error}",
                    process.ExitCode, error);
                throw new InvalidOperationException($"Command failed: {error}");
            }

            return output;
        }
        catch (OperationCanceledException)
        {
            throw new TimeoutException("Command execution timed out");
        }
    }

    private static bool IsValidArgument(string argument)
    {
        // Allow only safe characters
        return Regex.IsMatch(argument, @"^[a-zA-Z0-9._-]+$");
    }

    private static string EscapeArgument(string argument)
    {
        // Escape argument for shell safety
        return $"\"{argument.Replace("\"", "\\\"")}\"";
    }
}

// NoSQL injection prevention (for MongoDB)
public class MongoUserRepository
{
    private readonly IMongoCollection<User> _users;

    public MongoUserRepository(IMongoDatabase database)
    {
        _users = database.GetCollection<User>("users");
    }

    public async Task<User> GetUserByUsernameAsync(string username)
    {
        // Ensure username is string to prevent object injection
        if (username is not string usernameStr)
            throw new ArgumentException("Username must be a string");

        var filter = Builders<User>.Filter.Eq(u => u.Username, usernameStr);
        return await _users.Find(filter).FirstOrDefaultAsync();
    }

    public async Task<List<User>> SearchUsersAsync(SearchCriteria criteria)
    {
        var filterBuilder = Builders<User>.Filter;
        var filters = new List<FilterDefinition<User>>();

        // Type-safe filter building
        if (!string.IsNullOrEmpty(criteria.Username))
        {
            filters.Add(filterBuilder.Regex(u => u.Username,
                new BsonRegularExpression(Regex.Escape(criteria.Username), "i")));
        }

        if (!string.IsNullOrEmpty(criteria.Role))
        {
            if (!IsValidRole(criteria.Role))
                throw new ArgumentException("Invalid role");

            filters.Add(filterBuilder.Eq(u => u.Role, criteria.Role));
        }

        var combinedFilter = filters.Any()
            ? filterBuilder.And(filters)
            : filterBuilder.Empty;

        return await _users.Find(combinedFilter)
            .Limit(100)
            .ToListAsync();
    }

    private static bool IsValidRole(string role)
    {
        var validRoles = new[] { "Admin", "User", "Moderator" };
        return validRoles.Contains(role);
    }
}

// Controller with input validation
[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly IUserRepository _userRepository;
    private readonly IValidator<UserSearchRequest> _validator;

    public UsersController(
        IUserRepository userRepository,
        IValidator<UserSearchRequest> validator)
    {
        _userRepository = userRepository;
        _validator = validator;
    }

    [HttpGet("search")]
    public async Task<ActionResult<List<UserDto>>> SearchUsers(
        [FromQuery] UserSearchRequest request)
    {
        // Validate input
        var validationResult = await _validator.ValidateAsync(request);
        if (!validationResult.IsValid)
        {
            return BadRequest(validationResult.Errors);
        }

        try
        {
            var filters = new UserFilterDto
            {
                SearchTerm = request.SearchTerm,
                Role = request.Role,
                CreatedAfter = request.CreatedAfter
            };

            var users = await _userRepository.GetUsersWithFiltersAsync(filters);

            var userDtos = users.Select(u => new UserDto
            {
                Id = u.Id,
                Username = u.Username,
                Email = u.Email,
                Role = u.Role
            }).ToList();

            return Ok(userDtos);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
    }
}

// FluentValidation for input validation
public class UserSearchRequestValidator : AbstractValidator<UserSearchRequest>
{
    public UserSearchRequestValidator()
    {
        RuleFor(x => x.SearchTerm)
            .MaximumLength(50)
            .Matches(@"^[a-zA-Z0-9\s]*$")
            .When(x => !string.IsNullOrEmpty(x.SearchTerm))
            .WithMessage("Search term contains invalid characters");

        RuleFor(x => x.Role)
            .Must(BeValidRole)
            .When(x => !string.IsNullOrEmpty(x.Role))
            .WithMessage("Invalid role specified");
    }

    private static bool BeValidRole(string? role)
    {
        if (string.IsNullOrEmpty(role)) return true;
        var validRoles = new[] { "Admin", "User", "Moderator" };
        return validRoles.Contains(role);
    }
}
```

## A04 - Insecure Design

### ❌ Vulnerable Code
```csharp
// No rate limiting
[HttpPost("password-reset")]
public async Task<IActionResult> ResetPassword(string email)
{
    await _emailService.SendPasswordResetEmail(email);
    return Ok("Reset email sent");
}

// Business logic flaw
[HttpPost("transfer")]
public async Task<IActionResult> TransferMoney(decimal amount, int toAccount)
{
    await _bankService.Transfer(User.Identity.Name, toAccount, amount);
    return Ok();
}
```

### ✅ Secure Implementation
```csharp
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;

// Rate limiting configuration
public void ConfigureServices(IServiceCollection services)
{
    services.AddRateLimiter(options =>
    {
        options.AddFixedWindowLimiter("PasswordReset", limiterOptions =>
        {
            limiterOptions.PermitLimit = 3;
            limiterOptions.Window = TimeSpan.FromMinutes(15);
            limiterOptions.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
            limiterOptions.QueueLimit = 0;
        });

        options.AddSlidingWindowLimiter("Transfer", limiterOptions =>
        {
            limiterOptions.PermitLimit = 10;
            limiterOptions.Window = TimeSpan.FromMinutes(1);
            limiterOptions.SegmentsPerWindow = 6;
        });
    });

    services.AddScoped<IBusinessRuleService, BusinessRuleService>();
    services.AddScoped<IPasswordResetService, PasswordResetService>();
    services.AddScoped<ITransferService, TransferService>();
}

// Secure password reset service
public interface IPasswordResetService
{
    Task<PasswordResetResult> InitiateResetAsync(string email, string clientIP);
    Task<PasswordResetResult> CompleteResetAsync(string token, string newPassword);
}

public class PasswordResetService : IPasswordResetService
{
    private readonly ApplicationDbContext _context;
    private readonly IEmailService _emailService;
    private readonly IPasswordService _passwordService;
    private readonly ILogger<PasswordResetService> _logger;
    private readonly ICaptchaService _captchaService;

    public PasswordResetService(
        ApplicationDbContext context,
        IEmailService emailService,
        IPasswordService passwordService,
        ILogger<PasswordResetService> logger,
        ICaptchaService captchaService)
    {
        _context = context;
        _emailService = emailService;
        _passwordService = passwordService;
        _logger = logger;
        _captchaService = captchaService;
    }

    public async Task<PasswordResetResult> InitiateResetAsync(string email, string clientIP)
    {
        if (string.IsNullOrEmpty(email) || !IsValidEmail(email))
        {
            return PasswordResetResult.Invalid("Invalid email address");
        }

        // Rate limiting check
        var recentAttempts = await _context.PasswordResetAttempts
            .Where(a => a.ClientIP == clientIP && a.CreatedAt > DateTime.UtcNow.AddMinutes(-15))
            .CountAsync();

        if (recentAttempts >= 3)
        {
            _logger.LogWarning("Too many password reset attempts from IP: {IP}", clientIP);
            return PasswordResetResult.RateLimited();
        }

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);

        // Always log attempt
        await _context.PasswordResetAttempts.AddAsync(new PasswordResetAttempt
        {
            Email = email,
            ClientIP = clientIP,
            CreatedAt = DateTime.UtcNow,
            UserExists = user != null
        });

        if (user != null)
        {
            // Generate secure token
            using var rng = RandomNumberGenerator.Create();
            var tokenBytes = new byte[32];
            rng.GetBytes(tokenBytes);
            var token = Convert.ToBase64String(tokenBytes);

            var hashedToken = SHA256.HashData(Encoding.UTF8.GetBytes(token));

            // Store reset request
            await _context.PasswordResets.AddAsync(new PasswordReset
            {
                UserId = user.Id,
                TokenHash = Convert.ToBase64String(hashedToken),
                ExpiresAt = DateTime.UtcNow.AddMinutes(10),
                IsUsed = false,
                ClientIP = clientIP
            });

            await _context.SaveChangesAsync();

            // Send email with token
            await _emailService.SendPasswordResetEmailAsync(email, token);

            _logger.LogInformation("Password reset initiated for user: {UserId}", user.Id);
        }

        await _context.SaveChangesAsync();

        // Always return same response to prevent email enumeration
        return PasswordResetResult.Success("If an account exists, a reset email has been sent");
    }

    public async Task<PasswordResetResult> CompleteResetAsync(string token, string newPassword)
    {
        if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(newPassword))
        {
            return PasswordResetResult.Invalid("Invalid token or password");
        }

        // Validate password strength
        var passwordValidation = _passwordService.CheckPasswordStrength(newPassword);
        if (!passwordValidation.IsValid)
        {
            return PasswordResetResult.Invalid(string.Join(", ", passwordValidation.Errors));
        }

        var hashedToken = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        var hashedTokenString = Convert.ToBase64String(hashedToken);

        var resetRequest = await _context.PasswordResets
            .Include(r => r.User)
            .FirstOrDefaultAsync(r => r.TokenHash == hashedTokenString &&
                                    !r.IsUsed &&
                                    r.ExpiresAt > DateTime.UtcNow);

        if (resetRequest == null)
        {
            return PasswordResetResult.Invalid("Invalid or expired token");
        }

        // Update password
        resetRequest.User.Password = _passwordService.HashPassword(newPassword);
        resetRequest.User.UpdatedAt = DateTime.UtcNow;
        resetRequest.IsUsed = true;
        resetRequest.UsedAt = DateTime.UtcNow;

        // Invalidate all user sessions
        await InvalidateAllUserSessionsAsync(resetRequest.UserId);

        await _context.SaveChangesAsync();

        _logger.LogInformation("Password reset completed for user: {UserId}", resetRequest.UserId);

        return PasswordResetResult.Success("Password reset successfully");
    }

    private static bool IsValidEmail(string email)
    {
        try
        {
            var addr = new System.Net.Mail.MailAddress(email);
            return addr.Address == email;
        }
        catch
        {
            return false;
        }
    }

    private async Task InvalidateAllUserSessionsAsync(int userId)
    {
        // Implementation to invalidate all active sessions for the user
        var sessions = await _context.UserSessions
            .Where(s => s.UserId == userId && s.IsActive)
            .ToListAsync();

        foreach (var session in sessions)
        {
            session.IsActive = false;
            session.InvalidatedAt = DateTime.UtcNow;
        }
    }
}

// Secure transfer service with business rules
public interface ITransferService
{
    Task<TransferResult> TransferMoneyAsync(int fromUserId, TransferRequest request);
}

public class TransferService : ITransferService
{
    private readonly ApplicationDbContext _context;
    private readonly IBusinessRuleService _businessRules;
    private readonly ILogger<TransferService> _logger;
    private readonly INotificationService _notificationService;

    public TransferService(
        ApplicationDbContext context,
        IBusinessRuleService businessRules,
        ILogger<TransferService> logger,
        INotificationService notificationService)
    {
        _context = context;
        _businessRules = businessRules;
        _logger = logger;
        _notificationService = notificationService;
    }

    public async Task<TransferResult> TransferMoneyAsync(int fromUserId, TransferRequest request)
    {
        if (request.Amount <= 0)
        {
            return TransferResult.Failure("Amount must be positive");
        }

        if (request.Amount > 10000)
        {
            return TransferResult.Failure("Amount exceeds maximum transfer limit");
        }

        using var transaction = await _context.Database.BeginTransactionAsync();

        try
        {
            // Lock and get source account
            var fromAccount = await _context.Accounts
                .Where(a => a.UserId == fromUserId)
                .FirstOrDefaultAsync();

            if (fromAccount == null)
            {
                return TransferResult.Failure("Source account not found");
            }

            // Get destination account
            var toAccount = await _context.Accounts
                .FirstOrDefaultAsync(a => a.AccountNumber == request.ToAccountNumber);

            if (toAccount == null)
            {
                return TransferResult.Failure("Destination account not found");
            }

            // Prevent self-transfer
            if (fromAccount.Id == toAccount.Id)
            {
                return TransferResult.Failure("Cannot transfer to same account");
            }

            // Apply business rules
            var businessRuleResult = await _businessRules.ValidateTransferAsync(fromAccount, request);
            if (!businessRuleResult.IsValid)
            {
                return TransferResult.Failure(businessRuleResult.ErrorMessage);
            }

            // Check balance
            if (fromAccount.Balance < request.Amount)
            {
                return TransferResult.Failure("Insufficient funds");
            }

            // Check daily limits
            var dailyTransferAmount = await GetDailyTransferAmountAsync(fromUserId);
            if (dailyTransferAmount + request.Amount > fromAccount.DailyTransferLimit)
            {
                return TransferResult.Failure("Daily transfer limit exceeded");
            }

            // Perform transfer
            fromAccount.Balance -= request.Amount;
            toAccount.Balance += request.Amount;

            fromAccount.UpdatedAt = DateTime.UtcNow;
            toAccount.UpdatedAt = DateTime.UtcNow;

            // Create transaction record
            var transferRecord = new Transfer
            {
                FromAccountId = fromAccount.Id,
                ToAccountId = toAccount.Id,
                Amount = request.Amount,
                Description = request.Description,
                Status = TransferStatus.Completed,
                CreatedAt = DateTime.UtcNow,
                TransactionId = Guid.NewGuid().ToString()
            };

            _context.Transfers.Add(transferRecord);

            await _context.SaveChangesAsync();
            await transaction.CommitAsync();

            // Send notifications
            await _notificationService.NotifyTransferAsync(fromAccount.UserId, toAccount.UserId,
                request.Amount, transferRecord.TransactionId);

            _logger.LogInformation("Transfer completed: {TransactionId} from {FromAccount} to {ToAccount} amount {Amount}",
                transferRecord.TransactionId, fromAccount.AccountNumber, toAccount.AccountNumber, request.Amount);

            return TransferResult.Success(transferRecord.TransactionId);
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync();
            _logger.LogError(ex, "Transfer failed for user {UserId}", fromUserId);
            return TransferResult.Failure("Transfer failed");
        }
    }

    private async Task<decimal> GetDailyTransferAmountAsync(int userId)
    {
        var today = DateTime.UtcNow.Date;
        var tomorrow = today.AddDays(1);

        return await _context.Transfers
            .Where(t => t.FromAccount.UserId == userId &&
                       t.CreatedAt >= today &&
                       t.CreatedAt < tomorrow &&
                       t.Status == TransferStatus.Completed)
            .SumAsync(t => t.Amount);
    }
}

// Business rules service
public interface IBusinessRuleService
{
    Task<BusinessRuleResult> ValidateTransferAsync(Account fromAccount, TransferRequest request);
}

public class BusinessRuleService : IBusinessRuleService
{
    private readonly ApplicationDbContext _context;

    public BusinessRuleService(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<BusinessRuleResult> ValidateTransferAsync(Account fromAccount, TransferRequest request)
    {
        // Check account status
        if (!fromAccount.IsActive)
        {
            return BusinessRuleResult.Invalid("Account is not active");
        }

        if (fromAccount.IsFrozen)
        {
            return BusinessRuleResult.Invalid("Account is frozen");
        }

        // Check transfer count limits
        var todayTransferCount = await GetTodayTransferCountAsync(fromAccount.UserId);
        if (todayTransferCount >= 10)
        {
            return BusinessRuleResult.Invalid("Daily transfer count limit exceeded");
        }

        // Check for suspicious activity
        var recentTransfers = await _context.Transfers
            .Where(t => t.FromAccountId == fromAccount.Id &&
                       t.CreatedAt > DateTime.UtcNow.AddHours(-1))
            .CountAsync();

        if (recentTransfers >= 5)
        {
            return BusinessRuleResult.Invalid("Too many transfers in short time period");
        }

        // Validate business hours (if required)
        var currentHour = DateTime.UtcNow.Hour;
        if (request.Amount > 5000 && (currentHour < 9 || currentHour > 17))
        {
            return BusinessRuleResult.Invalid("Large transfers only allowed during business hours");
        }

        return BusinessRuleResult.Valid();
    }

    private async Task<int> GetTodayTransferCountAsync(int userId)
    {
        var today = DateTime.UtcNow.Date;
        var tomorrow = today.AddDays(1);

        return await _context.Transfers
            .Where(t => t.FromAccount.UserId == userId &&
                       t.CreatedAt >= today &&
                       t.CreatedAt < tomorrow)
            .CountAsync();
    }
}

// Controller with rate limiting
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class AccountController : ControllerBase
{
    private readonly ITransferService _transferService;
    private readonly IPasswordResetService _passwordResetService;

    public AccountController(
        ITransferService transferService,
        IPasswordResetService passwordResetService)
    {
        _transferService = transferService;
        _passwordResetService = passwordResetService;
    }

    [HttpPost("password-reset")]
    [EnableRateLimiting("PasswordReset")]
    [AllowAnonymous]
    public async Task<IActionResult> InitiatePasswordReset([FromBody] PasswordResetRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var clientIP = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var result = await _passwordResetService.InitiateResetAsync(request.Email, clientIP);

        if (!result.IsSuccess)
        {
            return BadRequest(result.ErrorMessage);
        }

        return Ok(new { message = result.Message });
    }

    [HttpPost("transfer")]
    [EnableRateLimiting("Transfer")]
    public async Task<IActionResult> Transfer([FromBody] TransferRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value!);
        var result = await _transferService.TransferMoneyAsync(userId, request);

        if (!result.IsSuccess)
        {
            return BadRequest(result.ErrorMessage);
        }

        return Ok(new { transactionId = result.TransactionId, message = "Transfer completed successfully" });
    }
}
```

This continues with the remaining vulnerabilities A05-A10 and A09-A10. Would you like me to continue with the rest of the C# remediation examples?