using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using JWTAuthTemplate.Context;
using JWTAuthTemplate.DTO.Identity;
using JWTAuthTemplate.Extensions;
using JWTAuthTemplate.Models.Identity;
using JWTAuthTemplate.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuthTemplate.Controllers
{
    [ApiController]
    [Route("Auth")]
    public class AuthenticationController: ControllerBase
    {
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly IOptionsMonitor<JwtBearerOptions> _jwtOptions;
        private readonly ApplicationDbContext _context;

        public AuthenticationController(ApplicationDbContext context, UserManager<ApplicationUser> signInManager, IConfiguration configuration, RoleManager<ApplicationRole> roleManager, IOptionsMonitor<JwtBearerOptions> jwtOptions)
        {
            _context = context;
            
            _userManager = signInManager;
            _configuration = configuration;
            _roleManager = roleManager;
            _jwtOptions = jwtOptions;
        }

        [HttpPost("register")]
        public async Task<ActionResult> Register([FromBody] RegisterDTO registration)
        {
            var emailExists = await _userManager.FindByEmailAsync(registration.Email);

            if (emailExists != null)
            {
                return BadRequest("That email is already in use!");
            }

            var user = new ApplicationUser()
            {
                Id = Guid.NewGuid().ToString(),
                Email = registration.Email,
                UserName = Guid.NewGuid().ToString(),
                SecurityStamp = Guid.NewGuid().ToString(),
                CreateDate = DateTime.UtcNow,
            };

            try
            {
                var statusPassword = ValidPassword.PasswordStrength(registration.Password); 
                if ((int)statusPassword == 1)
                {   
                    return BadRequest("weak_password");
                }
                var result = await _userManager.CreateAsync(user, registration.Password);
                if (!result.Succeeded)
                {
                    return BadRequest(result.Errors);
                }

                return Ok(new {user_id = user.Id, password_check_status = (int)statusPassword == 2 ? "good" : "perfect"});
            }
            catch (Exception e)
            {
                return BadRequest(e.Message);
            }
            
        }

        [HttpPost("authorize")]
        public async Task<ActionResult> Login([FromBody] LoginDTO login)
        {
            var user = await _userManager.FindByEmailAsync(login.Email);
            if (user == null)
            {
                return BadRequest("Invalid mail or password!");
                
            }

            var result = await _userManager.CheckPasswordAsync(user, login.Password);
            if (!result)
            {
                return BadRequest("Invalid mail or password!");
            }
            
            var claims = new List<Claim>()
            {
                new Claim("user_id", user.Id),
                new Claim(ClaimTypes.Email, user.Email),
            };

            foreach (var userRole in user.Roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, userRole.Role.Name));
            }

            var token = CreateToken(claims.ToList());
            var refreshToken = GenerateRefreshToken();

            _ = int.TryParse(_configuration["Jwt:RefreshTokenExpirationDays"], out int refreshTokenExpirationDays);
            
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(refreshTokenExpirationDays);

            await _userManager.UpdateAsync(user);


            return Ok(new
            {
                access_token = new JwtSecurityTokenHandler().WriteToken(token)
            });
        }

        
        [HttpGet("feed/{access_token}")]
        public async Task<IActionResult> Feed(string access_token)
        {
            try
            {
                var options = _jwtOptions.Get(JwtBearerDefaults.AuthenticationScheme);
                var tokenValidationParameters = options.TokenValidationParameters;

                var tokenHandler = new JwtSecurityTokenHandler();
                var principal = tokenHandler.ValidateToken(access_token, tokenValidationParameters, out SecurityToken securityToken);
                if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                    return Unauthorized();

                return Ok();
            }
            catch
            {
                return Unauthorized();
            }    
        }

        private JwtSecurityToken CreateToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]!));
            _ = int.TryParse(_configuration["JWT:TokenValidityInDays"], out int tokenValidityInDays);

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.UtcNow.AddDays(tokenValidityInDays),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            return token;
        }

        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            //get token validation configuration from addjwtbearer
            var options = _jwtOptions.Get(JwtBearerDefaults.AuthenticationScheme);
            var tokenValidationParameters = options.TokenValidationParameters;

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;

        }

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

    }
}
