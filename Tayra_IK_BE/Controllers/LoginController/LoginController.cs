using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Tayra_IK.Data;
using Tayra_IK.Models;

namespace Tayra_IK.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly AppDbContext _dbContext; // Assuming you have a DbContext

        public AuthController(IConfiguration configuration, AppDbContext dbContext)
        {
            _configuration = configuration;
            _dbContext = dbContext;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            Console.WriteLine("Received request. Email: " + model.Email + ", Password: " + model.Password);

            Console.WriteLine("girildi");
            if (string.IsNullOrEmpty(model.Email) || string.IsNullOrEmpty(model.Password))
            {
                return BadRequest("Email and password are required.");
            }

            if (AuthenticateUser(model.Email, model.Password))
            {
                var token = GenerateJwtToken(model.Email);
                var user = _dbContext.Users.SingleOrDefault(u => u.Email == model.Email);
                Console.WriteLine("model email: " + model.Email);
                Console.WriteLine("user email: " + user.Email);

                var role = user.Employee_Role.ToString();
                Console.WriteLine("user role:" + role);
                return Ok(new { token, role });
            }

            return Unauthorized("Invalid credentials");
        }

        private bool AuthenticateUser(string email, string password)
        {
            var user = _dbContext.Users.SingleOrDefault(u => u.Email == email);

            if (user == null)
            {
                return false;
            }

            // Compare the plaintext input password with the stored plaintext password
            bool isPasswordValid = password == user.Password;

            if (isPasswordValid)
            {
                Console.WriteLine("Authenticate User Successful");
            }

            return isPasswordValid;
        }

        private string GenerateJwtToken(string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                throw new ArgumentException("Email cannot be null or empty.", nameof(email));
            }

            var jwtConfigSection = _configuration.GetSection("Jwt");

            if (jwtConfigSection == null)
            {
                throw new InvalidOperationException("Jwt configuration section is missing.");
            }

            var jwtConfig = _configuration.GetSection("JwtConfig").Get<JwtConfig>();

            if (jwtConfig == null)
            {
                throw new InvalidOperationException("JwtConfig is null.");
            }

            // Define claims here
            var claims = new[]
            {
                new Claim(ClaimTypes.Email, email),
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfig.SecretKey));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: jwtConfig.Issuer,
                audience: jwtConfig.Audience,
                claims: claims,
                expires: DateTime.Now.AddHours(10),
                signingCredentials: credentials
            );

            Console.WriteLine("GenerateJwtToken Successful");

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
