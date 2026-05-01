using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using MerkleAudit.Api.Data;
using MerkleAudit.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;

namespace MerkleAudit.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [AllowAnonymous]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;

        public AuthController(AppDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserRegisterDto request)
        {
            // 1. Sprawdzamy czy użytkownik już istnieje
            if (await _context.Users.AnyAsync(u => u.Username == request.Username))
            {
                return BadRequest("Użytkownik o takiej nazwie już istnieje.");
            }

            // 2. Hashujemy hasło algorytmem BCrypt
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

            // 3. Tworzymy użytkownika
            var user = new User
            {
                Username = request.Username,
                PasswordHash = passwordHash,
                Role = request.Role == "Admin" ? "Admin" : "User"
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return Ok(new { message = "Rejestracja zakończona sukcesem." });
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserLoginDto request)
        {
            // 1. Szukamy użytkownika w bazie
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
            if (user == null)
            {
                return BadRequest("Nieprawidłowa nazwa użytkownika.");
            }

            // 2. Weryfikujemy czy hasło pasuje do hasza w bazie
            if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            {
                return BadRequest("Nieprawidłowe hasło.");
            }

            // 3. Jeśli wszystko się zgadza, generujemy token JWT
            string token = CreateToken(user);

            return Ok(new { token = token });
        }

        private string CreateToken(User user)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");

            // Definiujemy, co znajdzie się w tokenie (tzw. Claims)
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, user.Role)
            };

            // Pobieramy nasz tajny klucz z appsettings.json
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]!));

            // Podpisujemy token kluczem
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.Now.AddHours(2), // Token wygasa po 2 godzinach
                signingCredentials: creds
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }
    }
}