using BBK.HRMS.API.Auth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

// RULE: Only one endpoint per class
namespace BBK.HRMS.API.Areas.Auth.Controllers
{
    [ApiController]
    [Produces("application/json")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    public class LoginController : ControllerBase
    {
        [HttpPost]
        [Route("/login")]
        public ActionResult<string> Post(LoginRequest request)
        {
            Validate(request);
            if (!ModelState.IsValid)
            {
                return ValidationProblem();
            }
            string token = Process(request);
            return Ok(token);
        }

        private void Validate(LoginRequest request)
        {
            if (string.IsNullOrEmpty(request.CompanyCode))
            {
                ModelState.AddModelError("CompanyCode", "Company Code cannot be blank");
            }
            else if (request.CompanyCode != "BBK" && request.CompanyCode != "CMAX" && request.CompanyCode != "INVI")
            {
                ModelState.AddModelError("CompanyCode", "Invalid Company Code");
            }

            if (string.IsNullOrEmpty(request.Username))
            {
                ModelState.AddModelError("Username", "Username cannot be blank");
            }

            if (string.IsNullOrEmpty(request.Password))
            {
                ModelState.AddModelError("Password", "Password cannot be blank");
            }

            if (ModelState.IsValid)
            {
                if (request.Username != "soh1763" || request.Password != "123")
                {
                    ModelState.AddModelError("Username", "Invalid username or password");
                }
            }
        }

        private static string Process(LoginRequest request)
        {
            var issuer = "bbk-hrms";
            var audience = "bbk-hrms";
            var key = Encoding.ASCII.GetBytes("bbk-hrms-secret-key");
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("Id", Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Sub, request.Username ?? ""),
                    new Claim(JwtRegisteredClaimNames.Email, "sohil.ravjani@bbkonline.com"),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                 }),
                Expires = DateTime.UtcNow.AddMinutes(5),
                Issuer = issuer,
                Audience = audience,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512Signature)
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = tokenHandler.WriteToken(token);
            return jwtToken;
        }
    }

    public record LoginRequest(string? CompanyCode, string? Username, string? Password);
}
