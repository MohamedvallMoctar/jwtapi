using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TestApiJWTtest.Helpers;
using TestApiJWTtest.Models;

namespace TestApiJWTtest.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly JWT _jwt;
        public AuthService(UserManager<ApplicationUser> userManager, IOptions<JWT> jwt)
        {
            _userManager = userManager;
            _jwt = jwt.Value;
        }
        public async  Task<AuthModel>  RegisterAsync(RegisterModel model)
        {
            if (await _userManager.FindByEmailAsync(model.Email) is not null)
                return new AuthModel { Message = "Email is already in use" };
            if (await _userManager.FindByNameAsync(model.Username) is not null)
                return new AuthModel { Message = "Username is already in use" };

            var user = new ApplicationUser
            {
                UserName = model.Username,
                Email = model.Email,
                FirsName = model.FirstName,
                LastName = model.LastName,

            };
            var result = _userManager.CreateAsync(user,model.Password);
            if (!result.Result.Succeeded)
            {
                var errors = string.Empty;
                foreach(var error in result.Result.Errors)
                {
                    errors += error.Description;
                }
                return new AuthModel { Message = errors };

            }

            await _userManager.AddToRoleAsync(user, "User");
            var jwtSecurityToken = await  CreateJwtToken(user);
            return new AuthModel
            {
                Email = user.Email,
                ExpiresOn = jwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User"},
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                UserName = user.UserName,

            };
        }

        // start CreateJwtToken Method  

        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            foreach (var role in roles) {
                roleClaims.Add(new Claim("roles", role));
            }

            var claims = new[]
            {
                new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Email, user.Email),

            }
            .Union(roleClaims)
            .Union(userClaims);

            var symetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signinCredentials = new SigningCredentials(symetricSecurityKey, SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(
                    issuer: _jwt.Issuer,
                    audience: _jwt.Auience,
                    claims: claims,
                    expires: DateTime.Now.AddDays(_jwt.DurationInDays),
                    signingCredentials: signinCredentials

                );

            return jwtSecurityToken;

        }

        public async Task<AuthModel> GetTokenAsync(LoginModel model){

            var authModel = new AuthModel
            {
                Email = model.Email,

                
            };
            var user = await _userManager.FindByEmailAsync(model.Email);

            if(user == null || await _userManager.CheckPasswordAsync(user, model.Password))
            {
                authModel.Message = "User or Password are invalid ";
                

            }
            else
            {
                var securityToken = await CreateJwtToken(user);
                authModel.IsAuthenticated = true;
                authModel.Token = new JwtSecurityTokenHandler().WriteToken(securityToken);
                authModel.ExpiresOn = securityToken.ValidTo;

            }

            return authModel;
        }

    }
}
