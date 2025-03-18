using TestApiJWTtest.Models;

namespace TestApiJWTtest.Services
{
    public interface IAuthService
    {
        public Task<AuthModel> RegisterAsync(RegisterModel model);

        public Task<AuthModel> GetTokenAsync(LoginModel model);
    }
}
