using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TestApiJWTtest.Models;
using TestApiJWTtest.Services;

namespace TestApiJWTtest.Controllers
{
    [Route("/api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService ;
        public AuthController(IAuthService authService)
        {
            _authService = authService ;
        }

        // GET: AuthController
        //[Route("register")]
        [HttpPost("register")]

        public async Task<IActionResult> RegisterAsync([FromBody]RegisterModel model)
        {
            if(!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await _authService.RegisterAsync(model);
            if(!result.IsAuthenticated)
                return BadRequest(result.Message);
            return Ok(result);
        }

        [HttpPost("login")]
        public async Task<IActionResult> GetTokenAsync([FromBody]LoginModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await _authService.GetTokenAsync(model);
 
            if (!result.IsAuthenticated)
            {
                return BadRequest(result.Message);
            } 

            return Ok(result);
        }

        
    }
}
