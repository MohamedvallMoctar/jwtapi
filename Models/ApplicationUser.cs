using Microsoft.AspNetCore.Identity;

namespace TestApiJWTtest.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string FirsName { get; set; }
        public string LastName { get; set; }
    }
}
