using System.Security.Claims;

namespace LPS.Security.API
{
    public class UserContext : IUserContext
    {
        public string UserId { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }

        public readonly IHttpContextAccessor contextAccessor;

        public UserContext(IHttpContextAccessor contextAccessor)
        {
            this.contextAccessor = contextAccessor;
            RetrieveUserData();
        }

        public void RetrieveUserData()
        {
            UserId = this.contextAccessor.HttpContext.User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.UserData).Value;
            UserName = this.contextAccessor.HttpContext.User.Claims.FirstOrDefault(x => x.Type == "DisplayName").Value;
            Email = this.contextAccessor.HttpContext.User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Name).Value;
        }
    }
}
