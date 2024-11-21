namespace LPS.Security.API
{
    public interface IUserContext
    {
        string UserId { get; set; }
        string UserName { get; set; }
        string Email { get; set; }
    }
}
