using System.ComponentModel.DataAnnotations;

namespace LPS.Security.API.ViewModels
{
	public class LoginUserViewModel
	{
		[Required]
		public string Email { get; set; }
		
		[Required]
		[MinLength(6)]
		public string Password { get; set; }
	}
}
