using System.ComponentModel.DataAnnotations;

namespace LPS.Security.API.ViewModels
{
	public class RegisteUserViewModel
	{
		[Required]
		public string Email { get; set; }
		
		[Required]
		[MinLength(6)]
		public string Password { get; set; }
		
		[Required]
		public string DisplayName { get; set; }
	}
}
