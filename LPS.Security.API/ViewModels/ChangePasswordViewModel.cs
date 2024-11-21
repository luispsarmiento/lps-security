﻿using System.ComponentModel.DataAnnotations;

namespace LPS.Security.API.ViewModels
{
	public class ChangePasswordViewModel
	{
		[Required]
		public string OldPassword { get; set; }

		[Required]
		[MinLength(6)]
		public string NewPassword { get; set; }

		[Required]
		[Compare(nameof(NewPassword))]
		public string ConfirmNewPassword { get; set; }
	}
}
