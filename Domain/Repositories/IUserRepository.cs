﻿using Domain.Entities;
using System.Threading.Tasks;

namespace Domain.Repositories
{
	public interface IUserRepository: IBaseRepository<User>
	{
		Task<User> FindUserByUsernameAndPasswordAsync(string email, string password);
		Task<bool> DeleteUserTokensByUserIdAsync(string userId);
		Task<bool> AddUserTokenByUserIdAsync(string userId, Token token);
		Task<Token> FindTokenByUserIdAndAccessTokenAsync(string userId, string accessTokenHash);
		Task<(Token token, User user)> FindUserAndTokenByRefreshTokenAsync(string refreshToken);
		Task<bool> UpdateUserLastActivityDateAsync(User user);
		Task<bool> DeleteExpiredTokensAsync(string userId);
		Task<bool> DeleteTokensWithSameRefreshTokenSourceAsync(string refreshTokenIdHashSource, string userId);
		Task<User> FindUserByUsernameAsync(string email);
		Task<bool> ChangePassword(string userId, string newPasswordHash, string newSerialNumber);
	}
}
