using Domain.Entities;
using Domain.Repositories;
using Domain.Services;
using System;
using System.Data;
using System.Linq;
using System.Threading.Tasks;

namespace DataAccess
{
	public class UserRepository : BaseRepository<User>, IUserRepository
	{
		private readonly ISecurityService securityService;

		public UserRepository(LPSSecurityDbContext cosmosDbContext, ISecurityService securityService) : base(cosmosDbContext)
		{
			this.securityService = securityService;
		}

		public async Task<User> FindUserByUsernameAndPasswordAsync(string email, string password)
		{
			try
			{
				string passwordHash = securityService.GetSha256Hash(password);
				
				return Find(x => x.Email == email && x.Password == passwordHash).Result.FirstOrDefault();
			}
			catch (Exception ex)
			{
				throw ex;
			}
		}

		public async Task<bool> DeleteUserTokensByUserIdAsync(string userId)
		{
			try
			{

				var user = Find(x => x.Id == userId).Result.FirstOrDefault();

				user.Tokens.Clear();

				await Update(user);

				return true;
			}
			catch (Exception ex)
			{
				throw ex;
			}
		}

		public async Task<bool> AddUserTokenByUserIdAsync(string userId, Token token)
		{
			try
			{
				var user = Find(x => x.Id == userId).Result.FirstOrDefault();

				user?.Tokens.Add(token);

				await Update(user);

				return true;
			}
			catch (Exception ex)
			{
				throw ex;
			}
		}

		public async Task<Token> FindTokenByUserIdAndAccessTokenAsync(string userId, string accessTokenHash)
		{
			try
			{
				var user = Find(x => x.Id == userId).Result.FirstOrDefault();

				return user.Tokens.Where(x => x.AccessTokenHash == accessTokenHash).FirstOrDefault();
			}
			catch (Exception ex)
			{
				throw ex;
			}
		}

		public async Task<bool> UpdateUserLastActivityDateAsync(User user)
		{
			try
			{
				var currentUtc = DateTimeOffset.UtcNow;
				if (user.LastLoggedIn != null)
				{
					var updateLastActivityDate = TimeSpan.FromMinutes(2);
					var timeElapsed = currentUtc.Subtract(user.LastLoggedIn.Value);
					if (timeElapsed < updateLastActivityDate)
					{
						return true;
					}
				}

				user.LastLoggedIn = currentUtc;

				await Update(user);
				return true;
			}
			catch (Exception ex)
			{

				throw ex;
			}
		}

		public async Task<bool> DeleteExpiredTokensAsync(string userId)
		{
			try
			{
				var user = Find(x => x.Id == userId).Result.FirstOrDefault();

				user.Tokens.RemoveAll(x => x.RefreshTokenExpiresDateTime < DateTimeOffset.UtcNow);

				await Update(user);

				return true;
			}
			catch (Exception ex)
			{
				throw ex;
			}
		}

		public async Task<bool> DeleteTokensWithSameRefreshTokenSourceAsync(string refreshTokenIdHashSource, string userId)
		{
			if (string.IsNullOrWhiteSpace(refreshTokenIdHashSource))
			{
				return true;
			}

			try
			{
				var user = Find(x => x.Id == userId).Result.FirstOrDefault();

				user.Tokens.RemoveAll(x => x.RefreshTokenIdHashSource == refreshTokenIdHashSource || (x.RefreshTokenIdHash == refreshTokenIdHashSource && x.RefreshTokenIdHashSource == null));

				await Update(user);

				return true;
			}
			catch (Exception ex)
			{
				throw ex;
			}
		}

		public async Task<(Token token, User user)> FindUserAndTokenByRefreshTokenAsync(string refreshToken)
		{
			try
			{
				string refreshTokenHash = securityService.GetSha256Hash(refreshToken);

				User user = _context.User.AsEnumerable().Where(x => x.Tokens.Any(x => x.RefreshTokenIdHash == refreshTokenHash)).FirstOrDefault();

				if (user == null)
				{
					throw new Exception("Invalid refresh token");
				}
				return (user.Tokens.Where(x => x.RefreshTokenIdHash == refreshTokenHash).FirstOrDefault(), user);
			}
			catch (Exception ex)
			{
				throw ex;
			}
		}

		public async Task<User> FindUserByUsernameAsync(string email)
		{
			try
			{
				var user = Find(s => s.Email == email).Result.FirstOrDefault();//_context.User.FirstOrDefault(s => s.Email == email);
				return user;
			}
			catch (Exception ex)
			{
				throw ex;
			}
		}

		public async Task<bool> ChangePassword(string userId, string newPasswordHash, string newSerialNumber)
		{
			var user = Find(s => s.Id == userId).Result.FirstOrDefault();
			try
			{
				user.Password = newPasswordHash;
				user.SerialNumber = newSerialNumber;

				await Update(user);
				return true;
			}
			catch (Exception ex)
			{

				throw ex;
			}

		}
	}
}
