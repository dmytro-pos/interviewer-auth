using InterviewerAPI.DbModels;
using InterviewerAPI.Interfaces.Helpers;
using InterviewerAPI.Interfaces.Repositories;
using InterviewerAPI.Models.AuthModels;
using InterviewerAPI.Models.AuthModels.AuthEnums;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace InterviewerAPI.Repositories
{
    public class AuthRepository : IAuthRepository
    {
        private readonly int _refreshTokenExpirationTimeInDays;
        private readonly InterviewerAuthDbContext _authDbContext;
        private readonly IAuthHelper _authHelper;

        public AuthRepository(int refreshTokenExpirationTimeInDays, InterviewerAuthDbContext authDbContext,
            IAuthHelper authHelper)
        {
            _authDbContext = authDbContext;
            _refreshTokenExpirationTimeInDays = refreshTokenExpirationTimeInDays;
            _authHelper = authHelper;
        }

        public AuthenticationResponseModel GetToken(UserLoginRequestModel userLoginModel)
        {
            var user = GetUserAccountFromDb(userLoginModel);
            if (user == null)
                throw new UnauthorizedAccessException("Specified user does not exist");

            string accessToken = _authHelper.CreateAccessToken(user);
            string refreshToken = CreateRefreshToken(user.AccountGlobalIdentifier);

            return new AuthenticationResponseModel() { AccessToken = accessToken, RefreshToken = refreshToken };
        }

        public AuthenticationResponseModel ExtendUserSession(AuthenticationResponseModel extendUserSessionRequestModel)
        {
            var validatedAccessToken = _authHelper.ValidateAccessToken(extendUserSessionRequestModel.AccessToken);
            var userAccount = _authHelper.GetUserAccountFromClaims(validatedAccessToken);
            var refreshToken = GetRefreshTokenByAccountGlobalIdentifier(userAccount.AccountGlobalIdentifier);
            DateTime dateTime = DateTime.UtcNow;

            if (validatedAccessToken.ValidTo > dateTime)
                return extendUserSessionRequestModel;

            if (refreshToken.ExpirationDate < dateTime)
                throw new SecurityTokenException("Refresh token is expired. Please login to get new access token along with refresh one");

            var extendedTokens = new AuthenticationResponseModel()
            {
                AccessToken = _authHelper.CreateAccessToken(userAccount),
                RefreshToken = CreateRefreshToken(userAccount.AccountGlobalIdentifier)
            };

            return extendedTokens;
        }

        #region Helper Methods

        private UserAccountModel GetUserAccountFromDb(UserLoginRequestModel userLoginModel)
        {
            var user = _authDbContext.UsersAccounts.SingleAsync(u => u.UserEmail == userLoginModel.UserLogin).Result;

            if (user == null)
                return null;

            string saltedPassword = _authHelper.CreateSaltedPasswordHash(userLoginModel.UserPassword + user.Salt);
            bool passwordIsCorrect = user.UserPassword == saltedPassword;

            if (!passwordIsCorrect)
                return null;

            var userAccountModel = new UserAccountModel()
            {
                UserEmail = user.UserEmail,
                UserRole = (UserRolesEnum)user.UserRole,
                AccountGlobalIdentifier = user.AccountGlobalIdentifier
            };

            return userAccountModel;
        }

        private string CreateRefreshToken(Guid accountGlobalIdentifier) 
        {
            var randomNumber = new byte[32];
            string refreshToken = "";

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                refreshToken = Convert.ToBase64String(randomNumber);
            }

            DateTime refreshTokenCreatedDate = DateTime.UtcNow;
            DateTime refreshTokenExpirationDate = DateTime.UtcNow.AddDays(_refreshTokenExpirationTimeInDays);

            var refreshTokenModel = new RefreshToken() 
            {
                AccountGlobalIdentifier = accountGlobalIdentifier,
                CreatedDate = refreshTokenCreatedDate,
                ExpirationDate = refreshTokenExpirationDate,
                RefreshToken1 = refreshToken
            };

            var refreshTokenFromDb = GetRefreshTokenByAccountGlobalIdentifier(accountGlobalIdentifier);

            if (refreshTokenFromDb == null)
                _authDbContext.RefreshTokens.Add(refreshTokenModel);
            else
            {
                refreshTokenFromDb.RefreshToken1 = refreshToken;
                refreshTokenFromDb.CreatedDate = refreshTokenCreatedDate;
                refreshTokenFromDb.ExpirationDate = refreshTokenExpirationDate;
            }

            _authDbContext.SaveChangesAsync();
            
            return refreshToken;
        }

        private RefreshToken GetRefreshTokenByAccountGlobalIdentifier(Guid accountGlobalIdentifier) 
        {
            var refreshTokenFromDb = _authDbContext.RefreshTokens.SingleOrDefaultAsync(t =>
            t.AccountGlobalIdentifier == accountGlobalIdentifier).Result;

            return refreshTokenFromDb;
        }

        #endregion
    }
}
