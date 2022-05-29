using InterviewerAPI.DbModels;
using InterviewerAPI.Interfaces.Repositories;
using InterviewerAPI.Models.AuthModels;
using InterviewerAPI.Models.AuthModels.AuthEnums;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace InterviewerAPI.Repositories
{
    public class AuthRepository : IAuthRepository
    {
        private readonly string _secretKey;
        private readonly string _issuer;
        private readonly string _audience;
        private readonly int _accessTokenExpirationTimeInMinutes;
        private readonly int _refreshTokenExpirationTimeInDays;
        private readonly InterviewerAuthDbContext _authDbContext;

        public AuthRepository(string secretKey, string issuer, string audience, int accessTokenExpirationTimeInMinutes,
        int refreshTokenExpirationTimeInDays, InterviewerAuthDbContext authDbContext)
        {
            _secretKey = secretKey;
            _issuer = issuer;
            _audience = audience;
            _accessTokenExpirationTimeInMinutes = accessTokenExpirationTimeInMinutes;
            _authDbContext = authDbContext;
            _refreshTokenExpirationTimeInDays = refreshTokenExpirationTimeInDays;
        }

        public AuthenticationResponseModel GetToken(UserLoginRequestModel userLoginModel)
        {
            var user = GetUserAccount(userLoginModel);
            if (user == null)
                throw new UnauthorizedAccessException("Specified user does not exist");

            string accessToken = CreateAccessToken(user);
            string refreshToken = CreateRefreshToken(user.AccountGlobalIdentifier);

            return new AuthenticationResponseModel() { AccessToken = accessToken, RefreshToken = refreshToken };
        }

        #region Helper Methods

        private UserAccountModel GetUserAccount(UserLoginRequestModel userLoginModel)
        {
            var user = _authDbContext.UsersAccounts.SingleAsync(u => u.UserEmail == userLoginModel.UserLogin).Result;

            if (user == null)
                return null;
            string saltedPassword = CreateSaltedPasswordHash(userLoginModel.UserPassword + user.Salt);
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

        private string CreateAccessToken(UserAccountModel userAccountModel)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_secretKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

            var tokenHandler = new JwtSecurityTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Email, userAccountModel.UserEmail),
                    new Claim(ClaimTypes.Role, userAccountModel.UserRole.ToString()),
                    new Claim(ClaimTypes.NameIdentifier, userAccountModel.AccountGlobalIdentifier.ToString())
                }),
                Expires = DateTime.Now.AddMinutes(_accessTokenExpirationTimeInMinutes),
                Issuer = _issuer,
                Audience = _audience,
                SigningCredentials = credentials
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
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
            DateTime refreshTokenExpirationDate = DateTime.Now.AddDays(_refreshTokenExpirationTimeInDays);

            var refreshTokenModel = new RefreshToken() 
            {
                AccountGlobalIdentifier = accountGlobalIdentifier,
                CreatedDate = refreshTokenCreatedDate,
                ExpirationDate = refreshTokenExpirationDate,
                RefreshToken1 = refreshToken
            };

            var refreshTokenFromDb = _authDbContext.RefreshTokens.SingleOrDefaultAsync(t =>
            t.AccountGlobalIdentifier == accountGlobalIdentifier && t.ExpirationDate > DateTime.Now).Result;

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

        private string CreateSaltedPasswordHash(string saltedPassword)
        {
            byte[] hash;
            using (MD5 md5 = MD5.Create())
            {
                hash = md5.ComputeHash(Encoding.UTF8.GetBytes(saltedPassword));
            }

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hash.Length; i++)
            {
                sb.Append(hash[i].ToString("X2"));
            }
            return sb.ToString();
        }

        #endregion
    }
}
