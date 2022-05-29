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
            var user = GetUserAccountFromDb(userLoginModel);
            if (user == null)
                throw new UnauthorizedAccessException("Specified user does not exist");

            string accessToken = CreateAccessToken(user);
            string refreshToken = CreateRefreshToken(user.AccountGlobalIdentifier);

            return new AuthenticationResponseModel() { AccessToken = accessToken, RefreshToken = refreshToken };
        }

        public AuthenticationResponseModel ExtendUserSession(AuthenticationResponseModel extendUserSessionRequestModel)
        {
            var validatedAccessToken = ValidateAccessToken(extendUserSessionRequestModel.AccessToken);
            var userAccount = GetUserAccountFromClaims(validatedAccessToken);
            var refreshToken = GetRefreshTokenByAccountGlobalIdentifier(userAccount.AccountGlobalIdentifier);
            DateTime dateTime = DateTime.UtcNow;

            if (validatedAccessToken.ValidTo > dateTime)
                return extendUserSessionRequestModel;

            if (refreshToken.ExpirationDate < dateTime)
                throw new SecurityTokenException("Refresh token is expired. Please login to get new access token along with refresh one");


            var extendedTokens = new AuthenticationResponseModel()
            {
                AccessToken = CreateAccessToken(userAccount),
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

        private UserAccountModel GetUserAccountFromClaims(JwtSecurityToken accessToken) 
        {
            var accountGlobalIdentifier = Guid.Parse(accessToken.Claims.Single(c => c.Type == "nameid").Value);
            var userEmail = accessToken.Claims.Single(c => c.Type == "email").Value.ToString();
            var userRole = (UserRolesEnum)Enum.Parse(typeof(UserRolesEnum), accessToken.Claims.Single(c => c.Type == "role").Value);

            var userAccountModel = new UserAccountModel()
            {
                UserEmail = userEmail,
                AccountGlobalIdentifier = accountGlobalIdentifier,
                UserRole = userRole
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
                Expires = DateTime.UtcNow.AddMinutes(_accessTokenExpirationTimeInMinutes),
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

        private JwtSecurityToken ValidateAccessToken(string accessToken) 
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenValidationParams = new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _issuer,
                ValidAudience = _audience,
                ValidateLifetime = false,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_secretKey))
            };

            tokenHandler.ValidateToken(accessToken, tokenValidationParams, out SecurityToken validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;

            return jwtToken;
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
