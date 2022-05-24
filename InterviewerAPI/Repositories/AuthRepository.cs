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
        private readonly int _expireTimeInMinutes;
        private readonly InterviewerAuthDbContext _authDbContext;

        public AuthRepository(string secretKey, string issuer, string audience, int expireTimeInMinutes,
        InterviewerAuthDbContext authDbContext)
        {
            _secretKey = secretKey;
            _issuer = issuer;
            _audience = audience;
            _expireTimeInMinutes = expireTimeInMinutes;
            _authDbContext = authDbContext;
        }

        public string GetToken(UserLoginModel userLoginModel)
        {
            var user = GetUserAccount(userLoginModel);
            if (user == null)
                throw new UnauthorizedAccessException("Specified user does not exist");

            string token = CreateToken(user);

            return token;
        }

        #region Helper Methods

        private UserAccountModel GetUserAccount(UserLoginModel userLoginModel)
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
                UserRole = (UserRolesEnum)user.UserRole
            };

            return userAccountModel;
        }

        private string CreateToken(UserAccountModel userAccountModel)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_secretKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

            var tokenHandler = new JwtSecurityTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Email, userAccountModel.UserEmail),
                    new Claim(ClaimTypes.Role, userAccountModel.UserRole.ToString())
                }),
                Expires = DateTime.Now.AddMinutes(_expireTimeInMinutes),
                Issuer = _issuer,
                Audience = _audience,
                SigningCredentials = credentials
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
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
