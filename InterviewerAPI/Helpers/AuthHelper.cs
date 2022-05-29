using InterviewerAPI.Interfaces.Helpers;
using InterviewerAPI.Models.AuthModels;
using InterviewerAPI.Models.AuthModels.AuthEnums;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace InterviewerAPI.Helpers
{
    public class AuthHelper : IAuthHelper
    {
        private readonly string _secretKey;
        private readonly string _issuer;
        private readonly string _audience;
        private readonly int _accessTokenExpirationTimeInMinutes;

        public AuthHelper(string secretKey, string issuer, string audience, int accessTokenExpirationTimeInMinutes)
        {
            _secretKey = secretKey;
            _issuer = issuer;
            _audience = audience;
            _accessTokenExpirationTimeInMinutes = accessTokenExpirationTimeInMinutes;
        }

        public string CreateAccessToken(UserAccountModel userAccountModel)
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

        public string CreateSaltedPasswordHash(string saltedPassword)
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

        public UserAccountModel GetUserAccountFromClaims(JwtSecurityToken accessToken)
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

        public JwtSecurityToken ValidateAccessToken(string accessToken)
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
    }
}
