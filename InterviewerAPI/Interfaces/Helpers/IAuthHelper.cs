using InterviewerAPI.Models.AuthModels;
using System.IdentityModel.Tokens.Jwt;

namespace InterviewerAPI.Interfaces.Helpers
{
    public interface IAuthHelper
    {
        UserAccountModel GetUserAccountFromClaims(JwtSecurityToken accessToken);
        string CreateAccessToken(UserAccountModel userAccountModel);
        string CreateSaltedPasswordHash(string saltedPassword);
        JwtSecurityToken ValidateAccessToken(string accessToken);
    }
}
