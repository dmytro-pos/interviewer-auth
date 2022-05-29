using InterviewerAPI.Models.AuthModels;

namespace InterviewerAPI.Interfaces.Repositories
{
    public interface IAuthRepository
    {
        AuthenticationResponseModel GetToken(UserLoginRequestModel userLoginModel);
        AuthenticationResponseModel ExtendUserSession(AuthenticationResponseModel extendUserSessionRequestModel);
    }
}
