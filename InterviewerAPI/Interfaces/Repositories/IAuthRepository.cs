using InterviewerAPI.Models.AuthModels;

namespace InterviewerAPI.Interfaces.Repositories
{
    public interface IAuthRepository
    {
        string GetToken(UserLoginModel userLoginModel);
    }
}
