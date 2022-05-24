using InterviewerAPI.Models.AuthModels;

namespace InterviewerAPI.Interfaces.Repositories
{
    public interface IRegisterRepository
    {
        void RegisterAdministratorAccount(AdministratorAccountRegisterModel administratorRegisterModel);
    }
}
