using InterviewerAPI.DbModels;
using InterviewerAPI.Interfaces.Helpers;
using InterviewerAPI.Interfaces.Repositories;
using InterviewerAPI.Models.AuthModels;
using InterviewerAPI.Models.AuthModels.AuthEnums;

namespace InterviewerAPI.Repositories
{
    public class RegisterRepository : IRegisterRepository
    {
        private readonly InterviewerAuthDbContext _authDbContext;
        private readonly IAuthHelper _authHelper;
        public RegisterRepository(InterviewerAuthDbContext authDbContext, IAuthHelper authHelper)
        {
            _authDbContext = authDbContext;
            _authHelper = authHelper;
        }

        public void RegisterAdministratorAccount(AdminAccountRegisterRequestModel adminAccountRegisterRequestModel)
        {
            CheckIfUserAlreadyExist(adminAccountRegisterRequestModel.UserEmail);
            AddAdministratorToDb(adminAccountRegisterRequestModel);
        }

        #region Helper Methods

        private void CheckIfUserAlreadyExist(string userEmail)
        {
            var userExist = _authDbContext.UsersAccounts.Any(user => user.UserEmail == userEmail);
            if (userExist)
                throw new ArgumentException("User with specified email already exist");
        }

        private void AddAdministratorToDb(AdminAccountRegisterRequestModel administratorAccountRegisterModel)
        {
            Guid salt = Guid.NewGuid();
            var userAccount = new UsersAccount()
            {
                UserEmail = administratorAccountRegisterModel.UserEmail,
                UserRole = (int)UserRolesEnum.Admin,
                DateOfProfileCreation = DateTime.UtcNow,
                Salt = salt.ToString(),
                UserPassword = _authHelper.CreateSaltedPasswordHash(administratorAccountRegisterModel.Password + salt)
            };
            _authDbContext.UsersAccounts.Add(userAccount);
            _authDbContext.SaveChangesAsync();
        }

        #endregion
    }
}
