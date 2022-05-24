using InterviewerAPI.DbModels;
using InterviewerAPI.Interfaces.Repositories;
using InterviewerAPI.Models.AuthModels;
using InterviewerAPI.Models.AuthModels.AuthEnums;
using System.Security.Cryptography;
using System.Text;

namespace InterviewerAPI.Repositories
{
    public class RegisterRepository : IRegisterRepository
    {
        private readonly InterviewerAuthDbContext _authDbContext;
        public RegisterRepository(InterviewerAuthDbContext authDbContext)
        {
            _authDbContext = authDbContext;
        }

        public void RegisterAdministratorAccount(AdministratorAccountRegisterModel administratorAccountRegisterModel)
        {
            CheckIfUserAlreadyExist(administratorAccountRegisterModel.UserEmail);
            AddAdministratorToDb(administratorAccountRegisterModel);
        }

        #region Helper Methods

        private void CheckIfUserAlreadyExist(string userEmail)
        {
            var userExist = _authDbContext.UsersAccounts.Any(user => user.UserEmail == userEmail);
            if (userExist)
                throw new ArgumentException("User with specified email already exist");
        }

        private void AddAdministratorToDb(AdministratorAccountRegisterModel administratorAccountRegisterModel)
        {
            Guid salt = Guid.NewGuid();
            var userAccount = new UsersAccount()
            {
                UserEmail = administratorAccountRegisterModel.UserEmail,
                UserRole = (int)UserRolesEnum.Admin,
                DateOfProfileCreation = DateTime.Now,
                Salt = salt.ToString(),
                UserPassword = CreateSaltedPasswordHash(administratorAccountRegisterModel.Password + salt)
            };
            _authDbContext.UsersAccounts.Add(userAccount);
            _authDbContext.SaveChangesAsync();
        }

        private string CreateSaltedPasswordHash(string saltedPassword)
        {
            byte[] hash;
            using (MD5 md5 = MD5.Create())
            {
                hash = md5.ComputeHash(Encoding.UTF8.GetBytes(saltedPassword));
            }

            string a = BitConverter.ToString(hash);

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
