using InterviewerAPI.Models.AuthModels.AuthEnums;

namespace InterviewerAPI.Models.AuthModels
{
    public class UserAccountModel
    {
        public string? UserEmail { get; set; }
        public string? Salt { get; set; }
        public UserRolesEnum UserRole { get; set; }
        public DateTime DateOfProfileCreation { get; set; }
        public Guid AccountGlobalIdentifier { get; set; }
    }
}
