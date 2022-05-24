using System;
using System.Collections.Generic;

namespace InterviewerAPI.DbModels
{
    public partial class UsersAccount
    {
        public Guid AccountGlobalIdentifier { get; set; }
        public string UserEmail { get; set; } = null!;
        public string UserPassword { get; set; } = null!;
        public string Salt { get; set; } = null!;
        public int UserRole { get; set; }
        public DateTime DateOfProfileCreation { get; set; }
    }
}
