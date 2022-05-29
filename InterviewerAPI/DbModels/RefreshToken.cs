using System;
using System.Collections.Generic;

namespace InterviewerAPI.DbModels
{
    public partial class RefreshToken
    {
        public Guid AccountGlobalIdentifier { get; set; }
        public string? RefreshToken1 { get; set; }
        public DateTime? CreatedDate { get; set; }
        public DateTime? ExpirationDate { get; set; }
    }
}
