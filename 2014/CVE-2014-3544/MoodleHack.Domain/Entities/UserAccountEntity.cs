using System;

namespace MoodleHack.Domain.Entities
{
    public class UserAccountEntity
    {
        public UserAccountEntity()
        {
        }

        public UserAccountEntity(string role, string cookie, string fio, DateTime created, bool isActive)
        {
            Role = role;
            Cookie = cookie;
            Fio = fio;
            Created = created;
            IsActive = isActive;
        }
        public Guid Id { get; set; }
        public string Role { get; set; }
        public string Cookie { get; set; }
        public string Fio { get; set; }
        public DateTime Created { get; set; }
        public bool IsActive { get; set; }
    }
}