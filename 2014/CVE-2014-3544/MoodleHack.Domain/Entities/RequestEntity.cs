using System;

namespace MoodleHack.Domain.Entities
{
    public class RequestEntity
    {
        public RequestEntity()
        {
        }

        public RequestEntity(string ip, string request, bool success, DateTime created)
        {
            Ip = ip;
            Request = request;
            Success = success;
            Created = created;
        }
        public Guid Id { get; set; }
        public string Ip { get; set; }
        public string Request { get; set; }
        public bool Success { get; set; }
        public DateTime Created { get; set; }
    }
}