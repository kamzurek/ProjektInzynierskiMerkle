namespace MerkleAudit.Api.Models
{
    public class AuditLog
    {
        public int Id { get; set; }
        public string Sender { get; set; } = string.Empty;
        public string Receiver { get; set; } = string.Empty;
        public decimal Amount { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public string IpAddress { get; set; } = string.Empty;
        public string UserAgent { get; set; } = string.Empty;
        public string PreviousHash { get; set; } = string.Empty;
        public string Hash { get; set; } = string.Empty;
    }
}