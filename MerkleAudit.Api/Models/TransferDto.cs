namespace MerkleAudit.Api.Models
{
    public class TransferDto
    {
        public string Sender { get; set; } = string.Empty;
        public string Receiver { get; set; } = string.Empty;
        public decimal Amount { get; set; }
    }
}