namespace MerkleAudit.Api.Models
{
    public class AuditLog
    {
        // To będą kolumny w naszej bazie danych
        public int Id { get; set; }
        public string Sender { get; set; }       // Nadawca przelewu
        public string Receiver { get; set; }     // Odbiorca przelewu
        public decimal Amount { get; set; }      // Kwota
        public DateTime Timestamp { get; set; }  // Kiedy wykonano operację

        // Nasze zabezpieczenie kryptograficzne
        public string? Hash { get; set; }        // Hash z danych
    }
}
