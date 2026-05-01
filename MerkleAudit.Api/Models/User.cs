namespace MerkleAudit.Api.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; } = string.Empty;
        // Zapisujemy TYLKO hash hasła, nigdy czysty tekst
        public string PasswordHash { get; set; } = string.Empty;
        public string Role { get; set; } = "Admin";
    }
}
