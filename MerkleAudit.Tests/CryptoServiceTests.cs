using Xunit;
using MerkleAudit.Api.Services;
using MerkleAudit.Api.Models;

namespace MerkleAudit.Tests
{
    public class CryptoServiceTests
    {
        private readonly CryptoService _cryptoService;

        public CryptoServiceTests()
        {
            _cryptoService = new CryptoService();
        }

        [Fact]
        public void CalculateHashForLog_ZwracaDeterministycznyWynik()
        {
            // Arrange (Przygotowanie danych)
            var log = new AuditLog
            {
                Id = 1,
                Sender = "Admin",
                Receiver = "Jan Kowalski",
                Amount = 100.50m,
                IpAddress = "192.168.1.1",
                UserAgent = "Mozilla/5.0",
                PreviousHash = "0000000000000000"
            };

            // Act (Wykonanie akcji)
            var hash1 = _cryptoService.CalculateHashForLog(log);
            var hash2 = _cryptoService.CalculateHashForLog(log);

            // Assert (Weryfikacja)
            Assert.NotNull(hash1);
            Assert.Equal(hash1, hash2); // Hasz z tych samych danych MUSI byæ identyczny
        }

        [Fact]
        public void CalculateHashForLog_ZmianaKwotyZmieniaCalyHash()
        {
            // Arrange
            var log1 = new AuditLog { Id = 1, Sender = "A", Receiver = "B", Amount = 100.00m };
            var log2 = new AuditLog { Id = 1, Sender = "A", Receiver = "B", Amount = 100.01m };

            // Act
            var hash1 = _cryptoService.CalculateHashForLog(log1);
            var hash2 = _cryptoService.CalculateHashForLog(log2);

            // Assert
            Assert.NotEqual(hash1, hash2); // Nawet 1 grosz ró¿nicy musi daæ inny skrót
        }
    }
}