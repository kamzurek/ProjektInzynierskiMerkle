using Xunit;
using MerkleAudit.Api.Services;
using MerkleAudit.Api.Models;
using System.Collections.Generic;

namespace MerkleAudit.Tests
{
    public class MerkleTreeBuilderTests
    {
        private readonly MerkleTreeBuilder _treeBuilder;

        public MerkleTreeBuilderTests()
        {
            var cryptoService = new CryptoService();
            _treeBuilder = new MerkleTreeBuilder(cryptoService);
        }

        [Fact]
        public void BuildRoot_ZwracaNullDlaPustejListy()
        {
            // Arrange
            var emptyList = new List<AuditLog>();

            // Act
            var root = _treeBuilder.BuildRoot(emptyList);

            // Assert
            Assert.Null(root);
        }

        [Fact]
        public void BuildRoot_GenerujePrawidlowyKorzenDlaDwochElementow()
        {
            // Arrange
            var logs = new List<AuditLog>
            {
                new AuditLog { Id = 1, Hash = "HashA" },
                new AuditLog { Id = 2, Hash = "HashB" }
            };

            // Act
            var root = _treeBuilder.BuildRoot(logs);

            // Assert
            Assert.NotNull(root);
            Assert.NotEqual("HashA", root);
            Assert.NotEqual("HashB", root);
        }

        [Fact]
        public void GetProof_ZwracaNullDlaNieistniejacegoWpisu()
        {
            // Arrange
            var logs = new List<AuditLog> { new AuditLog { Id = 1, Hash = "PrawidlowyHash" } };

            // Act
            var proof = _treeBuilder.GetProof(logs, "FalszywyHash_Haker");

            // Assert
            Assert.Null(proof); // System nie może wygenerować dowodu dla nieistniejących danych
        }

        [Fact]
        public void GetProof_GenerujePrawidlowaLiczbeWezlowDowodu()
        {
            // Arrange (Drzewo z 4 elementów = dowód powinien mieć log2(4) = 2 poziomy)
            var logs = new List<AuditLog>
            {
                new AuditLog { Id = 1, Hash = "H1" },
                new AuditLog { Id = 2, Hash = "H2" },
                new AuditLog { Id = 3, Hash = "H3" },
                new AuditLog { Id = 4, Hash = "H4" }
            };

            // Act
            var proof = _treeBuilder.GetProof(logs, "H3");

            // Assert
            Assert.NotNull(proof);
            Assert.Equal(2, proof.Count); // Potrzebujemy dokładnie 2 skrótów, aby dojść do korzenia
        }

        [Fact]
        public void WeryfikacjaZeroTrust_WygenerowanyDowodPozwalaOdtworzycKorzen()
        {
            // Ten test to ostateczny dowód na działanie algorytmu!

            // 1. Arrange - Tworzymy symulowaną bazę przelewów
            var logs = new List<AuditLog>
            {
                new AuditLog { Id = 1, Hash = "Transakcja_A" },
                new AuditLog { Id = 2, Hash = "Transakcja_B" },
                new AuditLog { Id = 3, Hash = "Transakcja_C" }, // To nasz badany przelew
                new AuditLog { Id = 4, Hash = "Transakcja_D" },
                new AuditLog { Id = 5, Hash = "Transakcja_E" }  // Nieparzysta liczba elementów utrudnia zadanie!
            };

            string targetHash = "Transakcja_C";
            var cryptoService = new CryptoService();

            // Serwer oblicza prawdziwy Główny Korzeń
            string expectedServerRoot = _treeBuilder.BuildRoot(logs);

            // 2. Act - Klient żąda dowodu dla Transakcji C
            var proof = _treeBuilder.GetProof(logs, targetHash);

            // Symulujemy zachowanie aplikacji w React (weryfikacja po stronie klienta)
            string computedHash = targetHash;
            foreach (var sibling in proof)
            {
                if (sibling.Direction == "Left")
                {
                    computedHash = cryptoService.CombineAndHash(sibling.Hash, computedHash);
                }
                else // Direction == "Right"
                {
                    computedHash = cryptoService.CombineAndHash(computedHash, sibling.Hash);
                }
            }

            // 3. Assert - Obliczony przez klienta wynik MUSI być identyczny z korzeniem z serwera
            Assert.Equal(expectedServerRoot, computedHash);
        }
    }
}