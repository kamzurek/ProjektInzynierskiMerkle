using System.Collections.Generic;
using MerkleAudit.Api.Models;

namespace MerkleAudit.Api.Services
{
    public class MerkleTreeBuilder
    {
        private readonly CryptoService _cryptoService;

        // "Wstrzykujemy" nasz serwis kryptograficzny, żeby móc z niego korzystać w tej klasie
        public MerkleTreeBuilder(CryptoService cryptoService)
        {
            _cryptoService = cryptoService;
        }

        // Główna metoda, która z listy przelewów wylicza jeden Główny Hash (Merkle Root)
        public string BuildRoot(List<AuditLog> logs)
        {
            // Jeśli baza jest pusta, zwracamy null
            if (logs == null || logs.Count == 0)
                return null;

            // Krok 1: Zbieramy hasze ze wszystkich logów. To są nasze "liście" na samym dole drzewa.
            List<string> currentLevel = new List<string>();
            foreach (var log in logs)
            {
                // Jeśli log ma już swój hash, bierzemy go. Jeśli nie (bo np. to nowy przelew), wyliczamy na nowo.
                string logHash = string.IsNullOrEmpty(log.Hash) ? _cryptoService.CalculateHashForLog(log) : log.Hash;
                currentLevel.Add(logHash);
            }

            // Krok 2: Budujemy drzewo w górę. Pętla działa tak długo, aż zostanie nam tylko 1 element.
            while (currentLevel.Count > 1)
            {
                List<string> nextLevel = new List<string>();

                // Skaczemy co 2 (bierzemy lewy i prawy element)
                for (int i = 0; i < currentLevel.Count; i += 2)
                {
                    string leftHash = currentLevel[i];

                    // Magia Drzewa Merkle: co jeśli mamy nieparzystą liczbę logów? 
                    // Algorytm mówi: "Zduplikuj ostatni hash i połącz go z samym sobą".
                    string rightHash = (i + 1 < currentLevel.Count) ? currentLevel[i + 1] : leftHash;

                    // Łączymy dwa hasze z niższego poziomu w jeden nowy na wyższym poziomie
                    string combinedHash = _cryptoService.CombineAndHash(leftHash, rightHash);
                    nextLevel.Add(combinedHash);
                }

                // Przechodzimy poziom wyżej i powtarzamy proces
                currentLevel = nextLevel;
            }

            // Krok 3: Zwracamy ten jeden, ostatni hash, który został na samej górze piramidy
            return currentLevel[0];
        }
    }
}