using System;
using System.Security.Cryptography;
using System.Text;
using MerkleAudit.Api.Models;

namespace MerkleAudit.Api.Services
{
    public class CryptoService
    {
        private readonly RSA _rsa;
        // Ścieżka do pliku, w którym ukryjemy klucz prywatny serwera
        private readonly string _keyFolder = "Keys";
        private readonly string _keyFileName = "server_private.xml";

        public CryptoService()
        {
            _rsa = RSA.Create(2048);
            InitializeKeys();
        }

        private void InitializeKeys()
        {
            // 1. Tworzymy folder Keys, jeśli nie istnieje
            if (!Directory.Exists(_keyFolder))
            {
                Directory.CreateDirectory(_keyFolder);
            }

            string fullPath = Path.Combine(_keyFolder, _keyFileName);

            // 2. Jeśli plik klucza już istnieje - wczytujemy go
            if (File.Exists(fullPath))
            {
                string xmlKey = File.ReadAllText(fullPath);
                _rsa.FromXmlString(xmlKey);
                Console.WriteLine(">>> [Crypto] Wczytano istniejący klucz serwera z pliku.");
            }
            // 3. Jeśli nie ma klucza - generujemy i zapisujemy
            else
            {
                string xmlKey = _rsa.ToXmlString(true); // 'true' oznacza eksport z kluczem prywatnym
                File.WriteAllText(fullPath, xmlKey);
                Console.WriteLine(">>> [Crypto] Wygenerowano i zapisano nowy klucz serwera.");
            }
        }

        // --- Pozostałe metody pozostają bez zmian ---

        public string CalculateHashForLog(AuditLog log)
        {
            // 1. Standaryzacja danych!
            // Zmuszamy kwotę, by ZAWSZE miała 2 miejsca po przecinku (np. 1500.00) bez względu na to, jak odda ją baza.
            // Używamy InvariantCulture, żeby zapobiec zamianie kropki na przecinek na polskich Windowsach.
            string amountFormatted = log.Amount.ToString("0.00", System.Globalization.CultureInfo.InvariantCulture);

            // 2. Formatujemy datę ucinając z niej milisekundy i strefy czasowe
            string dateFormatted = log.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss");

            // 3. Budujemy surowy tekst do hashowania
            // DODANO: Wplatamy Cyfrowe Ślady (IP oraz UserAgent) tuż przed PreviousHash!
            string rawData = $"{log.Id}{log.Sender}{log.Receiver}{amountFormatted}{dateFormatted}{log.IpAddress}{log.UserAgent}{log.PreviousHash}";

            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                // 4. Liczymy hash 
                byte[] hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(rawData));
                System.Text.StringBuilder builder = new System.Text.StringBuilder();
                foreach (var b in hashBytes)
                {
                    builder.Append(b.ToString("x2"));
                }
                return builder.ToString();
            }
        }

        public string CombineAndHash(string leftHash, string rightHash)
        {
            string combinedData = leftHash + rightHash;
            byte[] bytes = Encoding.UTF8.GetBytes(combinedData);

            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(bytes);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }
        }

        public string SignData(string data)
        {
            if (string.IsNullOrEmpty(data)) return null;
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            byte[] signatureBytes = _rsa.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signatureBytes);
        }

        public bool VerifySignature(string data, string signatureBase64)
        {
            try
            {
                byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                byte[] signatureBytes = Convert.FromBase64String(signatureBase64);
                return _rsa.VerifyData(dataBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            catch { return false; }
        }

        public string GetPublicKey()
        {
            return _rsa.ToXmlString(false);
        }
    }
}