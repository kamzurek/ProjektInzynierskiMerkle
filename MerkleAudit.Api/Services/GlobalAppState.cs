namespace MerkleAudit.Api.Services
{
    // Singleton przechowujący globalny stan bezpieczeństwa systemu
    public class GlobalAppState
    {
        public bool IsQuarantineActive { get; set; } = false;
        public string QuarantineReason { get; set; } = string.Empty;
    }
}