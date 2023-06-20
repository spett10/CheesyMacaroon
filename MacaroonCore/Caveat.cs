using MacaroonCore.Dto;

namespace MacaroonCore
{
    public abstract class Caveat
    {
        public string Location { get; set; }
        public string CaveatId { get; set; }
        public string VerificationId { get; set; }

        public abstract byte[] Payload();

        public abstract bool IsFirstPartyCaveat { get; }

        public CaveatDto ToDto()
        {
            return new CaveatDto()
            {
                Location = this.Location,
                CaveatId = this.CaveatId,
                VerificationId = this.VerificationId
            };
        }
    }
}
