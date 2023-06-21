using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MacaroonCore
{
    // TODO: do we even need this when it is no longer abstract? We could have first party at the bottom, then thirdparty inherit from that? 
    public class Caveat
    {
        public string Location { get; set; }
        public string CaveatId { get; set; }
        public string VerificationId { get; set; }

        public virtual byte[] Payload() { throw new NotImplementedException(); }

        [JsonIgnore]
        public virtual bool IsFirstPartyCaveat { get; }

        [JsonConstructor]
        public Caveat()
        {

        }

        public string ToJson()
        {
            return JsonSerializer.Serialize(this, new JsonSerializerOptions()
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            });
        }

        public static Caveat Create(Caveat caveat)
        {
            if (FirstPartyCaveat.VerificationIdIndicatesFirstPartyCaveat(caveat.VerificationId))
            {
                return new FirstPartyCaveat()
                {
                    CaveatId = caveat.CaveatId,
                    Location = caveat.Location,
                    VerificationId = caveat.VerificationId
                };
            }
            else
            {
                return new ThirdPartyCaveat()
                {
                    CaveatId = caveat.CaveatId,
                    Location = caveat.Location,
                    VerificationId = caveat.VerificationId
                };
            }
        }
    }
}
