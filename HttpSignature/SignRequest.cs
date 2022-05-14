using System;
using System.Collections.Generic;
using System.Text;

namespace HttpSignature
{
    class SignRequest
    {
            public string Password { get; set; }
            public string Document { get; set; }
            public string TokenCertificate { get; set; }

    }
}
