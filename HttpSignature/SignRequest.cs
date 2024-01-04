using System;
using System.Collections.Generic;
using System.Text;

namespace HttpSignature
{
    class SignRequest
    {
        public string Type { get; set; }
        public string Driver { get; set;  }
        public string Password { get; set; }
        public string Document { get; set; }
        public string DllLibPath { get; set; }
        public string TokenCertificate { get; set; }
    }
}
