using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

using Pki;

namespace Org.BouncyCastle.X509
{
	internal static class X509CertificateExtensions
	{
		public static IssuerSerial GetIssuerSerial(this X509Certificate @this)
		{
			Guard.IsNotNull(@this, nameof(@this));
			var gn = new GeneralName(@this.IssuerDN);
			return new IssuerSerial(new GeneralNames(gn), new DerInteger(@this.SerialNumber));
		}
	}
}
