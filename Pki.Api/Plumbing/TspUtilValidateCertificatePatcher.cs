using System.Reflection;

using HarmonyLib;

using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;

namespace Pki.Api
{
	/// <summary>
	/// Initially, this repository has been created to check some behaviour signing a timestamp w/ a certificate
	///     whose EKU timeStamping is not present.
	/// Openssl caps this and looks like BC also cap this on certificate validation.
	///     With this patcher, we'll omit this validation in order to see how Adobe proccess the PDF w/ a 'bad' timestamp.
	/// </summary>
	public class TspUtilValidateCertificatePatcher
	{
		public static void Apply()
		{
			var original = typeof(TspUtil).GetMethod(nameof(TspUtil.ValidateCertificate), BindingFlags.Public | BindingFlags.Static);
			var prefix = typeof(TspUtilValidateCertificatePatcher).GetMethod(nameof(Prefix));
			var harmony = new Harmony(nameof(TspUtilValidateCertificatePatcher));
			harmony.Patch(original, new HarmonyMethod(prefix), null);
		}

		public static bool Prefix(ref X509Certificate cert)
		{
			return false; //< Skip original call w/o apply any validation..
		}
	}
}
