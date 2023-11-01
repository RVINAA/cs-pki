using Org.BouncyCastle.Utilities.Collections;

using Pki;

namespace Org.BouncyCastle.X509
{
	public class X509Store : IStore<X509Certificate>
	{
		#region Fields

		private readonly IEnumerable<X509Certificate> _certificates;

		#endregion

		#region .ctors

		public X509Store(IEnumerable<X509Certificate> certificates)
		{
			_certificates = certificates.ThrowIfNull(nameof(certificates));
		}

		#endregion

		public IEnumerable<X509Certificate> EnumerateMatches(ISelector<X509Certificate> selector)
		{
			if (selector == null) //< Return all.
				return _certificates;

			return _certificates.Where(x => selector.Match(x)).ToArray();
		}
	}
}
