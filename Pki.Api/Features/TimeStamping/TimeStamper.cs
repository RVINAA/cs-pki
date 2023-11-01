using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;

using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using AttributeTable = Org.BouncyCastle.Asn1.Cms.AttributeTable;

namespace Pki.Api.Features
{
	public interface ITimeStamper
	{
		byte[] Process(TimeStampRequest req);
	}

	public class TimeStamper : ITimeStamper
	{
		#region Fields

		private static readonly string[] _acceptedAlgOids = new[]
		{
			"1.3.14.3.2.26",          //< SHA-1
			"2.16.840.1.101.3.4.2.1", //< SHA-256
			"2.16.840.1.101.3.4.2.2", //< SHA-384
			"2.16.840.1.101.3.4.2.3"  //< SHA-512
		};

		private const string SHA1 = "SHA-1";
		private const string SHA256 = "SHA-256";

		private readonly ILogger<TimeStamper> _logger;

		private readonly TimestampSettings _settings;

		private AsymmetricKeyParameter _key;
		private X509Certificate _cert;
		private X509Store _store;

		private string _policyOid => _settings?.TsaPolicyOid;

		#endregion

		#region .ctors

		public TimeStamper(ILogger<TimeStamper> logger, Settings settings)
		{
			_logger = logger.ThrowIfNull(nameof(logger));
			_settings = settings?.Timestamp.ThrowIfNull(nameof(settings));

			LoadPkcs12();
		}

		#endregion

		#region Private methods

		private static BigInteger GetSerialNumberFor(byte[] bytes)
		{
			return new BigInteger(bytes); //< TODO: Should be unique & persisted..
		}

		private Attribute GetSigningCertificateAttributeFor(string algOid)
		{
			Guard.IsNotNullOrWhiteSpace(algOid, nameof(algOid));

			var digestAlgorithm = DigestUtilities.GetAlgorithmName(new DerObjectIdentifier(algOid));
			var certHash = DigestUtilities.CalculateDigest(digestAlgorithm, _cert.GetEncoded());
			var issuerSerial = _cert.GetIssuerSerial();

			if (digestAlgorithm == SHA1)
			{
				var essCertID = new EssCertID(certHash, issuerSerial);
				var signingCertificate = new SigningCertificate(essCertID);
				return new Attribute(PkcsObjectIdentifiers.IdAASigningCertificate, new DerSet(signingCertificate));
			}

			// RFC 5035 compliant..
			var essCertIdv2 = digestAlgorithm == SHA256
				? new EssCertIDv2(null, certHash, issuerSerial) //< SHA-256 is default.
				: new EssCertIDv2(AlgorithmIdentifier.GetInstance(digestAlgorithm), certHash, issuerSerial);

			var signingCertificateV2 = new SigningCertificateV2(new[] { essCertIdv2 });
			return new Attribute(PkcsObjectIdentifiers.IdAASigningCertificateV2, new DerSet(signingCertificateV2));
		}

		private void LoadPkcs12()
		{
			var store = new Pkcs12StoreBuilder().Build();
			using (var fs = File.OpenRead(_settings.Pkcs12Path))
			{
				var pass = _settings.Pkcs12Pass?.ToCharArray() ?? Array.Empty<char>();
				store.Load(fs, pass);
			}

			var alias = store.Aliases.First();
			var chain = store.GetCertificateChain(alias).Select(x => x.Certificate).ToArray();
			Guard.Against<ArgumentException>(chain.Length < 2, "Self-signed certificate should not be used for this..");

			_key = store.GetKey(alias)?.Key;
			_store = new X509Store(chain);
			_cert = chain[0]; //< XXX: Already ordered?!
		}

		#endregion

		public byte[] Process(TimeStampRequest req)
		{
			Guard.IsNotNull(req, nameof(req));
			var bytes = req.GetMessageImprintDigest();
			Guard.Against<ArgumentOutOfRangeException>(
				bytes?.Any() != true,
				"Missing bytes to sign?!"
			);

			_logger.LogDebug("Processing timestamp request w/ bytes length {0} and algOid {1}", bytes.Length, req.MessageImprintAlgOid);

			var signedAttrs = new Asn1EncodableVector();
			if (req.CertReq)
			{
				signedAttrs.Add(GetSigningCertificateAttributeFor(req.MessageImprintAlgOid));
			}

			// TODO: May add more signed attributes at this point.

			var gen = new TimeStampTokenGenerator(_key, _cert, req.MessageImprintAlgOid, _policyOid, new AttributeTable(signedAttrs), null);
			if (req.CertReq)
			{
				gen.SetCertificates(_store);
			}

			var respGen = new TimeStampResponseGenerator(gen, _acceptedAlgOids);
			var resp = respGen.Generate(req, GetSerialNumberFor(bytes), DateTime.UtcNow);

			_logger.LogDebug("Processed timestamp request w/ bytes length {0} and algOid {1} (Status: {2})", bytes.Length, req.MessageImprintAlgOid, resp.Status);

			return resp.GetEncoded();
		}
	}
}
