﻿using System.ComponentModel.DataAnnotations;

namespace Pki.Api
{
	public class TimestampSettings
	{
		[Required]
		public string TsaPolicyOid { get; init; }

		/// <summary>
		/// Path of the complete certificate chain and the private key as encrypted PKCS#12 file.
		/// </summary>
		[Required]
		public string Pkcs12Path { get; init; }

		/// <summary>
		/// PKCS#12's password if specified on file creation.
		/// </summary>
		public string Pkcs12Pass { get; init; }

		/// <summary>
		/// Determine if patch related to signing certificate validation should be ignored.. see patcher summary.
		/// </summary>
		public bool ApplyTspUtilValidateCertificatePatch { get; init; }
	}

	public class Settings
	{
		public TimestampSettings Timestamp { get; init; }
	}
}
