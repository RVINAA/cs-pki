using Microsoft.AspNetCore.Mvc;

using Org.BouncyCastle.Tsp;

namespace Pki.Api.Features
{
	[ApiController]
	[Route("timeStamping")]
	public class TimeStampingController : ControllerBase
	{
		#region Fields

		private const string CONTENT_TYPE_TIMESTAMP_QUERY = "application/timestamp-query";
		private const string CONTENT_TYPE_TIMESTAMP_REPLY = "application/timestamp-reply";

		private readonly ILogger<TimeStampingController> _logger;
		private readonly ITimeStamper _timeStamper;

		#endregion

		#region .ctors

		public TimeStampingController(ILogger<TimeStampingController> logger, ITimeStamper timeStampingSvc)
		{
			_logger = logger.ThrowIfNull(nameof(logger));
			_timeStamper = timeStampingSvc.ThrowIfNull(nameof(timeStampingSvc));
		}

		#endregion

		#region Private methods

		private async Task<TimeStampRequest> GetReq()
		{
			try
			{
				int readed;
				var buffer = new byte[8192];
				using var ms = new MemoryStream();
				while ((readed = await Request.Body.ReadAsync(buffer)) > 0)
					ms.Write(buffer, 0, readed);

				return new TimeStampRequest(ms.ToArray());
			}
			catch (Exception ex)
			{
				throw new ArgumentException("Timestamp request is not present or cannot be parsed from body", ex);
			}
		}

		#endregion

		[HttpPost]
		[Consumes(CONTENT_TYPE_TIMESTAMP_QUERY)]
		public async Task<IActionResult> Post()
		{
			_logger.LogDebug("Processing request to generate a timestamp");

			var req = await GetReq();
			var encoded = _timeStamper.Process(req);
			Guard.IsNotNull(encoded, nameof(encoded));

			_logger.LogDebug("Processed request to generate a timestamp");

			return File(encoded, CONTENT_TYPE_TIMESTAMP_REPLY);
		}
	}
}
