using Hellang.Middleware.ProblemDetails;

using Pki.Api.Features;

namespace Pki.Api
{
	public class Program
	{
		private static bool _isDevelopment;
		private static Settings _settings;

		public static void Main(string[] args)
		{
			var builder = WebApplication.CreateBuilder(args);
			builder.Services.AddEndpointsApiExplorer();
			builder.Services.AddProblemDetails(x =>
			{
				x.IncludeExceptionDetails = (ctx, env) => _isDevelopment;
			});
			builder.Services.AddControllers();
			builder.Services.AddSwaggerGen();

			var cfg = new ConfigurationBuilder()
				.SetBasePath(Directory.GetCurrentDirectory())
				.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
				.AddJsonFile("appsettings.local.json", optional: true, reloadOnChange: true)
				.AddEnvironmentVariables()
				.Build();

			_settings = cfg.GetSection("Settings").Get<Settings>();

			// Apply patches if demanded..
			if (_settings.Timestamp.ApplyTspUtilValidateCertificatePatch)
				TspUtilValidateCertificatePatcher.Apply();

			builder.Services.AddSingleton(cfg)
				.AddSingleton(_ => _settings)
				.AddSingleton<ITimeStamper, TimeStamper>();

			builder.Logging
				.AddSimpleConsole(x =>
				{
					x.TimestampFormat = "hh:mm:ss.ms - ";
					x.UseUtcTimestamp = true;
					x.SingleLine = true;
				});

			var app = builder.Build();
			if (_isDevelopment = app.Environment.IsDevelopment())
			{
				app.UseSwagger();
				app.UseSwaggerUI();
			}

			app.UseHttpsRedirection();
			app.UseProblemDetails();
			app.UseAuthorization();
			app.MapControllers();
			app.Run();
		}
	}
}
