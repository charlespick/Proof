using Proof.Refresher;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "Proof Refresher");
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
