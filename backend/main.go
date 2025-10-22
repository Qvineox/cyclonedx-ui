package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/Qvineox/cyclonedx-ui/cfg"
	"github.com/Qvineox/cyclonedx-ui/internal/db"
	"github.com/Qvineox/cyclonedx-ui/internal/server"
	"github.com/Qvineox/cyclonedx-ui/internal/services"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	var config *cfg.AppConfig

	configPath, _ := flags()
	if configPath == nil || len(*configPath) == 0 {
		config = cfg.NewAppConfigFromEnv()
	} else {
		config = cfg.NewAppConfigFromFile(configPath)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()

	slog.Info(fmt.Sprintf("setting new log level to: %d", config.LogLevel))
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.Level(config.LogLevel),
	})))

	var orm *gorm.DB
	if config.Database.Enable {
		dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s database=%s sslmode=disable TimeZone=%s",
			config.Database.Host,
			config.Database.Port,
			config.Database.User,
			config.Database.Pass,
			config.Database.Database,
			config.Database.Timezone,
		)

		slog.Info("connecting to database",
			slog.String("host", config.Database.Host),
			slog.Uint64("port", config.Database.Port),
		)

		var err error
		orm, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			panic("failed to connect database: " + err.Error())
		} else if orm != nil {
			slog.Info("successfully connected to database",
				slog.String("host", config.Database.Host),
				slog.Uint64("port", config.Database.Port),
			)
		}
	}

	s := server.Services{
		Sbom: services.NewSBOMServiceImpl(config.CycloneDX),
	}

	if config.Database.Enable && orm != nil {
		s.Project = services.NewProjectServiceImpl(db.NewProjectRepoImpl(orm), db.NewRevisionRepoImpl(orm))
	}

	grpcSrv, restSrv, err := server.NewServer(ctx, config.Server, s)

	if err != nil {
		panic("failed to create server: " + err.Error())
	}

	if config.Server.GRPC.Enable {
		slog.Info("starting grpc server...")
		go func() {
			listener, err := net.Listen("tcp", net.JoinHostPort(config.Server.GRPC.Host, strconv.FormatUint(config.Server.GRPC.Port, 10)))
			if err != nil {
				panic("failed to create http listener: " + err.Error())
			}

			err = grpcSrv.Serve(listener)
			if err != nil {
				panic("failed to start grpc server: " + err.Error())
			}
		}()

		slog.Warn(fmt.Sprintf("grpc server started on %s:%d (health: %s, reflection: %s)",
			config.Server.GRPC.Host,
			config.Server.GRPC.Port,
			strconv.FormatBool(config.Server.Health),
			strconv.FormatBool(config.Server.GRPC.Reflect),
		))
	}

	if config.Server.HTTP.Enable {
		slog.Info("starting http server...")
		go func() {
			err = http.ListenAndServe(net.JoinHostPort(config.Server.HTTP.Host, strconv.FormatUint(config.Server.HTTP.Port, 10)), restSrv)
			if err != nil {
				panic("failed to start http server: " + err.Error())
			}
		}()

		slog.Warn(fmt.Sprintf("http server started on %s:%d", config.Server.HTTP.Host, config.Server.HTTP.Port))
	}

	<-ctx.Done()
}

func flags() (configFilePath *string, serveUIServer *bool) {
	configFilePath = flag.String("config", "", "config file path")
	serveUIServer = flag.Bool("web", false, "serve ui server")

	// https://gobyexample.com/command-line-flags

	flag.Parse()
	return
}
